using FirebaseAdmin.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using System.Security.Claims;
using System.Text;
using Google.Cloud.Firestore;
using Firebase.Models;
using static Firebase.Models.AuthModels;

namespace Firebase.Services
{
    /// <summary>
    /// Servicio para manejar operaciones de autenticación con Firebase.
    /// Proporciona métodos para login, registro y autenticación con Google.
    /// </summary>
    public class AuthenticationService
    {
        private readonly IConfiguration _configuration;
        private readonly FirestoreDb _firestore;
        private readonly AuditService _auditService;
        private readonly HttpClient _httpClient;
        private readonly string _firebaseApiKey;

        /// <summary>
        /// Constructor del servicio de autenticación.
        /// </summary>
        /// <param name="configuration">Configuración de la aplicación</param>
        /// <param name="firestore">Instancia de FirestoreDb</param>
        /// <param name="auditService">Servicio de auditoría</param>
        /// <param name="httpClient">Cliente HTTP para llamadas a Firebase</param>
        public AuthenticationService(IConfiguration configuration, FirestoreDb firestore, AuditService auditService, HttpClient httpClient)
        {
            _configuration = configuration;
            _firestore = firestore;
            _auditService = auditService;
            _httpClient = httpClient;
            _firebaseApiKey = _configuration["Firebase:ApiKey"] ?? throw new InvalidOperationException("Firebase API Key no configurada");
        }

        /// <summary>
        /// Autentica un usuario con email y contraseña usando Firebase.
        /// </summary>
        /// <param name="email">Email del usuario</param>
        /// <param name="password">Contraseña del usuario</param>
        /// <returns>Resultado de la operación de autenticación</returns>
        public async Task<AuthenticationResult> AuthenticateWithEmailAsync(string email, string password)
        {
            try
            {
                var loginInfo = new
                {
                    email = email,
                    password = password,
                    returnSecureToken = true
                };

                var content = new StringContent(JsonConvert.SerializeObject(loginInfo), Encoding.UTF8, "application/json");
                var uri = $"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={_firebaseApiKey}";
                var response = await _httpClient.PostAsync(uri, content);

                if (!response.IsSuccessStatusCode)
                {
                    var errorResponse = await response.Content.ReadAsStringAsync();
                    var firebaseError = JsonConvert.DeserializeObject<FirebaseErrorResponse>(errorResponse);
                    var errorCode = firebaseError?.error?.message?.Split(' ').FirstOrDefault() ?? "UNKNOWN_ERROR";
                    
                    return AuthenticationResult.Failure(GetFirebaseErrorMessage(errorCode));
                }

                var responseData = await response.Content.ReadAsStringAsync();
                var loginResponse = JsonConvert.DeserializeObject<FirebaseLoginResponse>(responseData);
                
                if (loginResponse?.localId == null)
                {
                    return AuthenticationResult.Failure("Error al procesar la respuesta de autenticación.");
                }

                // Verificar estado del empleado en Firestore
                var employeeDoc = await _firestore.Collection("empleados").Document(loginResponse.localId).GetSnapshotAsync();
                
                if (!employeeDoc.Exists || employeeDoc.GetValue<string>("Estado") != "Activo")
                {
                    return AuthenticationResult.Failure("Cuenta inactiva, contacte con el administrador.");
                }

                var userInfo = new UserInfo
                {
                    Uid = loginResponse.localId,
                    Email = email,
                    Name = employeeDoc.GetValue<string>("Nombre"),
                    Role = employeeDoc.GetValue<string>("Rol")
                };

                return AuthenticationResult.Success(userInfo);
            }
            catch (Exception ex)
            {
                return AuthenticationResult.Failure("Error al iniciar sesión. Por favor, intente de nuevo.");
            }
        }

        /// <summary>
        /// Registra un nuevo usuario en Firebase Authentication y Firestore.
        /// </summary>
        /// <param name="request">Datos de registro del usuario</param>
        /// <returns>Resultado de la operación de registro</returns>
        public async Task<AuthenticationResult> RegisterUserAsync(RegisterRequest request)
        {
            try
            {
                // Crear usuario en Firebase Authentication
                var userRecordArgs = new UserRecordArgs
                {
                    Email = request.Email,
                    Password = request.Password,
                    DisplayName = request.NombreCompleto
                };

                var userRecord = await FirebaseAuth.DefaultInstance.CreateUserAsync(userRecordArgs);

                // Guardar datos adicionales en Firestore
                var employeeData = new Dictionary<string, object>
                {
                    { "Uid", userRecord.Uid },
                    { "Nombre", request.NombreCompleto },
                    { "Email", request.Email },
                    { "Rol", "Empleado" },
                    { "Estado", "Activo" }
                };

                await _firestore.Collection("empleados").Document(userRecord.Uid).SetAsync(employeeData);

                // Autenticar al usuario recién registrado
                var authResult = await AuthenticateWithEmailAsync(request.Email, request.Password);
                
                if (authResult.IsSuccess)
                {
                    // Registrar evento de auditoría
                    await _auditService.LogEvent(userRecord.Uid, request.Email, "Registro de usuario", userRecord.Uid, "Empleado");
                }

                return authResult;
            }
            catch (FirebaseAuthException ex)
            {
                var errorCode = ex.AuthErrorCode.ToString();
                return AuthenticationResult.Failure($"Error al registrar el usuario: {GetFirebaseErrorMessage(errorCode)}");
            }
            catch (Exception)
            {
                return AuthenticationResult.Failure("Error al registrar el usuario. Por favor, intente de nuevo.");
            }
        }

        /// <summary>
        /// Verifica un token de Google y autentica al usuario.
        /// </summary>
        /// <param name="idToken">Token de ID de Google</param>
        /// <returns>Resultado de la operación de autenticación</returns>
        public async Task<AuthenticationResult> AuthenticateWithGoogleAsync(string idToken)
        {
            try
            {
                var decodedToken = await FirebaseAuth.DefaultInstance.VerifyIdTokenAsync(idToken);
                var email = decodedToken.Claims["email"].ToString();
                var displayName = decodedToken.Claims["name"].ToString();
                var uid = decodedToken.Uid;

                var employeesCollection = _firestore.Collection("empleados");
                var employeeDoc = await employeesCollection.Document(uid).GetSnapshotAsync();

                string role;
                string estado;

                if (!employeeDoc.Exists)
                {
                    // Verificar si existe un empleado con este email (migración de cuentas)
                    var emailQuery = employeesCollection.WhereEqualTo("Email", email);
                    var emailSnapshot = await emailQuery.GetSnapshotAsync();

                    if (emailSnapshot.Count > 0)
                    {
                        // Migrar empleado existente
                        var existingEmployee = emailSnapshot.Documents[0];
                        role = existingEmployee.GetValue<string>("Rol");
                        estado = existingEmployee.GetValue<string>("Estado");

                        if (estado != "Activo")
                        {
                            return AuthenticationResult.Failure("Su cuenta está inactiva. Por favor, contacte al administrador.");
                        }

                        // Migrar: eliminar documento viejo y crear con UID correcto
                        await existingEmployee.Reference.DeleteAsync();

                        var migratedEmployee = new Dictionary<string, object>
                        {
                            { "Uid", uid },
                            { "Nombre", displayName },
                            { "Email", email },
                            { "Rol", role },
                            { "Estado", estado }
                        };
                        await employeesCollection.Document(uid).SetAsync(migratedEmployee);

                        await _auditService.LogEvent(uid, email, "Migración a Google Auth", uid, "Empleado");
                    }
                    else
                    {
                        // Crear nuevo empleado
                        role = "Empleado";
                        estado = "Activo";

                        var newEmployee = new Dictionary<string, object>
                        {
                            { "Uid", uid },
                            { "Nombre", displayName },
                            { "Email", email },
                            { "Rol", role },
                            { "Estado", estado }
                        };
                        await employeesCollection.Document(uid).SetAsync(newEmployee);

                        await _auditService.LogEvent(uid, email, "Registro con Google", uid, "Empleado");
                    }
                }
                else
                {
                    // Empleado ya existe
                    role = employeeDoc.GetValue<string>("Rol");
                    estado = employeeDoc.GetValue<string>("Estado");

                    if (estado != "Activo")
                    {
                        return AuthenticationResult.Failure("Su cuenta está inactiva. Por favor, contacte al administrador.");
                    }
                }

                var userInfo = new UserInfo
                {
                    Uid = uid,
                    Email = email,
                    Name = displayName,
                    Role = role
                };

                // Registrar evento de auditoría
                await _auditService.LogEvent(uid, email, "Inicio de sesión con Google", null, null);

                return AuthenticationResult.Success(userInfo);
            }
            catch (Firebase.Auth.FirebaseAuthException ex)
            {
                return AuthenticationResult.Failure("Error de autenticación: " + ex.Message);
            }
            catch (Exception)
            {
                return AuthenticationResult.Failure("Error al autenticar con Google. Por favor, intente de nuevo.");
            }
        }

        /// <summary>
        /// Crea los claims de autenticación para un usuario.
        /// </summary>
        /// <param name="userInfo">Información del usuario</param>
        /// <returns>Lista de claims</returns>
        public List<Claim> CreateUserClaims(UserInfo userInfo)
        {
            return new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, userInfo.Uid),
                new Claim(ClaimTypes.Name, userInfo.Name),
                new Claim(ClaimTypes.Email, userInfo.Email),
                new Claim(ClaimTypes.Role, userInfo.Role)
            };
        }

        /// <summary>
        /// Traduce códigos de error de Firebase a mensajes en español.
        /// </summary>
        /// <param name="errorCode">Código de error de Firebase</param>
        /// <returns>Mensaje de error en español</returns>
        private string GetFirebaseErrorMessage(string errorCode)
        {
            return errorCode switch
            {
                "EMAIL_EXISTS" => "El correo electrónico ya está registrado.",
                "INVALID_PASSWORD" => "La contraseña es incorrecta.",
                "INVALID_EMAIL" => "El correo electrónico no es válido.",
                "USER_DISABLED" => "La cuenta ha sido deshabilitada por un administrador.",
                "EMAIL_NOT_FOUND" => "No existe ninguna cuenta con este correo electrónico.",
                "OPERATION_NOT_ALLOWED" => "Operación no permitida.",
                "TOO_MANY_ATTEMPTS_TRY_LATER" => "Demasiados intentos fallidos. Inténtalo más tarde.",
                "INVALID_LOGIN_CREDENTIALS" => "Credenciales de inicio de sesión inválidas.",
                _ => "Se ha producido un error al procesar la solicitud."
            };
        }
    }

    /// <summary>
    /// Resultado de una operación de autenticación.
    /// </summary>
    public class AuthenticationResult
    {
        /// <summary>
        /// Indica si la operación fue exitosa.
        /// </summary>
        public bool IsSuccess { get; private set; }

        /// <summary>
        /// Mensaje de error si la operación falló.
        /// </summary>
        public string? ErrorMessage { get; private set; }

        /// <summary>
        /// Información del usuario si la operación fue exitosa.
        /// </summary>
        public UserInfo? UserInfo { get; private set; }

        private AuthenticationResult() { }

        /// <summary>
        /// Crea un resultado exitoso.
        /// </summary>
        /// <param name="userInfo">Información del usuario</param>
        /// <returns>Resultado exitoso</returns>
        public static AuthenticationResult Success(UserInfo userInfo)
        {
            return new AuthenticationResult
            {
                IsSuccess = true,
                UserInfo = userInfo
            };
        }

        /// <summary>
        /// Crea un resultado fallido.
        /// </summary>
        /// <param name="errorMessage">Mensaje de error</param>
        /// <returns>Resultado fallido</returns>
        public static AuthenticationResult Failure(string errorMessage)
        {
            return new AuthenticationResult
            {
                IsSuccess = false,
                ErrorMessage = errorMessage
            };
        }
    }

    /// <summary>
    /// Información básica del usuario autenticado.
    /// </summary>
    public class UserInfo
    {
        /// <summary>
        /// Identificador único del usuario.
        /// </summary>
        public required string Uid { get; set; }

        /// <summary>
        /// Email del usuario.
        /// </summary>
        public required string Email { get; set; }

        /// <summary>
        /// Nombre completo del usuario.
        /// </summary>
        public required string Name { get; set; }

        /// <summary>
        /// Rol del usuario en el sistema.
        /// </summary>
        public required string Role { get; set; }
    }
}