using FirebaseAdmin;
using Firebase.Models;
using FirebaseAdmin.Auth;
using Google.Cloud.Firestore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Threading.Tasks;
using static Firebase.Models.AuthModels;
using Firebase.Services;

/// <summary>
/// Controlador para la gestión de autenticación y registro de usuarios.
/// Maneja el inicio de sesión con email/contraseña, registro de nuevos usuarios y autenticación con Google.
/// </summary>
public class LoginController : Controller
{
    private readonly Firebase.Services.AuthenticationService _authService;

    /// <summary>
    /// Constructor del controlador de login.
    /// </summary>
    /// <param name="authService">Servicio de autenticación</param>
    public LoginController(Firebase.Services.AuthenticationService authService)
    {
        _authService = authService;
    }

    /// <summary>
    /// Muestra la página principal de login/registro.
    /// </summary>
    /// <returns>Vista de login</returns>
    public IActionResult Index()
    {
        return View();
    }

    /// <summary>
    /// Procesa el inicio de sesión con email y contraseña.
    /// </summary>
    /// <param name="request">Datos de login del usuario</param>
    /// <returns>Resultado de la autenticación</returns>
    [HttpPost]
    public async Task<IActionResult> Login(LoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            ViewBag.Error = "Por favor, complete todos los campos correctamente.";
            return View("Index");
        }

        try
        {
            var result = await _authService.AuthenticateWithEmailAsync(request.Email, request.Password);
            
            if (!result.IsSuccess)
            {
                ViewBag.Error = result.ErrorMessage;
                return View("Index");
            }

            // Crear claims y autenticar al usuario
            await SignInUserAsync(result.UserInfo!);

            // Registrar evento de inicio de sesión en Google Analytics
            TempData["LoginEvent"] = true;
            
            return RedirectToAction("Index", "Lavados");
        }
        catch (Exception)
        {
            ViewBag.Error = "Error al iniciar sesión. Por favor, intente de nuevo.";
            return View("Index");
        }
    }

    /// <summary>
    /// Procesa el registro de un nuevo usuario.
    /// </summary>
    /// <param name="request">Datos de registro del usuario</param>
    /// <returns>Resultado del registro</returns>
    [HttpPost]
    public async Task<IActionResult> RegisterUser(RegisterRequest request)
    {
        if (!ModelState.IsValid)
        {
            ViewBag.Error = "Por favor, complete todos los campos del registro correctamente.";
            return View("Index");
        }

        try
        {
            var result = await _authService.RegisterUserAsync(request);
            
            if (!result.IsSuccess)
            {
                ViewBag.Error = result.ErrorMessage;
                return View("Index");
            }

            // Autenticar al usuario recién registrado
            await SignInUserAsync(result.UserInfo!);
            
            return RedirectToAction("Index", "Lavados");
        }
        catch (Exception)
        {
            ViewBag.Error = "Error al registrar el usuario. Por favor, intente de nuevo.";
            return View("Index");
        }
    }

    /// <summary>
    /// Procesa la autenticación con Google.
    /// </summary>
    /// <param name="request">Token de ID de Google</param>
    /// <returns>Resultado de la autenticación</returns>
    [HttpPost]
    public async Task<IActionResult> LoginWithGoogle([FromBody] GoogleLoginRequest request)
    {
        try
        {
            var result = await _authService.AuthenticateWithGoogleAsync(request.IdToken);
            
            if (!result.IsSuccess)
            {
                return BadRequest(new { error = result.ErrorMessage });
            }

            // Crear claims y autenticar al usuario
            await SignInUserAsync(result.UserInfo!, isPersistent: true);

            return Json(new { redirectUrl = Url.Action("Index", "Lavados") });
        }
        catch (Exception)
        {
            return BadRequest(new { error = "Error al autenticar con Google. Por favor, intente de nuevo." });
        }
    }

    /// <summary>
    /// Autentica al usuario en la aplicación creando las claims correspondientes.
    /// </summary>
    /// <param name="userInfo">Información del usuario</param>
    /// <param name="isPersistent">Indica si la sesión debe ser persistente</param>
    /// <returns>Task</returns>
    private async Task SignInUserAsync(UserInfo userInfo, bool isPersistent = false)
    {
        var claims = _authService.CreateUserClaims(userInfo);
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);
        
        var authProperties = new AuthenticationProperties
        {
            IsPersistent = isPersistent
        };

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, authProperties);
    }
}

/// <summary>
/// Modelo para las solicitudes de login con Google.
/// </summary>
public class GoogleLoginRequest
{
    /// <summary>
    /// Token de ID proporcionado por Google.
    /// </summary>
    [Required]
    public required string IdToken { get; set; }
}

