/**
 * Módulo para la autenticación con Google Firebase
 * 
 * Este módulo maneja la configuración de Firebase y la autenticación
 * con Google utilizando el SDK de Firebase v9 y autenticación con popup.
 */

import { initializeApp } from 'https://www.gstatic.com/firebasejs/9.19.1/firebase-app.js';
import { getAuth, signInWithPopup, GoogleAuthProvider } from 'https://www.gstatic.com/firebasejs/9.19.1/firebase-auth.js';

/**
 * Configuración de Firebase
 * Contiene las claves y configuraciones necesarias para conectar con Firebase
 */
const firebaseConfig = {
    apiKey: "AIzaSyBubyUIDmvFmRIvQ--pvnw9wnQcAulJJy8",
    authDomain: "aplicacion-lavadero.firebaseapp.com",
    projectId: "aplicacion-lavadero",
    storageBucket: "aplicacion-lavadero.firebasestorage.app",
    messagingSenderId: "587422469290",
    appId: "1:587422469290:web:4a11be624229aa286614d3",
    measurementId: "G-E7YCZ8WG1H"
};

// Inicializar Firebase
const app = initializeApp(firebaseConfig);
const provider = new GoogleAuthProvider();
const auth = getAuth();

/**
 * Maneja el proceso de autenticación con Google
 * 
 * Este método:
 * 1. Abre un popup para que el usuario se autentique con Google
 * 2. Obtiene el token de ID del usuario autenticado
 * 3. Envía el token al servidor para verificación y creación de sesión
 * 4. Redirige al usuario a la página principal si es exitoso
 */
async function handleGoogleLogin() {
    try {
        // Mostrar popup de Google para autenticación
        const result = await signInWithPopup(auth, provider);
        
        // Obtener el token de ID para enviar al servidor
        const idToken = await result.user.getIdToken();
        
        // Enviar token al servidor para verificación
        const response = await fetch('/Login/LoginWithGoogle', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ idToken })
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.redirectUrl) {
                // Redirigir al usuario a la página principal
                window.location.href = data.redirectUrl;
            } else {
                console.error('Error: No se recibió la URL de redirección del servidor');
                showErrorMessage('Error en la respuesta del servidor. Por favor, intente de nuevo.');
            }
        } else {
            // Manejar errores del servidor
            const errorData = await response.json();
            const errorMessage = errorData.error || 'Error desconocido al iniciar sesión con Google';
            console.error('Error del servidor:', errorMessage);
            showErrorMessage(errorMessage);
        }
    } catch (error) {
        // Manejar errores de Firebase o red
        console.error('Error durante la autenticación con Google:', error);
        
        // Proporcionar mensajes de error más específicos
        let userMessage = 'Error al iniciar sesión con Google. Por favor, intente de nuevo.';
        
        if (error.code === 'auth/popup-closed-by-user') {
            userMessage = 'La ventana de autenticación fue cerrada. Por favor, intente de nuevo.';
        } else if (error.code === 'auth/network-request-failed') {
            userMessage = 'Error de conexión. Verifique su conexión a internet y intente de nuevo.';
        } else if (error.code === 'auth/too-many-requests') {
            userMessage = 'Demasiados intentos. Por favor, espere unos minutos antes de intentar de nuevo.';
        }
        
        showErrorMessage(userMessage);
    }
}

/**
 * Muestra un mensaje de error al usuario
 * @param {string} message - El mensaje de error a mostrar
 */
function showErrorMessage(message) {
    // Buscar si ya existe un contenedor de error
    let errorContainer = document.querySelector('.google-auth-error');
    
    if (!errorContainer) {
        // Crear un nuevo contenedor de error si no existe
        errorContainer = document.createElement('div');
        errorContainer.className = 'google-auth-error text-center text-red-600 bg-red-100 border border-red-400 rounded p-4 mt-4';
        
        // Insertar el contenedor después del botón de Google
        const googleButton = document.getElementById('google-login-button');
        if (googleButton && googleButton.parentNode) {
            googleButton.parentNode.insertBefore(errorContainer, googleButton.nextSibling);
        }
    }
    
    // Establecer el mensaje de error
    errorContainer.textContent = message;
    errorContainer.style.display = 'block';
    
    // Ocultar el mensaje después de 5 segundos
    setTimeout(() => {
        if (errorContainer) {
            errorContainer.style.display = 'none';
        }
    }, 5000);
}

// Configurar el event listener cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', function() {
    const googleLoginButton = document.getElementById('google-login-button');
    
    if (googleLoginButton) {
        googleLoginButton.addEventListener('click', handleGoogleLogin);
    } else {
        console.warn('Botón de login con Google no encontrado en la página');
    }
});

