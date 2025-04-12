// login.js (Actualizado para JWT)
document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm')
    const messageElement = document.getElementById('loginMessage')
    const backendUrl = 'http://localhost:3000' // URL base del API

    loginForm.addEventListener('submit', async (event) => {
        event.preventDefault()
        const username = document.getElementById('username').value
        const password = document.getElementById('password').value
        messageElement.textContent = ''

        if (!username || !password) { /* ... */ return }

        try {
            const response = await fetch(`${backendUrl}/auth/login`, { // Ruta actualizada
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            })

            const data = await response.json()

            if (response.ok) { // Login exitoso, esperamos token
                if (data.token) {
                    // --- INICIO CAMBIOS JWT ---
                    // Guardar el token JWT en localStorage
                    localStorage.setItem('jwtToken', data.token)
                    // Ya no guardamos userId directamente
                    localStorage.removeItem('userId')
                    // Podríamos guardar el username si queremos mostrarlo rápido,
                    // pero es mejor obtenerlo del perfil protegido.
                    localStorage.removeItem('username')
                    // --- FIN CAMBIOS JWT ---

                    window.location.href = 'profile.html' // Redirigir al perfil
                } else {
                    messageElement.textContent = 'Error: No se recibió token del servidor.'
                }
            } else { // Error
                messageElement.textContent = `Error: ${data.error || 'Usuario o contraseña inválidos'}`
                localStorage.removeItem('jwtToken') // Limpiar token si falla
            }
        } catch (error) {
            console.error('Error de login:', error)
            messageElement.textContent = 'Login falló. Problema de red o del servidor.'
            localStorage.removeItem('jwtToken')
        }
    })
})