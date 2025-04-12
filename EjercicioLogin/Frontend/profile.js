// profile.js (Actualizado para JWT)
document.addEventListener('DOMContentLoaded', async () => {
    const usernameDisplay = document.getElementById('usernameDisplay')
    const userIdDisplay = document.getElementById('userIdDisplay') // Podemos quitar o dejar esto
    const logoutButton = document.getElementById('logoutButton')
    const backendUrl = 'http://localhost:3000'

    // --- INICIO CAMBIOS JWT ---
    // 1. Obtener el token de localStorage
    const token = localStorage.getItem('jwtToken')

    if (!token) {
        // Si no hay token, redirigir a login
        alert('No han iniciado sesión (no hay token). Redirigiendo...')
        window.location.href = 'index.html'
        return
    }

    // 2. Intentar obtener los datos del perfil desde el endpoint protegido
    try {
        const response = await fetch(`${backendUrl}/users/profile`, { // Ruta protegida
            method: 'GET',
            headers: {
                // ¡Enviar el token en el header Authorization!
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json' // Aunque GET no tiene body, es buena práctica
            }
        })

        if (response.ok) {
            const userData = await response.json()
            // Mostrar datos obtenidos del backend
            usernameDisplay.textContent = userData.username
            userIdDisplay.textContent = userData.id // Mostrar ID si el elemento existe
        } else {
            // Si el token es inválido/expirado (401) u otro error
            console.error('Error obteniendo perfil:', response.status, response.statusText)
            const errorData = await response.json().catch(() => ({})) // Intentar leer error JSON
            alert(`Error al cargar perfil: ${errorData.error || response.statusText}. Redirigiendo a login.`)
            localStorage.removeItem('jwtToken') // Limpiar token inválido
            window.location.href = 'index.html'
            return
        }

    } catch (error) {
        console.error('Error de red o fetch al obtener perfil:', error)
        alert('Error de conexión al obtener perfil. Redirigiendo a login.')
        localStorage.removeItem('jwtToken')
        window.location.href = 'index.html'
        return
    }
    // --- FIN CAMBIOS JWT ---

    // 3. Configurar el botón de Logout (ahora llama al backend)
    logoutButton.addEventListener('click', async () => {
        const currentToken = localStorage.getItem('jwtToken')
        if (!currentToken) {
            alert("Ya no hay sesión activa.")
            window.location.href = 'index.html'
            return
        }

        try {
            const response = await fetch(`${backendUrl}/auth/logout`, { // Ruta de logout
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${currentToken}`, // Necesario para identificar qué token invalidar
                    'Content-Type': 'application/json'
                }
                // No necesita body usualmente
            })

            const data = await response.json()

            if (response.ok) {
                alert(data.message || 'Logout exitoso.')
            } else {
                // Incluso si falla el backend, limpiar localmente
                alert(`Logout completado localmente, pero hubo un problema notificando al servidor: ${data.error || response.statusText}`)
            }

        } catch (error) {
            console.error('Error en fetch de logout:', error)
            alert('Logout completado localmente, pero hubo un error de red al notificar al servidor.')
        } finally {
            // Siempre limpiar localStorage y redirigir
            localStorage.removeItem('jwtToken')
            localStorage.removeItem('username') // Limpiar cualquier otro dato guardado
            localStorage.removeItem('userId')
            window.location.href = 'index.html'
        }
    })
})