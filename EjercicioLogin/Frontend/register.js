// register.js
document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('registerForm')
    const messageElement = document.getElementById('registerMessage')
    // Asegúrense que esta URL apunta a su backend Go
    const backendUrl = 'http://localhost:3000'

    registerForm.addEventListener('submit', async (event) => {
        event.preventDefault()
        const username = document.getElementById('username').value
        const password = document.getElementById('password').value
        messageElement.textContent = '' // Limpiar mensajes

        if (!username || !password) {
            messageElement.textContent = 'Por favor llenen todos los campos.'
            return
        }

        try {
            const response = await fetch(`${backendUrl}/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            })

            const data = await response.json() // Esperamos JSON del backend

            if (response.ok) { // Status 201 Created
                messageElement.style.color = 'green'
                messageElement.textContent = data.message + ' Pueden ir a Login.'
                registerForm.reset() // Limpiar formulario
            } else { // Error (400, 409, 500...)
                messageElement.style.color = 'red'
                messageElement.textContent = `Error: ${data.error || response.statusText}`
            }
        } catch (error) {
            console.error('Error de registro:', error)
            messageElement.style.color = 'red'
            messageElement.textContent = 'Registro falló. Problema de red o del servidor. Revisen la consola.'
        }
    })
})