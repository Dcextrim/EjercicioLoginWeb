package handlers

import (
	// Adjust the path based on your project structure
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	// Import your models package (adjust path 'myapp' if your module name is different)
	"EjercicioLogin/models"

	"golang.org/x/crypto/bcrypt"
)

// postLoginHandler handles user login attempts.
func PostLoginHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var creds models.LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, `{"error": "Cuerpo de solicitud inválido"}`, http.StatusBadRequest)
			return
		}
		if creds.Username == "" || creds.Password == "" {
			http.Error(w, `{"error": "Usuario y contraseña requeridos"}`, http.StatusBadRequest)
			return
		}

		var storedHash string
		var userID int
		err := db.QueryRow("SELECT id, password_hash FROM users WHERE username = ?", creds.Username).Scan(&userID, &storedHash)
		if err != nil {
			/////aqui termina el cambio
			// Use the factory from the models package
			models.NewErrorResponse("Invalid username or password") // Generic message
			//////Lo que esta entre esto se queda
			if err == sql.ErrNoRows {
				http.Error(w, `{"error": "Usuario o contraseña inválidos"}`, http.StatusUnauthorized)
			} else {
				log.Println("Error consultando usuario:", err)
				http.Error(w, `{"error": "Error interno del servidor"}`, http.StatusInternalServerError)
			}
			return
		}

		// Comparar hash (necesitamos bcrypt aquí de nuevo)
		err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(creds.Password))
		if err != nil {
			http.Error(w, `{"error": "Usuario o contraseña inválidos"}`, http.StatusUnauthorized)
			return
		}

		// --- INICIO CAMBIOS JWT ---
		// ¡Login Exitoso! Generar y guardar JWT
		tokenString, expirationTime, err := generateJWT(userID)
		if err != nil {
			log.Printf("Error generando JWT para user %d: %v", userID, err)
			http.Error(w, `{"error": "Error interno al generar sesión"}`, http.StatusInternalServerError)
			return
		}

		// Guardar el hash del token en la DB
		err = storeToken(db, userID, tokenString, expirationTime)
		if err != nil {
			log.Printf("Error guardando token para user %d: %v", userID, err)
			http.Error(w, `{"error": "Error interno al guardar sesión"}`, http.StatusInternalServerError)
			return
		}

		log.Printf("Login JWT exitoso para usuario ID: %d (%s)", userID, creds.Username)

		// Devolver el token JWT al cliente
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
		// --- FIN CAMBIOS JWT ---
	}
}
