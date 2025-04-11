package main

import (
	"EjercicioLogin/models"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	// Conectar a la base de datos
	db, err := setupDatabase("./users.db")
	if err != nil {
		log.Fatal("CRITICAL: No se pudo conectar a la base de datos:", err)
	}
	defer db.Close() // Asegurar que se cierre al final

	// Crear router Chi
	r := chi.NewRouter()

	// Middlewares
	r.Use(middleware.Logger)    // Loggea cada request
	r.Use(middleware.Recoverer) // Recupera de panics
	r.Use(configureCORS())      // Aplica nuestra configuración CORS

	// Rutas Públicas (sin autenticación requerida inicialmente)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("API de Login v1.0"))
	})
	r.Post("/register", PostRegisterHandler(db))
	r.Post("/login", PostLoginHandler(db))

	// Iniciar servidor
	port := ":3000"
	log.Printf("Servidor escuchando en puerto %s", port)
	log.Fatal(http.ListenAndServe(port, r))
}

func PostRegisterHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Decode Request Body into RegisterRequest DTO
		var req models.RegisterRequest // Use DTO from models package
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Error decoding register request: %v", err)
			response := models.NewErrorResponse("Invalid request body")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(response)
			return
		}

		// 2. Basic Validation
		if req.Username == "" || req.Password == "" {
			response := models.NewErrorResponse("Username and password cannot be empty")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(response)
			return
		}
		// Add more validation here if needed (e.g., password length)

		// 3. Hash the Password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Error hashing password for user %s: %v", req.Username, err)
			response := models.NewErrorResponse("Internal server error during registration setup")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(response)
			return
		}

		// 4. Insert User into Database
		// We use ExecContext for context propagation and get the result
		result, err := db.ExecContext(r.Context(),
			"INSERT INTO users(username, password_hash) VALUES(?, ?)",
			req.Username, string(hashedPassword),
		)

		if err != nil {
			// Default error response
			response := models.NewErrorResponse("Failed to register user")
			statusCode := http.StatusInternalServerError
			// Check for specific SQLite UNIQUE constraint error
			if err.Error() == "UNIQUE constraint failed: users.username" {
				response = models.NewErrorResponse("Username already in use")
				statusCode = http.StatusConflict
			} else {
				// Log other database errors
				log.Printf("Error inserting user %s: %v", req.Username, err)
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			json.NewEncoder(w).Encode(response)
			return
		}

		// 5. Get the ID of the newly inserted user
		userID, err := result.LastInsertId()
		if err != nil {
			// This is less likely, but handle it just in case
			log.Printf("Error getting last insert ID after registering user %s: %v", req.Username, err)
			// Send a success response but maybe log that we couldn't get the ID
			response := models.NewErrorResponse("Registration partially successful, but failed to retrieve user ID")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError) // Or maybe 201 still? Debatable.
			json.NewEncoder(w).Encode(response)
			return
		}

		// 6. Registration Successful - Prepare and Send Success Response
		log.Printf("User '%s' (ID: %d) registered successfully.", req.Username, userID)

		// Create the specific data payload for the success response
		registerData := models.RegisterSuccessData{
			UserID:   userID,
			Username: req.Username,
		}

		// Wrap the data in the standard APIResponse using the factory
		response := models.NewSuccessResponse(registerData)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated) // 201 Created is the correct status code
		json.NewEncoder(w).Encode(response)
	}
}

func PostLoginHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Decode Request Body into LoginRequest DTO from models package
		var req models.LoginRequest // Use the DTO from the models package
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Error decoding login request: %v", err)
			// Use the factory from the models package
			response := models.NewErrorResponse("Invalid request body")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(response)
			return
		}

		// 2. Basic Validation
		if req.Username == "" || req.Password == "" {
			// Use the factory from the models package
			response := models.NewErrorResponse("Username and password are required")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(response)
			return
		}

		// 3. Query Database for User ID and Hashed Password
		var storedHash string
		var userID int64 // Use int64 for database IDs
		err := db.QueryRowContext(r.Context(),
			"SELECT id, password_hash FROM users WHERE username = ?",
			req.Username,
		).Scan(&userID, &storedHash)

		if err != nil {
			// Use the factory from the models package
			response := models.NewErrorResponse("Invalid username or password") // Generic message
			statusCode := http.StatusUnauthorized

			if err != sql.ErrNoRows {
				log.Printf("Error querying user '%s': %v", req.Username, err)
				// Use the factory from the models package
				response = models.NewErrorResponse("Internal server error")
				statusCode = http.StatusInternalServerError
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			json.NewEncoder(w).Encode(response)
			return
		}

		// 4. Compare Provided Password with Stored Hash
		err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(req.Password))
		if err != nil {
			// Use the factory from the models package
			response := models.NewErrorResponse("Invalid username or password")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(response)
			return
		}

		// 5. Login Successful - Prepare and Send Success Response
		log.Printf("Login successful for user ID: %d (%s)", userID, req.Username)

		// Create the specific data payload using the DTO from the models package
		loginData := models.LoginSuccessData{ // Use the DTO from the models package
			UserID:   userID,
			Username: req.Username,
		}

		// Wrap the data in the standard APIResponse using the factory from the models package
		response := models.NewSuccessResponse(loginData)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}
