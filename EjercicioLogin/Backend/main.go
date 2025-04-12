package main

import (
	"EjercicioLogin/handlers"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	// Conectar a la base de datos
	db, err := setupDatabase("./users.db")
	if err != nil {
		log.Fatal("CRITICAL: No se pudo conectar a la base de datos:", err)
	}
	defer db.Close()

	// Crear router Chi
	r := chi.NewRouter()

	// Middlewares
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(configureCORS()) // CORS primero

	// --- Rutas Públicas ---
	r.Route("/auth", func(r chi.Router) {
		r.Post("/register", handlers.PostRegisterHandler(db)) // Registro
		r.Post("/login", handlers.PostLoginHandler(db))       // Login
	})

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("API de Login v1.0"))
	})

	// --- Rutas Protegidas ---
	r.Group(func(r chi.Router) {
		r.Use(handlers.JwtAuthMiddleware(db)) // Aquí se aplica el middleware JWT

		r.Post("/auth/logout", handlers.PostLogoutHandler(db))
		r.Get("/users/profile", getUserProfileHandler(db))
	})

	// (Opcional: mantener ruta pública)
	//r.Get("/users/{userID}", handlers.GetUserHandler(db))

	// Iniciar servidor
	port := ":3000"
	log.Printf("Servidor escuchando en puerto %s", port)
	log.Fatal(http.ListenAndServe(port, r))
}

// --- Handler para Perfil del Usuario Protegido ---
type UserResponse struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
}

func getUserProfileHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := r.Context().Value("userID").(int)
		if !ok || userID == 0 {
			http.Error(w, `{"error": "No se pudo obtener ID de usuario del token"}`, http.StatusInternalServerError)
			return
		}

		var userResp UserResponse
		err := db.QueryRow("SELECT id, username FROM users WHERE id = ?", userID).
			Scan(&userResp.ID, &userResp.Username)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, `{"error": "Usuario del token no encontrado"}`, http.StatusNotFound)
			} else {
				log.Printf("Error consultando perfil para user %d: %v", userID, err)
				http.Error(w, `{"error": "Error interno del servidor"}`, http.StatusInternalServerError)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userResp)
	}
}
