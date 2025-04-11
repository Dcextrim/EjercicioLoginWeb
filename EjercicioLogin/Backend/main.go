package main

import (
	"EjercicioLogin/handlers"
	"database/sql"

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
	r.Post("/register", handlers.PostRegisterHandler(db))
	r.Post("/login", handlers.PostLoginHandler(db))

	// Iniciar servidor
	port := ":3000"
	log.Printf("Servidor escuchando en puerto %s", port)
	log.Fatal(http.ListenAndServe(port, r))
}

func PostRegisterHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("User registered successfully"))
	}
}

func PostLoginHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User logged in successfully"))
	}
}
