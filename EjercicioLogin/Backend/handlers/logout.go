package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

func PostLogoutHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extraer el token del header (asumiendo que el middleware jwtAuth ya lo validó)
		authHeader := r.Header.Get("Authorization")
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			// Esto no debería pasar si el middleware funcionó, pero por si acaso
			http.Error(w, `{"error": "Token inválido en logout"}`, http.StatusBadRequest)
			return
		}
		tokenString := parts[1]

		// Invalidar el token en la base de datos
		err := invalidateToken(db, tokenString)
		if err != nil {
			log.Printf("Error invalidando token durante logout: %v", err)
			// No necesariamente un error crítico para el cliente, pero loggear
			// Podríamos decidir si devolver 500 o un 200 OK de todas formas
		}

		log.Printf("Logout procesado para token (hash: %s...)", hashToken(tokenString)[:10])
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "Logout exitoso"})
	}
}
