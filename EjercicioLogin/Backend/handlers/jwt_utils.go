package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ¡IMPORTANTE! Usar una clave secreta segura y guardarla fuera del código (ej. variable de entorno)
var jwtSecretKey = []byte("mi_clave_secreta_muy_segura_cambiar_esto") // ¡CAMBIAR ESTO!

// generateJWT crea un nuevo token JWT para un usuario
func generateJWT(userID int) (string, time.Time, error) {
	expirationTime := time.Now().Add(24 * time.Hour) // Token válido por 24 horas
	claims := &jwt.RegisteredClaims{
		Subject:   fmt.Sprintf("%d", userID), // Guardamos el UserID como string en "Subject"
		ExpiresAt: jwt.NewNumericDate(expirationTime),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return "", time.Time{}, err
	}
	return tokenString, expirationTime, nil
}

// hashToken crea un hash SHA256 del token para almacenamiento seguro
func hashToken(token string) string {
	hasher := sha256.New()
	hasher.Write([]byte(token))
	return hex.EncodeToString(hasher.Sum(nil))
}

// storeToken guarda el hash del token en la base de datos
func storeToken(db *sql.DB, userID int, token string, expiresAt time.Time) error {
	tokenHash := hashToken(token)
	stmt, err := db.Prepare("INSERT INTO active_tokens(user_id, token_hash, expires_at) VALUES(?, ?, ?)")
	if err != nil {
		return fmt.Errorf("error preparando statement para guardar token: %w", err)
	}
	defer stmt.Close()
	_, err = stmt.Exec(userID, tokenHash, expiresAt)
	if err != nil {
		return fmt.Errorf("error ejecutando statement para guardar token: %w", err)
	}
	return nil
}

// invalidateToken marca un token como inactivo (elimina de la tabla)
func invalidateToken(db *sql.DB, token string) error {
	tokenHash := hashToken(token)
	stmt, err := db.Prepare("DELETE FROM active_tokens WHERE token_hash = ?")
	if err != nil {
		return fmt.Errorf("error preparando statement para invalidar token: %w", err)
	}
	defer stmt.Close()
	result, err := stmt.Exec(tokenHash)
	if err != nil {
		return fmt.Errorf("error ejecutando statement para invalidar token: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("Intento de invalidar token no encontrado o ya invalidado (hash: %s...)", tokenHash[:10])
		// No necesariamente un error, podría ser un token expirado o ya invalidado
	} else {
		log.Printf("Token invalidado exitosamente (hash: %s...)", tokenHash[:10])
	}
	return nil
}

// validateTokenAndGetUserID verifica el token, su validez en DB y devuelve el UserID
func validateTokenAndGetUserID(db *sql.DB, tokenString string) (int, error) {
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Verificar método de firma
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("método de firma inesperado: %v", token.Header["alg"])
		}
		return jwtSecretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			log.Println("Token expirado detectado:", err)
			// Limpiar token expirado de la DB (opcional, pero buena práctica)
			go func() { // Ejecutar en goroutine para no bloquear
				errClean := cleanupExpiredToken(db, tokenString)
				if errClean != nil {
					log.Printf("Error limpiando token expirado de DB: %v", errClean)
				}
			}()
		}
		return 0, fmt.Errorf("error parseando token: %w", err)
	}

	if !token.Valid {
		return 0, errors.New("token inválido")
	}

	// Verificar si el token (su hash) está activo en la base de datos
	tokenHash := hashToken(tokenString)
	var dbUserID int
	var expiresAt time.Time
	err = db.QueryRow("SELECT user_id, expires_at FROM active_tokens WHERE token_hash = ?", tokenHash).Scan(&dbUserID, &expiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, errors.New("token no encontrado o inactivo en DB")
		}
		return 0, fmt.Errorf("error consultando token en DB: %w", err)
	}

	// Doble check de expiración (aunque ParseWithClaims ya lo hace)
	if time.Now().After(expiresAt) {
		go func() { // Limpiar si está expirado pero aún en DB
			errClean := cleanupExpiredToken(db, tokenString)
			if errClean != nil {
				log.Printf("Error limpiando token expirado de DB (check secundario): %v", errClean)
			}
		}()
		return 0, errors.New("token expirado (según DB)")
	}

	// El token es válido y activo, obtener UserID del claim "Subject"
	userID := claims.Subject // Extraer directamente el Subject del token
	if userID == "" {
		return 0, errors.New("el token no contiene un Subject válido")
	}

	// Convertir userID string a int
	var finalUserID int
	fmt.Sscan(userID, &finalUserID)
	if finalUserID == 0 || finalUserID != dbUserID {
		return 0, errors.New("discrepancia de UserID entre token y DB")
	}

	return finalUserID, nil
}

// Middleware de autenticación JWT
func JwtAuthMiddleware(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Falta header de autorización", http.StatusUnauthorized)
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				http.Error(w, "Header de autorización mal formado (se espera 'Bearer token')", http.StatusUnauthorized)
				return
			}

			tokenString := parts[1]
			userID, err := validateTokenAndGetUserID(db, tokenString)
			if err != nil {
				log.Printf("Error validando token: %v", err)
				http.Error(w, "Token inválido o expirado", http.StatusUnauthorized)
				return
			}

			// Añadir userID al contexto de la solicitud para usarlo en handlers posteriores
			ctx := context.WithValue(r.Context(), "userID", userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// cleanupExpiredToken (helper para limpiar tokens expirados)
func cleanupExpiredToken(db *sql.DB, tokenString string) error {
	tokenHash := hashToken(tokenString)
	_, err := db.Exec("DELETE FROM active_tokens WHERE token_hash = ?", tokenHash)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("error eliminando token expirado hash %s: %w", tokenHash[:10], err)
	}
	log.Printf("Token expirado limpiado de DB (hash: %s...)", tokenHash[:10])
	return nil
}

// (Necesitarás importar "context" también)
