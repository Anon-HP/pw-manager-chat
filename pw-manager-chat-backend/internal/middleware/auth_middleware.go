package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Anon-HP/pw-manager-chat-backend/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const userIDKey contextKey = "userID"

// var jwtSecretKey = config.JWTSecretKey

func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			sendUnauthorized(w, "Missing Authorization Header.")
			return
		}

		parts := strings.Split(authHeader, " ")

		if len(parts) != 2 || parts[0] != "Bearer" {
			sendUnauthorized(w, "Invalid Authorization Format. Expected 'Bearer <Token>'.")
			return
		}

		tokenString := parts[1]

		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected Signing Method: %v", t.Header["alg"])
			}
			return config.JWTSecretKey, nil
		})

		if err != nil || !token.Valid {
			sendUnauthorized(w, "Invalid or Expired Token.")
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)

		if !ok {
			sendUnauthorized(w, "Invalid Token Claims.")
			return
		}

		userID, ok := claims["sub"].(string)

		if !ok {
			sendUnauthorized(w, "User ID Not Found in Token")
			return
		}

		ctx := context.WithValue(r.Context(), userIDKey, userID)

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func GetUserID(ctx context.Context) (string, error) {
	userID, ok := ctx.Value(userIDKey).(string)

	if !ok {
		return "", fmt.Errorf("User ID Not Found in Context")
	}

	return userID, nil
}

func sendUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
