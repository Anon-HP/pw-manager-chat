package service

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/Anon-HP/pw-manager-chat-backend/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

// var jwtSecretKey = config.JWTSecretKey

func generateJWT(userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(15 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(config.JWTSecretKey)
	if err != nil {
		return "", errors.New("Error: Could not Fetch Keys." + err.Error())
	}

	return signedToken, nil
}

func generateSecureRefreshToken(length int) (string, error) {
	b := make([]byte, length)

	_, err := rand.Read(b)

	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}
