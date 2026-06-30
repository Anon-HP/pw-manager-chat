package config

import (
	"log"
	"os"
)

var JWTSecretKey []byte

func Init() {
	key := os.Getenv("JWT_SECRET_KEY")

	if key == "" {
		log.Fatal("JWT_SECRET_KEY environment variable is not set")
	}

	JWTSecretKey = []byte(key)
}
