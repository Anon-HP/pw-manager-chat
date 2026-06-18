package main

import (
	"log"
	"net/http"

	deliveryHTTP "github.com/Anon-HP/pw-manager-chat-backend/internal/delivery/http"
	"github.com/Anon-HP/pw-manager-chat-backend/internal/repository"
	"github.com/Anon-HP/pw-manager-chat-backend/internal/service"
)

func main() {
	userRepo := repository.NewMemoryStore()

	authService := service.NewAuthService(userRepo)

	authHandler := deliveryHTTP.NewAuthHandler(authService)

	mux := http.NewServeMux()

	mux.HandleFunc("/api/register", authHandler.Register)

	log.Println("Password Manager Live on port 5000!!")

	err := http.ListenAndServe(":5000", mux)

	if err != nil {
		log.Fatalf("The server crashed with error: %v.\n", err)
	}
}
