package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Anon-HP/pw-manager-chat-backend/internal/config"
	deliveryHTTP "github.com/Anon-HP/pw-manager-chat-backend/internal/delivery/http"
	"github.com/Anon-HP/pw-manager-chat-backend/internal/delivery/ws"
	"github.com/Anon-HP/pw-manager-chat-backend/internal/middleware"
	"github.com/Anon-HP/pw-manager-chat-backend/internal/repository"
	"github.com/Anon-HP/pw-manager-chat-backend/internal/service"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()
	config.Init()
	go middleware.CleanupLimiters()
	// 1. THE SINGLETON DATABASE
	masterDB := repository.NewMemoryStore()

	// 2. THE CHAT ENGINE
	chatHub := ws.NewHub(masterDB)
	go chatHub.Run()

	// 3. SERVICES & HANDLERS
	authService := service.NewAuthService(masterDB)
	authHandler := deliveryHTTP.NewAuthHandler(authService)

	vaultHandler := deliveryHTTP.NewVaultHandler(masterDB)
	wsHandler := deliveryHTTP.NewWSHandler(chatHub, masterDB)

	// 4. ROUTER SETUP
	mux := http.NewServeMux()

	// Auth Routes (Public)
	mux.HandleFunc("POST /api/register", authHandler.Register)
	mux.HandleFunc("POST /api/login", authHandler.Login)
	mux.HandleFunc("POST /api/refresh", authHandler.Refresh)
	mux.HandleFunc("POST /api/logout", authHandler.Logout)
	mux.HandleFunc("DELETE /api/delete-account", middleware.RequireAuth(authHandler.DeleteAccount))

	// Vault Routes (Protected by standard middleware)
	mux.HandleFunc("GET /api/vault", middleware.RequireAuth(vaultHandler.GetEntries))
	mux.HandleFunc("POST /api/vault/create", middleware.RequireAuth(vaultHandler.CreateEntry))
	mux.HandleFunc("DELETE /api/vault/delete", middleware.RequireAuth(vaultHandler.DeleteEntry))
	mux.HandleFunc("DELETE /api/vault/delete-bulk", middleware.RequireAuth(vaultHandler.BulkDeleteEntries))
	mux.HandleFunc("PATCH /api/vault/update", middleware.RequireAuth(vaultHandler.UpdateEntry))

	// Chat Routes
	// Protected REST call to get a 10-second ticket
	mux.HandleFunc("GET /api/ws/ticket", middleware.RequireAuth(wsHandler.GetTicket))

	// Unprotected WS upgrader (It validates the ticket internally)
	mux.HandleFunc("GET /api/ws", wsHandler.ServeWS)

	// 5. START SERVER

	// err := http.ListenAndServe(":5000", mux)
	// if err != nil {
	// 	log.Fatalf("The server crashed with error: %v.\n", err)
	// }

	allowedOrigin := os.Getenv("FRONTEND_ORIGIN")
	handler := middleware.CORS(allowedOrigin, mux)

	srv := &http.Server{Addr: ":5000", Handler: handler}
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	log.Println("Password Manager & Chat Engine Live on port 5000!!")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("Server crashed: %v\n", err)
	}

}
