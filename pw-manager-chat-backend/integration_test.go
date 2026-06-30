package main_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Anon-HP/pw-manager-chat-backend/internal/config"
	deliveryHTTP "github.com/Anon-HP/pw-manager-chat-backend/internal/delivery/http"
	"github.com/Anon-HP/pw-manager-chat-backend/internal/delivery/ws"
	"github.com/Anon-HP/pw-manager-chat-backend/internal/middleware"
	"github.com/Anon-HP/pw-manager-chat-backend/internal/repository"
	"github.com/Anon-HP/pw-manager-chat-backend/internal/service"
	"github.com/gorilla/websocket"
)

// setupTestServer mimics your main.go wiring and returns a test server
func setupTestServer() *httptest.Server {
	os.Setenv("JWT_SECRET_KEY", "super-secret-test-key-1234567890")
	config.Init()

	masterDB := repository.NewMemoryStore()
	chatHub := ws.NewHub(masterDB)
	go chatHub.Run()

	authService := service.NewAuthService(masterDB)
	authHandler := deliveryHTTP.NewAuthHandler(authService)

	vaultHandler := deliveryHTTP.NewVaultHandler(masterDB)
	wsHandler := deliveryHTTP.NewWSHandler(chatHub, masterDB)

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/register", authHandler.Register)
	mux.HandleFunc("POST /api/login", authHandler.Login)
	mux.HandleFunc("POST /api/refresh", authHandler.Refresh)
	mux.HandleFunc("POST /api/logout", authHandler.Logout)

	mux.HandleFunc("GET /api/vault", middleware.RequireAuth(vaultHandler.GetEntries))
	mux.HandleFunc("POST /api/vault/create", middleware.RequireAuth(vaultHandler.CreateEntry))
	mux.HandleFunc("DELETE /api/vault/delete", middleware.RequireAuth(vaultHandler.DeleteEntry))
	mux.HandleFunc("DELETE /api/vault/delete-bulk", middleware.RequireAuth(vaultHandler.BulkDeleteEntries))
	mux.HandleFunc("PATCH /api/vault/update", middleware.RequireAuth(vaultHandler.UpdateEntry))

	mux.HandleFunc("GET /api/ws/ticket", middleware.RequireAuth(wsHandler.GetTicket))
	mux.HandleFunc("GET /api/ws", wsHandler.ServeWS)

	return httptest.NewServer(mux)
}

func TestEndToEndLifecycle(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	var accessToken string
	var refreshToken string
	var vaultEntryID = "test-entry-id-123"
	var wsTicket string

	client := &http.Client{Timeout: 10 * time.Second}

	// A complex password is required to pass the real HIBP API check in auth_service
	testPassword := "SuperSecureTestPassword123!@#"

	// ==========================================
	// 1. REGISTER
	// ==========================================
	t.Run("1_Register", func(t *testing.T) {
		payload := map[string]string{
			"username": "testuser1",
			"email":    "testuser1@example.com",
			"password": testPassword,
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/register", bytes.NewBuffer(body))

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("Expected status 201 Created, got %d", resp.StatusCode)
		}
	})

	// ==========================================
	// 2. LOGIN
	// ==========================================
	t.Run("2_Login", func(t *testing.T) {
		payload := map[string]any{
			"identifier":  "testuser1@example.com",
			"password":    testPassword,
			"remember_me": true,
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/login", bytes.NewBuffer(body))

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200 OK, got %d", resp.StatusCode)
		}

		var resBody map[string]any
		json.NewDecoder(resp.Body).Decode(&resBody)

		accessToken = resBody["access_token"].(string)
		refreshToken = resBody["refresh_token"].(string)

		if accessToken == "" || refreshToken == "" {
			t.Fatalf("Failed to extract tokens from login response")
		}
	})

	// ==========================================
	// 3. CREATE VAULT ENTRY
	// ==========================================
	t.Run("3_CreateVaultEntry", func(t *testing.T) {
		payload := map[string]string{
			"id":                 vaultEntryID,
			"type":               "password",
			"encrypted_payload":  "encrypted_data_blob",
			"encrypted_item_key": "encrypted_key_blob",
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/vault/create", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("Expected status 201 Created, got %d", resp.StatusCode)
		}
	})

	// ==========================================
	// 4. GET VAULT ENTRIES
	// ==========================================
	t.Run("4_GetVaultEntries", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/vault", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200 OK, got %d", resp.StatusCode)
		}

		var entries []map[string]any
		json.NewDecoder(resp.Body).Decode(&entries)

		if len(entries) != 1 {
			t.Fatalf("Expected 1 vault entry, got %d", len(entries))
		}
		if entries[0]["id"] != vaultEntryID {
			t.Fatalf("Expected entry ID %s, got %s", vaultEntryID, entries[0]["id"])
		}
	})

	// ==========================================
	// 5. UPDATE VAULT ENTRY
	// ==========================================
	t.Run("5_UpdateVaultEntry", func(t *testing.T) {
		payload := map[string]string{
			"id":                 vaultEntryID,
			"encrypted_payload":  "new_encrypted_data",
			"encrypted_item_key": "new_encrypted_key",
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPatch, ts.URL+"/api/vault/update", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200 OK, got %d", resp.StatusCode)
		}
	})

	// ==========================================
	// 6. REQUEST WS TICKET
	// ==========================================
	t.Run("6_RequestWSTicket", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/ws/ticket", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200 OK, got %d", resp.StatusCode)
		}

		var resBody map[string]string
		json.NewDecoder(resp.Body).Decode(&resBody)
		wsTicket = resBody["ticket"]

		if wsTicket == "" {
			t.Fatalf("Failed to retrieve WS ticket")
		}
	})

	// ==========================================
	// 7. WEBSOCKET CONNECT & CHAT
	// ==========================================
	t.Run("7_WebSocketChat", func(t *testing.T) {
		// Convert http:// to ws://
		wsURL := strings.Replace(ts.URL, "http://", "ws://", 1) + "/api/ws?ticket=" + wsTicket

		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatalf("Failed to upgrade WebSocket: %v", err)
		}
		defer conn.Close()

		// Test sending a JSON chat message
		msg := map[string]string{
			"type":        "text",
			"receiver_id": "some-other-user-uuid",
			"content":     "Hello World!",
		}
		if err := conn.WriteJSON(msg); err != nil {
			t.Fatalf("Failed to write to WebSocket: %v", err)
		}

		// Brief pause to allow Hub to process the message
		time.Sleep(100 * time.Millisecond)
	})

	// ==========================================
	// 8. BULK DELETE VAULT ENTRIES
	// ==========================================
	t.Run("8_BulkDeleteEntries", func(t *testing.T) {
		payload := map[string][]string{
			"ids": {vaultEntryID},
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/vault/delete-bulk", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200 OK, got %d", resp.StatusCode)
		}
	})

	// ==========================================
	// 9. REFRESH TOKEN
	// ==========================================
	t.Run("9_RefreshToken", func(t *testing.T) {
		payload := map[string]string{
			"refresh_token": refreshToken,
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/refresh", bytes.NewBuffer(body))

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200 OK, got %d", resp.StatusCode)
		}
	})

	// ==========================================
	// 10. LOGOUT
	// ==========================================
	t.Run("10_Logout", func(t *testing.T) {
		payload := map[string]string{
			"refresh_token": refreshToken,
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/logout", bytes.NewBuffer(body))

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200 OK, got %d", resp.StatusCode)
		}
	})
}
