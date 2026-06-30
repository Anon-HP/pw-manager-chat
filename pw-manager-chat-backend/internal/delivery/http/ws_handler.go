// ws_handler.go

package http

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"

	"github.com/Anon-HP/pw-manager-chat-backend/internal/delivery/ws"
	"github.com/Anon-HP/pw-manager-chat-backend/internal/middleware"
	"github.com/Anon-HP/pw-manager-chat-backend/internal/models"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,

	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")

		if origin == "" {
			return true // NOte: if NOT testing using postman or curl, change this to false
		}

		u, err := url.Parse(origin)

		if err != nil {
			return false
		}

		if u.Host == "pw-manager-chat.abc.xyz" { // change this to your domain when deploying
			return true
		}

		log.Printf("Invalid Frontend Domain: %s", u.Host)
		return false
	},
}

type WSTicketRepository interface {
	CreateWSTicket(userID string) string
	ConsumeWSTicket(ticket string) (string, error)
}

type WSHandler struct {
	hub  *ws.Hub
	repo WSTicketRepository
}

func NewWSHandler(hub *ws.Hub, repo WSTicketRepository) *WSHandler {
	return &WSHandler{
		hub:  hub,
		repo: repo,
	}
}

func (h *WSHandler) ServeWS(w http.ResponseWriter, r *http.Request) {
	ticket := r.URL.Query().Get("ticket")

	userID, err := h.repo.ConsumeWSTicket(ticket)

	if err != nil {
		http.Error(w, "Unauthorised Access", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)

	if err != nil {
		log.Printf("Failed to upgrade HTTP to WS with error %v.\n", err)
		return
	}

	client := &ws.Client{
		Hub:    h.hub,
		UserID: userID,
		Conn:   conn,
		Send:   make(chan *models.ChatMessage, 256),
	}

	client.Hub.Register <- client

	go client.ReadPump()
	go client.WritePump()
}

func (h *WSHandler) GetTicket(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())

	if err != nil {
		sendError(w, http.StatusUnauthorized, "Unauthorised.")
		return
	}
	ticket := h.repo.CreateWSTicket(userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"ticket": ticket})
}
