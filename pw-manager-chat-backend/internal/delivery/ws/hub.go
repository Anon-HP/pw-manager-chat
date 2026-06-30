package ws

import (
	"log"
	"sync"
	"time"

	"github.com/Anon-HP/pw-manager-chat-backend/internal/models"
	"github.com/google/uuid"
)

type Hub struct {
	mu         sync.RWMutex
	clients    map[string]map[*Client]bool
	Broadcast  chan *models.ChatMessage
	Register   chan *Client
	Unregister chan *Client
	repo       MessageRepository
}

type MessageRepository interface {
	SaveMessage(msg *models.ChatMessage) error
	GetPendingMessages(userID string) ([]*models.ChatMessage, error)
	DeleteMessages(userID string, messageIDs []string) error
}

func NewHub(repo MessageRepository) *Hub {
	return &Hub{
		clients:    make(map[string]map[*Client]bool),
		Broadcast:  make(chan *models.ChatMessage),
		Register:   make(chan *Client),
		Unregister: make(chan *Client),
		repo:       repo,
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.Register:
			h.mu.Lock()

			if h.clients[client.UserID] == nil {
				h.clients[client.UserID] = make(map[*Client]bool)
			}

			h.clients[client.UserID][client] = true
			h.mu.Unlock()

			go func() {
				defer func() {
					if r := recover(); r != nil {
						// r contains whatever value was passed to panic()
						log.Printf("recovered panic: %v", r)
					}
				}()

				pendingMessages, err := h.repo.GetPendingMessages(client.UserID)

				if err != nil {
					log.Printf("Could not fetch Offline Messages for user %s due to error: %v.\n", client.UserID, err)
				}

				if err == nil && len(pendingMessages) > 0 {
					var deliveredIDs []string

				loop:
					for _, msg := range pendingMessages {
						sent := false
						select {
						case client.Send <- msg:
							sent = true

						default:
							if sent {
								deliveredIDs = append(deliveredIDs, msg.ID)
							} else {
								break loop
							}
						}

						deliveredIDs = append(deliveredIDs, msg.ID)
					}

					if len(deliveredIDs) > 0 {
						if err := h.repo.DeleteMessages(client.UserID, deliveredIDs); err != nil {
							log.Printf("Could not Delete Offline Messages for user %s due to error: %v.\n", client.UserID, err)
						}
					}
				}
			}()

		case client := <-h.Unregister:
			h.mu.Lock()

			if connections, ok := h.clients[client.UserID]; ok {
				if _, ok := connections[client]; ok {
					delete(connections, client)
					close(client.Send)

					if len(connections) == 0 {
						delete(h.clients, client.UserID)
					}
				}
			}
			h.mu.Unlock()

		case message := <-h.Broadcast:
			h.mu.RLock()

			receiverConnections, isReceiverOnline := h.clients[message.ReceiverID]

			h.mu.RUnlock()

			if isReceiverOnline {
				for client := range receiverConnections {
					select {
					case client.Send <- message:

					default:
						close(client.Send)
						h.mu.Lock()
						delete(receiverConnections, client)
						h.mu.Unlock()
					}
				}
			} else {
				err := h.repo.SaveMessage(message)

				if err != nil {
					log.Printf("CRITICAL ERROR: Failed to save offline message from %s to %s due to error: %v.\n", message.SenderID, message.ReceiverID, err)

					h.mu.RLock()
					senderConnections, isSenderOnline := h.clients[message.SenderID]
					h.mu.RUnlock()

					if isSenderOnline {
						systemErrorMsg := &models.ChatMessage{
							ID:         uuid.NewString(),
							Type:       "system_error",
							SenderID:   "SYSTEM",
							ReceiverID: message.SenderID,
							Content:    "Message Failed to Deliver. Please Try Again Later.",
							TimeStamp:  time.Now(),
						}

						for client := range senderConnections {
							select {
							case client.Send <- systemErrorMsg:

							default:
								close(client.Send)

								h.mu.Lock()
								delete(senderConnections, client)
								h.mu.Unlock()
							}
						}
					}
				}
			}
		}
	}
}
