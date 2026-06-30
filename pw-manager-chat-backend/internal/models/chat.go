package models

import "time"

type ChatMessage struct {
	ID         string    `json:"id" db:"id"`
	Type       string    `json:"type" db:"type"`
	SenderID   string    `json:"sender_id" db:"sender_id"`
	ReceiverID string    `json:"receiver_id" db:"receiver_id"`
	Content    string    `json:"content" db:"content"`
	TimeStamp  time.Time `json:"timestamp" db:"timestamp"`
}
