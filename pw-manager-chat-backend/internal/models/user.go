package models

import "time"

type User struct {
	ID           string `json:"id" db:"id"`
	Username     string `json:"username" db:"username"`
	Email        string `json:"email" db:"email"`
	PasswordHash string `json:"-" db:"password_hash"`
	// PasswordSalt string    `json:"-" db:"password_salt"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type UserKeys struct {
	UserID              string `json:"user_id" db:"user_id"`
	PublicKey           string `json:"public_key" db:"public_key"`
	EncryptedPrivateKey string `json:"-" db:"encrypted_private_key"`
	VaultKeySalt        string `json:"-" db:"vault_key_salt"`
}

type VaultEntry struct {
	ID               string    `json:"id" db:"id"`
	UserID           string    `json:"user_id" db:"user_id"`
	Type             string    `json:"type" db:"type"` // password or file
	EncryptedPayload string    `json:"encrypted_payload" db:"encrypted_payload"`
	EncryptedItemKey string    `json:"encrypted_item_key" db:"encrypted_item_key"`
	FileURL          *string   `json:"file_url,omitempty" db:"file_url"`
	SizeBytes        *int64    `json:"size_bytes,omitempty" db:"size_bytes"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
}
