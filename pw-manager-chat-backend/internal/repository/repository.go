package repository

import (
	"context"

	"github.com/Anon-HP/pw-manager-chat-backend/internal/models"
)

type UserRepository interface {
	CreateUser(ctx context.Context, user *models.User, keys *models.UserKeys) error
	GetUserByUserName(ctx context.Context, username string) (*models.User, error)
	GetUserByID(ctx context.Context, userID string) (*models.User, error)
	GetUserKeys(ctx context.Context, userID string) (*models.UserKeys, error)
}

type VaultRepository interface {
	SaveEntry(ctx context.Context, entry *models.VaultEntry) error
	GetEntriesByUserID(ctx context.Context, userID string) ([]*models.VaultEntry, error)
	GetEntriesByType(ctx context.Context, userID string, entryType string) ([]*models.VaultEntry, error)
	GetEntryByEntryID(ctx context.Context, entryID string, userID string) (*models.VaultEntry, error)
	DeleteEntry(ctx context.Context, entryID string, userID string) error
}
