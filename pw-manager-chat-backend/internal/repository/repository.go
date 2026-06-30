package repository

import (
	"context"
	"errors"

	"github.com/Anon-HP/pw-manager-chat-backend/internal/models"
)

var (
	ErrUsernameTaken   = errors.New("username already taken")
	ErrEmailTaken      = errors.New("email already registered")
	ErrInvalidPassword = errors.New("Invalid Password")
)

type UserRepository interface {
	CreateUser(ctx context.Context, user *models.User, keys *models.UserKeys) error
	GetUserByUserName(ctx context.Context, username string) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByID(ctx context.Context, userID string) (*models.User, error)
	GetUserKeys(ctx context.Context, userID string) (*models.UserKeys, error)
	CreateSession(ctx context.Context, session *models.Session) error
	GetSessionByToken(ctx context.Context, token string) (*models.Session, error)
	DeleteSession(ctx context.Context, sessionID string) error
	DeleteUser(ctx context.Context, userID string) error
}

// type VaultRepository interface {
// 	SaveEntry(ctx context.Context, entry *models.VaultEntry) error
// 	GetEntriesByUserID(ctx context.Context, userID string) ([]*models.VaultEntry, error)
// 	GetEntriesByType(ctx context.Context, userID string, entryType string) ([]*models.VaultEntry, error)
// 	GetEntryByEntryID(ctx context.Context, entryID string, userID string) (*models.VaultEntry, error)
// 	DeleteEntry(ctx context.Context, entryID string, userID string) error
// 	BulkDeleteEntries(ctx context.Context, entryIDs []string, userID string) (int, error)
// 	UpdateEntry(ctx context.Context, entry *models.VaultEntry) error
// }
