//memory_store.go

package repository

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Anon-HP/pw-manager-chat-backend/internal/models"
	"github.com/google/uuid"
)

// MemoryStore acts as our temporary, thread-safe in-memory database.
// It uses a Mutex to prevent data races, and multiple maps acting as "indexes"
// so we can achieve O(1) lookup times regardless of how we search for a user.
type MemoryStore struct {
	// mu is a Read/Write Mutex. It ensures 10,000 users can read simultaneously,
	// but writes are locked down strictly one at a time.
	mu sync.RWMutex

	// User Indexes (All point to the exact same memory address for a given user)
	usersByUsername map[string]*models.User
	usersByID       map[string]*models.User
	usersByEmail    map[string]*models.User

	// Cryptographic Keys
	keys map[string]*models.UserKeys

	sessions        map[string]*models.Session
	sessionsByToken map[string]*models.Session
	// Vault Data (The Encrypted Passwords/Notes)
	vaultEntries         map[string]*models.VaultEntry
	vaultEntriesByUserID map[string][]*models.VaultEntry // Groups entries for quick fetching

	offlineMessages         map[string]*models.ChatMessage
	offlineMessagesByUserID map[string][]*models.ChatMessage

	wsTickets map[string]string
}

// NewMemoryStore acts as our database constructor.
// It initializes all the empty maps so Go doesn't throw a nil pointer panic when we try to write to them.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		usersByUsername:         make(map[string]*models.User),
		usersByID:               make(map[string]*models.User),
		usersByEmail:            make(map[string]*models.User),
		keys:                    make(map[string]*models.UserKeys),
		sessions:                make(map[string]*models.Session),
		sessionsByToken:         make(map[string]*models.Session),
		vaultEntries:            make(map[string]*models.VaultEntry),
		vaultEntriesByUserID:    make(map[string][]*models.VaultEntry),
		offlineMessages:         make(map[string]*models.ChatMessage),
		offlineMessagesByUserID: make(map[string][]*models.ChatMessage),
		wsTickets:               make(map[string]string),
	}
}

// CreateUser handles the registration pipeline.
func (m *MemoryStore) CreateUser(ctx context.Context, user *models.User, keys *models.UserKeys) error {
	// 1. Constraint Checks: We verify uniqueness BEFORE locking the database
	// to keep our system highly performant and prevent unnecessary blocking.
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.usersByUsername[user.Username]; exists {
		return ErrUsernameTaken
	}
	if _, exists := m.usersByEmail[user.Email]; exists {
		return ErrEmailTaken
	}

	// Security Check: Ensure we aren't accidentally attaching keys to the wrong user.
	if user.ID != keys.UserID {
		return errors.New("Security Error: User ID does not match Keys UserID")
	}

	// 2. Lock the database for writing.
	// Defer ensures the lock is mathematically guaranteed to release when the function ends.

	// 3. Save the actual data into our indexes.
	m.usersByUsername[user.Username] = user
	m.usersByEmail[user.Email] = user
	m.usersByID[user.ID] = user
	m.keys[keys.UserID] = keys
	return nil
}

// GetUserByUserName fetches a user via their public-facing username.
func (m *MemoryStore) GetUserByUserName(ctx context.Context, username string) (*models.User, error) {
	// RLock is a "Read Lock". It prevents writes from happening during the read,
	// but allows infinite other reads to happen at the exact same time.
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, exists := m.usersByUsername[username]

	if !exists {
		return nil, errors.New("Error: User Not Found.")
	}
	return user, nil
}

// GetUserByEmail fetches a user via their private email (used primarily for Login).
func (m *MemoryStore) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, exists := m.usersByEmail[email]

	if !exists {
		return nil, errors.New("Error: User Not Found.")
	}
	return user, nil
}

// GetUserByID fetches a user via their database UUID.
func (m *MemoryStore) GetUserByID(ctx context.Context, userID string) (*models.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, exists := m.usersByID[userID]

	if !exists {
		return nil, errors.New("Error: User Not Found.")
	}
	return user, nil
}

// GetUserKeys retrieves the specific AES-GCM locked safe for a given user UUID.
func (m *MemoryStore) GetUserKeys(ctx context.Context, userID string) (*models.UserKeys, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	userKeys, exists := m.keys[userID]

	if !exists {
		return nil, errors.New("Error: Keys Not Found.")
	}
	return userKeys, nil
}

// SaveEntry adds a new encrypted item (password, secure note, etc.) to the user's vault.
func (m *MemoryStore) SaveEntry(ctx context.Context, entry *models.VaultEntry) error {
	// Standard write lock to safely update the maps.
	m.mu.Lock()
	defer m.mu.Unlock()

	entry.CreatedAt = time.Now()
	entry.UpdatedAt = time.Now()
	m.vaultEntries[entry.ID] = entry

	m.vaultEntriesByUserID[entry.UserID] = append(m.vaultEntriesByUserID[entry.UserID], entry)

	return nil
}

// GetEntriesByUserID pulls down the entire encrypted vault for a specific user.
func (m *MemoryStore) GetEntriesByUserID(ctx context.Context, userID string) ([]*models.VaultEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	vaultEntries, exists := m.vaultEntriesByUserID[userID]

	if !exists {
		return []*models.VaultEntry{}, nil
	}

	finalVaultEntries := make([]*models.VaultEntry, len(vaultEntries))
	copy(finalVaultEntries, vaultEntries)

	return finalVaultEntries, nil
}

// GetEntriesByType allows filtering a user's vault locally (e.g., fetching only "Credit Cards").
func (m *MemoryStore) GetEntriesByType(ctx context.Context, userID string, entryType string) ([]*models.VaultEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	vaultEntries, _ := m.vaultEntriesByUserID[userID]

	var filteredVaultEntries []*models.VaultEntry

	// Loop through the user's entries and append only the ones matching the requested type.
	for _, entry := range vaultEntries {
		if entry.Type == entryType {
			filteredVaultEntries = append(filteredVaultEntries, entry)
		}
	}

	return filteredVaultEntries, nil
}

// GetEntryByEntryID fetches a single, specific item from the vault while ensuring authorization.
func (m *MemoryStore) GetEntryByEntryID(ctx context.Context, entryID string, userID string) (*models.VaultEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	vaultEntry, exists := m.vaultEntries[entryID]

	if !exists {
		return nil, errors.New("Error: Entry Not Found.")
	}

	// Critical Security Check: Ensure the person requesting this entry actually owns it.
	// This prevents IDOR (Insecure Direct Object Reference) vulnerabilities.
	if vaultEntry.UserID != userID {
		return nil, errors.New("Error: Unauthorised Access!")
	}

	return vaultEntry, nil
}

// DeleteEntry securely removes an item from the vault and cleans up the indexes.
func (m *MemoryStore) DeleteEntry(ctx context.Context, entryID string, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	vaultEntry, exists := m.vaultEntries[entryID]

	if !exists {
		return errors.New("Error: Entry Not Found.")
	}

	// Secondary authorization check to prevent malicious deletion.
	if vaultEntry.UserID != userID {
		return errors.New("Error: Unauthorised Access!")
	}

	// 1. Remove it from the global entry index
	delete(m.vaultEntries, entryID)

	// 2. Rebuild the user's personal vault list, omitting the deleted item.
	// This is a standard Go slice manipulation pattern.
	userEntries := m.vaultEntriesByUserID[userID]
	var updatedEntries []*models.VaultEntry

	for _, entry := range userEntries {
		if entry.ID != entryID {
			updatedEntries = append(updatedEntries, entry)
		}
	}

	// 3. Update the index with the newly rebuilt slice
	m.vaultEntriesByUserID[userID] = updatedEntries

	return nil
}

func (m *MemoryStore) BulkDeleteEntries(ctx context.Context, entryIDs []string, userID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	deletedCount := 0

	deletedIDs := make(map[string]bool)

	for _, id := range entryIDs {
		existingItem, exists := m.vaultEntries[id]

		if exists && existingItem.UserID == userID {
			delete(m.vaultEntries, id)
			deletedIDs[id] = true
			deletedCount++
		}
	}

	if len(deletedIDs) == 0 {
		return 0, nil
	}

	userEntries := m.vaultEntriesByUserID[userID]

	updatedEntries := make([]*models.VaultEntry, 0, len(userEntries)-len(deletedIDs))

	for _, entry := range userEntries {
		if !deletedIDs[entry.ID] {
			updatedEntries = append(updatedEntries, entry)
		}
	}

	m.vaultEntriesByUserID[userID] = updatedEntries

	return deletedCount, nil
}

func (m *MemoryStore) UpdateEntry(ctx context.Context, entry *models.VaultEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existingItem, exists := m.vaultEntries[entry.ID]

	if !exists {
		return errors.New("Entry Not Found.")
	}

	if existingItem.UserID != entry.UserID {
		return errors.New("User does not own this Entry.")
	}

	existingItem.EncryptedPayload = entry.EncryptedPayload
	existingItem.EncryptedItemKey = entry.EncryptedItemKey
	existingItem.UpdatedAt = time.Now()

	return nil
}

func (m *MemoryStore) CreateSession(ctx context.Context, session *models.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions[session.ID] = session
	m.sessionsByToken[session.RefreshToken] = session

	return nil
}

func (m *MemoryStore) GetSessionByToken(ctx context.Context, token string) (*models.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessionsByToken[token]

	if !exists {
		return nil, errors.New("Error: Session Not Found.")
	}

	return session, nil
}

func (m *MemoryStore) DeleteSession(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[sessionID]

	if !exists {
		return nil
	}

	delete(m.sessionsByToken, session.RefreshToken)

	delete(m.sessions, sessionID)

	return nil
}

func (m *MemoryStore) SaveMessage(msg *models.ChatMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.offlineMessages[msg.ID] = msg
	m.offlineMessagesByUserID[msg.ReceiverID] = append(m.offlineMessagesByUserID[msg.ReceiverID], msg)

	return nil
}

func (m *MemoryStore) GetPendingMessages(userID string) ([]*models.ChatMessage, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	messages, exists := m.offlineMessagesByUserID[userID]

	if !exists {
		return []*models.ChatMessage{}, nil
	}

	return messages, nil
}

func (m *MemoryStore) DeleteMessages(userID string, messageIDs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	toDelete := make(map[string]bool)

	for _, id := range messageIDs {
		message, exists := m.offlineMessages[id]

		if !exists {
			continue
		}

		if message.ReceiverID != userID {
			continue
		}

		toDelete[id] = true
		delete(m.offlineMessages, id)
	}

	var updatedInbox []*models.ChatMessage

	for _, existingMessage := range m.offlineMessagesByUserID[userID] {
		if !toDelete[existingMessage.ID] {
			updatedInbox = append(updatedInbox, existingMessage)
		}
	}

	if len(updatedInbox) == 0 {
		delete(m.offlineMessagesByUserID, userID)
	} else {
		m.offlineMessagesByUserID[userID] = updatedInbox
	}

	return nil
}

func (m *MemoryStore) CreateWSTicket(userID string) string {
	m.mu.Lock()

	ticket := uuid.NewString()
	m.wsTickets[ticket] = userID
	m.mu.Unlock()

	go func(ticketID string) {
		time.Sleep(10 * time.Second)

		m.mu.Lock()
		defer m.mu.Unlock()

		delete(m.wsTickets, ticketID)
	}(ticket)

	return ticket
}

func (m *MemoryStore) ConsumeWSTicket(ticket string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	userID, exists := m.wsTickets[ticket]

	if !exists {
		return "", errors.New("Invalid or Expired Token")
	}

	delete(m.wsTickets, ticket)

	return userID, nil
}

func (m *MemoryStore) RevokeSession(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, exists := m.sessions[sessionID]
	if !exists {
		return nil
	}
	session.IsRevoked = true
	return nil
}

func (m *MemoryStore) DeleteUser(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.usersByID[userID]
	if !exists {
		return errors.New("user not found")
	}

	// 1. Delete all vault entries
	if entries, ok := m.vaultEntriesByUserID[userID]; ok {
		for _, entry := range entries {
			delete(m.vaultEntries, entry.ID)
		}
		delete(m.vaultEntriesByUserID, userID)
	}

	// 2. Delete all sessions — scan since there's no sessionsByUserID index
	for sessionID, session := range m.sessions {
		if session.UserID == userID {
			delete(m.sessionsByToken, session.RefreshToken)
			delete(m.sessions, sessionID)
		}
	}

	// 3. Delete offline messages addressed to this user
	if messages, ok := m.offlineMessagesByUserID[userID]; ok {
		for _, msg := range messages {
			delete(m.offlineMessages, msg.ID)
		}
		delete(m.offlineMessagesByUserID, userID)
	}

	// 4. Delete cryptographic keys
	delete(m.keys, userID)

	// 5. Remove from all three user indexes
	delete(m.usersByUsername, user.Username)
	delete(m.usersByEmail, user.Email)
	delete(m.usersByID, userID)

	return nil
}
