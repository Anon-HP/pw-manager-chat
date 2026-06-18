package repository

import (
	"context"
	"errors"
	"sync"

	"github.com/Anon-HP/pw-manager-chat-backend/internal/models"
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

	// Vault Data (The Encrypted Passwords/Notes)
	vaultEntries         map[string]*models.VaultEntry
	vaultEntriesByUserID map[string][]*models.VaultEntry // Groups entries for quick fetching
}

// NewMemoryStore acts as our database constructor.
// It initializes all the empty maps so Go doesn't throw a nil pointer panic when we try to write to them.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		usersByUsername:      make(map[string]*models.User),
		usersByID:            make(map[string]*models.User),
		usersByEmail:         make(map[string]*models.User),
		keys:                 make(map[string]*models.UserKeys),
		vaultEntries:         make(map[string]*models.VaultEntry),
		vaultEntriesByUserID: make(map[string][]*models.VaultEntry),
	}
}

// CreateUser handles the registration pipeline.
func (m *MemoryStore) CreateUser(ctx context.Context, user *models.User, keys *models.UserKeys) error {
	// 1. Constraint Checks: We verify uniqueness BEFORE locking the database
	// to keep our system highly performant and prevent unnecessary blocking.
	if _, exists := m.usersByUsername[user.Username]; exists {
		return errors.New("Error: Username is already taken")
	}
	if _, exists := m.usersByEmail[user.Email]; exists {
		return errors.New("Error: Email is already registered")
	}

	// Security Check: Ensure we aren't accidentally attaching keys to the wrong user.
	if user.ID != keys.UserID {
		return errors.New("Security Error: User ID does not match Keys UserID")
	}

	// 2. Lock the database for writing.
	// Defer ensures the lock is mathematically guaranteed to release when the function ends.
	m.mu.Lock()
	defer m.mu.Unlock()

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

	m.vaultEntries[entry.ID] = entry

	return nil
}

// GetEntriesByUserID pulls down the entire encrypted vault for a specific user.
func (m *MemoryStore) GetEntriesByUserID(ctx context.Context, userID string) ([]*models.VaultEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	vaultEntries, _ := m.vaultEntriesByUserID[userID]

	// if !exists {
	//  return nil, errors.New("Error: No Entries for this user.")
	// }
	return vaultEntries, nil
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
