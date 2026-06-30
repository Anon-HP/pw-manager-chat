// vault_handler.go

package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Anon-HP/pw-manager-chat-backend/internal/middleware"
	"github.com/Anon-HP/pw-manager-chat-backend/internal/models"
)

type VaultRepository interface {
	SaveEntry(ctx context.Context, entry *models.VaultEntry) error
	GetEntriesByUserID(ctx context.Context, userID string) ([]*models.VaultEntry, error)
	DeleteEntry(ctx context.Context, entryID string, userID string) error
	BulkDeleteEntries(ctx context.Context, entryIDs []string, userID string) (int, error)
	UpdateEntry(ctx context.Context, entry *models.VaultEntry) error
}

type VaultHandler struct {
	repo VaultRepository
}

func NewVaultHandler(repository VaultRepository) *VaultHandler {
	return &VaultHandler{repo: repository}
}

type createEntryRequest struct {
	ID               string `json:"id"`
	Type             string `json:"type"`
	EncryptedPayload string `json:"encrypted_payload"`
	EncryptedItemKey string `json:"encrypted_item_key"`
}

type bulkDeleteRequest struct {
	IDs []string `json:"ids"`
}

type updateEntryRequest struct {
	ID               string `json:"id"`
	EncryptedPayload string `json:"encrypted_payload"`
	EncryptedItemKey string `json:"encrypted_item_key"`
}

var validEntryTypes = map[string]bool{"password": true, "note": true, "credit_card": true, "file": true}

func (v *VaultHandler) CreateEntry(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())

	if err != nil {
		sendError(w, http.StatusUnauthorized, "Unauthorized.")
		return
	}

	var req createEntryRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if !validEntryTypes[req.Type] {
		sendError(w, http.StatusBadRequest, "Invalid entry type.")
		return
	}

	entry := &models.VaultEntry{
		ID:               req.ID,
		UserID:           userID,
		Type:             req.Type,
		EncryptedPayload: req.EncryptedPayload,
		EncryptedItemKey: req.EncryptedItemKey,
	}

	if err := v.repo.SaveEntry(r.Context(), entry); err != nil {
		sendError(w, http.StatusInternalServerError, "Failed to Save Entry")
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Entry Saved Securely."})
}

func (v *VaultHandler) GetEntries(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())

	if err != nil {
		sendError(w, http.StatusUnauthorized, "Unauthorized.")
		return
	}

	entries, err := v.repo.GetEntriesByUserID(r.Context(), userID)

	if err != nil {
		sendError(w, http.StatusInternalServerError, "Failed to Fetch Vault.")
		return
	}

	if entries == nil {
		entries = []*models.VaultEntry{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

func (v *VaultHandler) DeleteEntry(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())

	if err != nil {
		sendError(w, http.StatusUnauthorized, "Unauthorized.")
		return
	}

	entryID := r.URL.Query().Get("id")

	if entryID == "" {
		sendError(w, http.StatusBadRequest, "Missing Entry ID.")
		return
	}

	if err := v.repo.DeleteEntry(r.Context(), entryID, userID); err != nil {
		sendError(w, http.StatusNotFound, err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Entry has been successfully deleted."})

}

func (v *VaultHandler) BulkDeleteEntries(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())

	if err != nil {
		sendError(w, http.StatusUnauthorized, "Unauthorized.")
		return
	}

	var req bulkDeleteRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "Invalid JSON Body.")
		return
	}

	if len(req.IDs) == 0 {
		sendError(w, http.StatusBadRequest, "No Entry IDs Provided.")
		return
	}

	deletedCount, err := v.repo.BulkDeleteEntries(r.Context(), req.IDs, userID)

	if err != nil {
		sendError(w, http.StatusInternalServerError, "Failed to Delete Entries.")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Successfully deleted %d entries.", deletedCount),
	})
}

func (v *VaultHandler) UpdateEntry(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())

	if err != nil {
		sendError(w, http.StatusUnauthorized, "Unauthorized.")
		return
	}

	var req updateEntryRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if req.ID == "" {
		sendError(w, http.StatusBadRequest, "Missing Entry ID.")
		return
	}

	entryToUpdate := &models.VaultEntry{
		ID:               req.ID,
		UserID:           userID,
		EncryptedPayload: req.EncryptedPayload,
		EncryptedItemKey: req.EncryptedItemKey,
	}

	if err := v.repo.UpdateEntry(r.Context(), entryToUpdate); err != nil {
		sendError(w, http.StatusInternalServerError, "Failed to update entry:"+err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Entry Updated Securely."})
}

func sendError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
