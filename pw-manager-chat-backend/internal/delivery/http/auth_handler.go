package http

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/Anon-HP/pw-manager-chat-backend/internal/service"
)

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,20}$`)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

type AuthHandler struct {
	service service.AuthService
}

func NewAuthHandler(s service.AuthService) *AuthHandler {
	return &AuthHandler{service: s}
}

type registerRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (a *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Error: Method Not Allowed!", http.StatusMethodNotAllowed)
		return
	}

	var req registerRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Error: Invalid Request Payload", http.StatusBadRequest)
		return
	}

	validationErrors := make(map[string]string)

	if req.Username == "" {
		validationErrors["username"] = "Username is required!"
	} else if !usernameRegex.MatchString(req.Username) {
		validationErrors["username"] = "Username must be 3-20 characters and contain only letters, numbers, hyphens, or underscores."
	}
	if req.Email == "" {
		validationErrors["email"] = "E-Mail is required!"
	} else if !emailRegex.MatchString(req.Email) {
		validationErrors["email"] = "E-mail is invalid."
	}
	if req.Password == "" {
		validationErrors["password"] = "Password is required!"
	}

	if len(validationErrors) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		json.NewEncoder(w).Encode(map[string]any{
			"error":  "Validation failed.",
			"fields": validationErrors,
		})
		return
	}

	user, err := a.service.Register(r.Context(), req.Username, req.Email, req.Password)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	json.NewEncoder(w).Encode(user)
}
