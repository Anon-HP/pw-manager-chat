//auth_handler.go

package http

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"regexp"

	"github.com/Anon-HP/pw-manager-chat-backend/internal/middleware"
	"github.com/Anon-HP/pw-manager-chat-backend/internal/models"
	"github.com/Anon-HP/pw-manager-chat-backend/internal/repository"
	"github.com/Anon-HP/pw-manager-chat-backend/internal/service"
)

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,20}$`)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

var ErrInvalidPassword = errors.New("Invalid Password")

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

type loginRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
	RememberMe bool   `json:"remember_me"`
}

type tokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type loginResponse struct {
	User          *models.User `json:"user"`
	PrivateKeyPEM string       `json:"private_key_pem"`
	AccessToken   string       `json:"access_token"`
	RefreshToken  string       `json:"refresh_token"`
}

type deleteAccountRequest struct {
	Password string `json:"password"`
}

func (a *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	// if r.Method != http.MethodPost {
	// 	http.Error(w, "Error: Method Not Allowed!", http.StatusMethodNotAllowed)
	// 	return
	// }

	var req registerRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Error: Invalid Request Payload", http.StatusBadRequest)
		return
	}

	clientIP := GetClientIP(r)
	userAgent := r.Header.Get("User-Agent")

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
	} else if len(req.Password) < 12 || len(req.Password) > 100 {
		validationErrors["password"] = "Password must be between 12 and 100 charatcers."
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

	user, err := a.service.Register(r.Context(), req.Username, req.Email, req.Password, clientIP, userAgent)

	if err != nil {
		if errors.Is(err, repository.ErrUsernameTaken) {
			sendError(w, http.StatusConflict, "Username is already in use.")
			return
		}
		if errors.Is(err, repository.ErrEmailTaken) {
			sendError(w, http.StatusConflict, "E-mail is already in use.")
			return
		}

		sendError(w, http.StatusInternalServerError, "Registration fail")

		// http.Error(w, err.Error(), http.StatusInternalServerError)

		// w.Header().Set("Content-Type", "application/json")
		// w.WriteHeader(http.StatusInternalServerError)

		// json.NewEncoder(w).Encode(map[string]any{
		// 	"error":  "Registration failed.",
		// 	"fields": err,
		// })

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	json.NewEncoder(w).Encode(user)
}

func (a *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	// if r.Method != http.MethodPost {
	// 	http.Error(w, "Error: Method Not Allowed!", http.StatusMethodNotAllowed)
	// 	return
	// }

	var req loginRequest

	err := json.NewDecoder(r.Body).Decode(&req)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON Format."})
		return
	}

	clientIP := GetClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	validationErrors := make(map[string]string)
	var isEmail bool

	if req.Identifier == "" {
		validationErrors["identifier"] = "Username or E-mail is required."
	} else if emailRegex.MatchString(req.Identifier) {
		isEmail = true
	} else if usernameRegex.MatchString(req.Identifier) {
		isEmail = false
	} else {
		validationErrors["identifier"] = "Please Enter a Valid Username or E-Mail."
	}

	if req.Password == "" {
		validationErrors["password"] = "Password is required."
	}

	if len(validationErrors) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"errors": validationErrors})
		return
	}

	user, privateKeyPEM, accessToken, refreshToken, err := a.service.Login(r.Context(), req.Identifier, isEmail, req.Password, req.RememberMe, clientIP, userAgent)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	response := loginResponse{
		User:          user,
		PrivateKeyPEM: privateKeyPEM,
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (a *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	// if r.Method != http.MethodPost {
	// 	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	// 	return
	// }

	var req tokenRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		sendError(w, http.StatusBadRequest, "Error: Refresh Token Required.")
		return
	}

	newAccessToken, err := a.service.Refresh(r.Context(), req.RefreshToken)

	if err != nil {
		sendError(w, http.StatusUnauthorized, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"access_token": newAccessToken,
	})
}

func (a *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// if r.Method != http.MethodPost {
	// 	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	// 	return
	// }

	var req tokenRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		sendError(w, http.StatusBadRequest, "Error: Refresh Token Required.")
		return
	}

	if err := a.service.Logout(r.Context(), req.RefreshToken); err != nil {
		sendError(w, http.StatusInternalServerError, "Failed to Log Out Securely.")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Successfully Logged Out.",
	})
}

func (a *AuthHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		sendError(w, http.StatusUnauthorized, "Unauthorized.")
		return
	}

	var req deleteAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "Invalid JSON.")
		return
	}

	if req.Password == "" {
		sendError(w, http.StatusBadRequest, "Password is required to delete your account.")
		return
	}

	if err := a.service.DeleteAccount(r.Context(), userID, req.Password); err != nil {
		if errors.Is(err, ErrInvalidPassword) {
			sendError(w, http.StatusUnauthorized, "Incorrect password.")
			return
		}
		sendError(w, http.StatusInternalServerError, "Failed to delete account.")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Account successfully deleted.",
	})
}

func GetClientIP(r *http.Request) string {
	// forwardedFor := r.Header.Get("X-Forwarded-For")

	// if forwardedFor != "" {
	// 	return strings.Split(forwardedFor, ",")[0]
	// }

	// ipStr := r.RemoteAddr

	// if colonIndex := strings.LastIndex(ipStr, ":"); colonIndex != -1 {
	// 	return ipStr[:colonIndex]
	// }

	// return ipStr

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr // fallback
	}

	return ip // Since we don't know about proxy now, we'll just be using the standard one.
}
