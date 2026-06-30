//auth_service.go

package service

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/Anon-HP/pw-manager-chat-backend/internal/models"
	"github.com/Anon-HP/pw-manager-chat-backend/internal/repository"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	Register(ctx context.Context, user string, email string, plainTextPassword string, clientIP string, userAgent string) (*models.User, error)
	Login(ctx context.Context, identifier string, isEmail bool, plainTextPassword string, rememberMe bool, clientIP string, userAgent string) (*models.User, string, string, string, error)
	Refresh(ctx context.Context, refreshToken string) (string, error)
	Logout(ctx context.Context, refreshToken string) error
	DeleteAccount(ctx context.Context, userID string, plainTextPassword string) error
}

type authService struct {
	repo repository.UserRepository
}

func NewAuthService(repo repository.UserRepository) AuthService {
	return &authService{repo: repo}
}

func (a *authService) Register(ctx context.Context, user string, email string, plainTextPassword string, clientIP string, userAgent string) (*models.User, error) {
	pwned, err := isPasswordPwned(ctx, plainTextPassword)

	if err != nil {
		log.Printf("HIBP check failed %v", err)
	} else if pwned {
		return nil, errors.New("Password been breached. Choose a different one.")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(plainTextPassword), bcrypt.DefaultCost)

	if err != nil {
		return nil, errors.New("Error: Couldn't Save Password:" + err.Error())
	}

	newUser := &models.User{
		ID:                    uuid.NewString(),
		Username:              user,
		Email:                 email,
		PasswordHash:          string(hashedPassword),
		RegistrationIP:        clientIP,
		RegistrationUserAgent: userAgent,
		CreatedAt:             time.Now(),
	}

	newKeys, err := generateVaultKeys(newUser.ID, plainTextPassword)

	if err != nil {
		return nil, errors.New("Error: Failed To Forge Vault Keys:" + err.Error())
	}

	err = a.repo.CreateUser(ctx, newUser, newKeys)

	if err != nil {
		return nil, fmt.Errorf("Failed to save user to database: %w\n", err)
	}

	return newUser, nil
}

func (a *authService) Login(ctx context.Context, identifier string, isEmail bool, plainTextPassword string, rememberMe bool, clientIP string, userAgent string) (*models.User, string, string, string, error) {
	var user *models.User // We are creating these outside if/else because if we initialise them inside if/else, they'll not be able to be used outside that if/else block
	var err error

	if isEmail {
		user, err = a.repo.GetUserByEmail(ctx, identifier)
	} else {
		user, err = a.repo.GetUserByUserName(ctx, identifier)
	}

	if err != nil {
		return nil, "", "", "", errors.New("Error: Invalid Credetials.")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(plainTextPassword))
	if err != nil {
		return nil, "", "", "", errors.New("Error: Invalid Credentials.")
	}

	userKeys, err := a.repo.GetUserKeys(ctx, user.ID)

	if err != nil {
		return nil, "", "", "", errors.New("Error: Could not Fetch Keys." + err.Error())
	}

	privateKeyBytes, err := unlockVaultKeys(plainTextPassword, userKeys.VaultKeySalt, userKeys.EncryptedPrivateKey)

	if err != nil {
		return nil, "", "", "", errors.New("Error: Database Corruption:" + err.Error())
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	privateKeyPEM := string(pem.EncodeToMemory(pemBlock))

	accessToken, err := generateJWT(user.ID)

	if err != nil {
		return nil, "", "", "", errors.New("Error: Failed to Generate Access Token:" + err.Error())
	}

	var refreshTokenDuration time.Duration

	if rememberMe {
		refreshTokenDuration = time.Hour * 24 * 30
	} else {
		refreshTokenDuration = time.Hour * 24
	}

	refreshTokenString, err := generateSecureRefreshToken(32)

	if err != nil {
		return nil, "", "", "", errors.New("Error: Failed to Generate Refresh Token:" + err.Error())
	}

	session := &models.Session{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		RefreshToken: refreshTokenString,
		ClientIP:     clientIP,
		UserAgent:    userAgent,
		IsRevoked:    false,
		ExpiresAt:    time.Now().Add(refreshTokenDuration),
		CreatedAt:    time.Now(),
	}

	err = a.repo.CreateSession(ctx, session)

	if err != nil {
		return nil, "", "", "", errors.New("Error: Failed to Generate Session:" + err.Error())
	}

	return user, privateKeyPEM, accessToken, refreshTokenString, nil
}

func (a *authService) Refresh(ctx context.Context, refreshToken string) (string, error) {
	session, err := a.repo.GetSessionByToken(ctx, refreshToken)

	if err != nil {
		return "", errors.New("Error: Invalid Refresh Token.")
	}

	if session.IsRevoked {
		return "", errors.New("Error: Session Expired. Please Log In Again.")
	}

	if time.Now().After(session.ExpiresAt) {
		// Automatically clean up the dead session
		_ = a.repo.DeleteSession(ctx, session.ID)
		return "", errors.New("Error: Session Expired. Please Log In Again.")
	}

	newAccessToken, err := generateJWT(session.UserID)

	if err != nil {
		return "", errors.New("Error: Failed to Generate New Access Token.")
	}

	return newAccessToken, nil
}

func (a *authService) Logout(ctx context.Context, refreshToken string) error {
	session, err := a.repo.GetSessionByToken(ctx, refreshToken)

	if err != nil {
		return nil
	}

	return a.repo.DeleteSession(ctx, session.ID)
}

func (a *authService) DeleteAccount(ctx context.Context, userID string, plainTextPassword string) error {
	user, err := a.repo.GetUserByID(ctx, userID)
	if err != nil {
		return errors.New("user not found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(plainTextPassword)); err != nil {
		return repository.ErrInvalidPassword
	}

	return a.repo.DeleteUser(ctx, userID)
}
