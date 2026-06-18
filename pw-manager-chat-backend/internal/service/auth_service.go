package service

import (
	"context"
	"errors"
	"time"

	"github.com/Anon-HP/pw-manager-chat-backend/internal/models"
	"github.com/Anon-HP/pw-manager-chat-backend/internal/repository"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	Register(ctx context.Context, user string, email string, plainTextPassword string) (*models.User, error)
}

type authService struct {
	repo repository.UserRepository
}

func NewAuthService(repo repository.UserRepository) AuthService {
	return &authService{repo: repo}
}

func (a *authService) Register(ctx context.Context, user string, email string, plainTextPassword string) (*models.User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(plainTextPassword), bcrypt.DefaultCost)

	if err != nil {
		return nil, errors.New("Error: Couldn't Save Password:" + err.Error())
	}

	newUser := &models.User{
		ID:           uuid.NewString(),
		Username:     user,
		Email:        email,
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
	}

	newKeys, err := generateVaultKeys(newUser.ID, plainTextPassword)

	if err != nil {
		return nil, errors.New("Error: Failed To Forge Vault Keys:" + err.Error())
	}

	err = a.repo.CreateUser(ctx, newUser, newKeys)

	if err != nil {
		return nil, errors.New("Error: Failed To Save User To Database:" + err.Error())
	}

	return newUser, nil
}
