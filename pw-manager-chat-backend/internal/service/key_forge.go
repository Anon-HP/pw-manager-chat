package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"

	"github.com/Anon-HP/pw-manager-chat-backend/internal/models"
	"golang.org/x/crypto/argon2"
)

func generateVaultKeys(userID string, plainTextPassword string) (*models.UserKeys, error) {
	privateKeyObject, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		return nil, errors.New("Error: Failed To Generate RSA Keys:" + err.Error())
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(privateKeyObject.Public())

	if err != nil {
		return nil, errors.New("Error: Failed To Generate Public Key Bytes:" + err.Error())
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	publicKey := string(pem.EncodeToMemory(pemBlock))

	vaultSaltBytes := make([]byte, 16)
	_, err = rand.Read(vaultSaltBytes)

	if err != nil {
		return nil, errors.New("Error: Failed To Generate Vault Salt:" + err.Error())
	}

	symmetricKeyBytes := argon2.IDKey([]byte(plainTextPassword), vaultSaltBytes, 1, 64*1024, 4, 32)

	finalSaltString := base64.StdEncoding.EncodeToString(vaultSaltBytes)

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKeyObject)

	if err != nil {
		return nil, errors.New("Error: Failed To Generate Private Key Bytes:" + err.Error())
	}

	block, err := aes.NewCipher(symmetricKeyBytes)

	if err != nil {
		return nil, errors.New("Error: Failed To Generate AES Cipher:" + err.Error())
	}

	aesGCM, err := cipher.NewGCM(block)

	if err != nil {
		return nil, errors.New("Error: Failed To Generate AESGCM:" + err.Error())
	}

	nonce := make([]byte, aesGCM.NonceSize())

	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("Error: Failed To Generate Nonce:" + err.Error())
	}

	encryptedPrivateKeyBytes := aesGCM.Seal(nonce, nonce, privateKeyBytes, nil)

	finalEncryptedPrivateKey := base64.StdEncoding.EncodeToString(encryptedPrivateKeyBytes)

	return &models.UserKeys{
		UserID:              userID,
		PublicKey:           publicKey,
		EncryptedPrivateKey: finalEncryptedPrivateKey,
		VaultKeySalt:        finalSaltString,
	}, nil
}

func unlockVaultKeys(plainTextPassword string, vaultKeySaltBase64 string, encryptedPrivateKeyBase64 string) ([]byte, error) {
	vaultKeySalt, err := base64.StdEncoding.DecodeString(vaultKeySaltBase64)

	if err != nil {
		return nil, errors.New("Error: Salt Corrupted In Database:" + err.Error())
	}

	encryptedPrivateKey, err := base64.StdEncoding.DecodeString(encryptedPrivateKeyBase64)

	if err != nil {
		return nil, errors.New("Error: Private Key Corrupted In Database:" + err.Error())
	}

	symmetricKeyBytes := argon2.IDKey([]byte(plainTextPassword), vaultKeySalt, 1, 64*1024, 4, 32)

	block, err := aes.NewCipher(symmetricKeyBytes)

	if err != nil {
		return nil, errors.New("Error: Failed To Generate AES Cipher:" + err.Error())
	}

	aesGCM, err := cipher.NewGCM(block)

	if err != nil {
		return nil, errors.New("Error: Failed To Generate AESGCM:" + err.Error())
	}

	nonceSize := aesGCM.NonceSize()

	if len(encryptedPrivateKey) < nonceSize {
		return nil, errors.New("Encrypted Private Key Somehow Less Than Nonce")
	}

	nonce := encryptedPrivateKey[:nonceSize]
	cipherText := encryptedPrivateKey[nonceSize:]

	decryptedPrivateKey, err := aesGCM.Open(nil, nonce, cipherText, nil)

	if err != nil {
		return nil, errors.New("Error: Database Corruption!")
	}

	return decryptedPrivateKey, nil
}
