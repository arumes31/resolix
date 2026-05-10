package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const saltSize = 16
const iterCount = 100000

// Encrypt encrypts plaintext using AES-GCM and PBKDF2.
func Encrypt(plaintext []byte, password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("encryption password required")
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	key := pbkdf2.Key([]byte(password), salt, iterCount, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	salt = append(salt, ciphertext...)
	return base64.StdEncoding.EncodeToString(salt), nil
}

// Decrypt decrypts a base64 encoded ciphertext using AES-GCM and PBKDF2.
func Decrypt(encodedCiphertext string, password string) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("encryption password required")
	}

	data, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return nil, err
	}

	if len(data) < saltSize {
		return nil, errors.New("ciphertext too short")
	}

	salt, ciphertext := data[:saltSize], data[saltSize:]

	key := pbkdf2.Key([]byte(password), salt, iterCount, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
