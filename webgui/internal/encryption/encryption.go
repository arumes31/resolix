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
	"os"
	"strconv"
	"sync"

	"golang.org/x/crypto/pbkdf2"
)

var (
	// fixedSalt is used so we only run the expensive PBKDF2 once per password
	fixedSalt = []byte("TailscaleDNSHist")
	keyCache  = make(map[string][]byte)
	keyMu     sync.RWMutex
)

func getIterCount() int {
	if v := os.Getenv("PBKDF2_ITERATIONS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i >= 100000 {
			return i
		}
	}
	// Recommended modern minimum for PBKDF2-HMAC-SHA256
	// Tuning: Adjust PBKDF2_ITERATIONS env var to target ~100ms latency on deployment hardware
	return 600000
}

func getKey(password string) []byte {
	keyMu.RLock()
	k, ok := keyCache[password]
	keyMu.RUnlock()
	if ok {
		return k
	}

	keyMu.Lock()
	defer keyMu.Unlock()
	if k, ok := keyCache[password]; ok {
		return k
	}
	k = pbkdf2.Key([]byte(password), fixedSalt, getIterCount(), 32, sha256.New)
	keyCache[password] = k
	return k
}

// Encrypt encrypts plaintext using AES-GCM and PBKDF2.
func Encrypt(plaintext []byte, password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("encryption password required")
	}

	key := getKey(password)
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

	// For the fast format, we just prepend the nonce to the ciphertext
	// We no longer store the 16-byte random salt per line.
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
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

	key := getKey(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract the nonce and ciphertext
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Old formats (with random salts) will fail authentication here very quickly,
	// preventing the O(n * 100ms) startup hang.
	return gcm.Open(nil, nonce, ciphertext, nil)
}
