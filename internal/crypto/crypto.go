package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// ErrDecrypt is returned when decryption fails (wrong key or corrupted data).
var ErrDecrypt = errors.New("decryption failed: wrong key or corrupted data")

const (
	// Argon2id parameters (OWASP recommended)
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Time    = 3         // 3 iterations
	argon2Threads = 4         // 4 parallel threads
	keyLen        = 32        // 32 bytes = 256 bits for AES-256
	saltLen       = 16        // 16 bytes salt
	nonceLen      = 12        // 12 bytes nonce for AES-GCM
)

// DeriveKey derives a 32-byte AES key from password + salt using Argon2id.
func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, keyLen)
}

// Encrypt encrypts plaintext with AES-256-GCM. Returns nonce(12) || ciphertext.
// Generates a fresh 12-byte nonce per call.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	// Return nonce || ciphertext
	result := make([]byte, nonceLen+len(ciphertext))
	copy(result, nonce)
	copy(result[nonceLen:], ciphertext)

	return result, nil
}

// Decrypt decrypts data produced by Encrypt. Expects nonce(12) || ciphertext.
func Decrypt(key, data []byte) ([]byte, error) {
	if len(data) < nonceLen {
		return nil, ErrDecrypt
	}

	nonce := data[:nonceLen]
	ciphertext := data[nonceLen:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecrypt
	}

	return plaintext, nil
}

// GenerateSalt returns 16 random bytes.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}
