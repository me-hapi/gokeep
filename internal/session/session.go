package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zalando/go-keyring"
)

// Sentinel errors
var (
	ErrSessionExpired = errors.New("session expired: re-enter master password")
	ErrNoSession      = errors.New("no active session")
)

const (
	keyringService = "fort"
	keyringAccount = "master-password" // Store password, not derived key
	sessionFile    = "session"
	SessionMaxAge  = 24 * time.Hour
)

// IsValid returns true if session file exists and mtime < 24h old.
func IsValid(dir string) bool {
	sessionPath := filepath.Join(dir, sessionFile)

	info, err := os.Stat(sessionPath)
	if err != nil {
		return false
	}

	return time.Since(info.ModTime()) < SessionMaxAge
}

// StorePassword saves the master password to OS keyring and writes session timestamp.
// We store the password (not the derived key) so the key must be re-derived each time,
// reducing the window of exposure if the keyring is compromised.
// ponytail: keyring rollback paths on filesystem failure are unexercised by tests.
var StorePassword = func(dir string, password string) error {
	// Store password in keyring
	if err := keyring.Set(keyringService, keyringAccount, password); err != nil {
		return fmt.Errorf("store password in keyring: %w", err)
	}

	// Create directory if needed
	if err := os.MkdirAll(dir, 0700); err != nil {
		keyring.Delete(keyringService, keyringAccount)
		return fmt.Errorf("create directory: %w", err)
	}

	// Write session file (empty, mtime = now)
	sessionPath := filepath.Join(dir, sessionFile)
	if err := os.WriteFile(sessionPath, []byte{}, 0600); err != nil {
		os.Remove(sessionPath) // best-effort: leave no stale session file
		keyring.Delete(keyringService, keyringAccount)
		return fmt.Errorf("write session file: %w", err)
	}

	// Explicitly set permissions (umask may have loosened them)
	if err := os.Chmod(sessionPath, 0600); err != nil {
		os.Remove(sessionPath) // best-effort: leave no stale session file
		keyring.Delete(keyringService, keyringAccount)
		return fmt.Errorf("set session file permissions: %w", err)
	}

	return nil
}

// LoadPassword reads the master password from OS keyring.
var LoadPassword = func() (string, error) {
	password, err := keyring.Get(keyringService, keyringAccount)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", ErrNoSession
		}
		return "", fmt.Errorf("read password from keyring: %w", err)
	}

	return password, nil
}

// Touch updates session file mtime to now (extends session on each use).
func Touch(dir string) error {
	sessionPath := filepath.Join(dir, sessionFile)

	// Create directory if needed
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	// Create file if it doesn't exist
	if _, err := os.Stat(sessionPath); os.IsNotExist(err) {
		if err := os.WriteFile(sessionPath, []byte{}, 0600); err != nil {
			return fmt.Errorf("create session file: %w", err)
		}
	}

	// Update mtime to now
	now := time.Now()
	if err := os.Chtimes(sessionPath, now, now); err != nil {
		return fmt.Errorf("update session timestamp: %w", err)
	}

	return nil
}

// Clear removes key from keyring and deletes session file.
var Clear = func(dir string) error {
	// Remove from keyring
	if err := keyring.Delete(keyringService, keyringAccount); err != nil {
		// Ignore "not found" errors
		if !errors.Is(err, keyring.ErrNotFound) {
			return fmt.Errorf("delete key from keyring: %w", err)
		}
	}

	// Delete session file
	sessionPath := filepath.Join(dir, sessionFile)
	if err := os.Remove(sessionPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete session file: %w", err)
	}

	return nil
}
