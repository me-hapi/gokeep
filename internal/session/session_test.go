package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIsValidWithin24h(t *testing.T) {
	dir := t.TempDir()

	// Create session file
	sessionPath := filepath.Join(dir, sessionFile)
	if err := os.WriteFile(sessionPath, []byte{}, 0600); err != nil {
		t.Fatalf("create session file: %v", err)
	}

	// Should be valid (just created)
	if !IsValid(dir) {
		t.Error("session should be valid within 24h")
	}
}

func TestIsValidAfter24h(t *testing.T) {
	dir := t.TempDir()

	// Create session file
	sessionPath := filepath.Join(dir, sessionFile)
	if err := os.WriteFile(sessionPath, []byte{}, 0600); err != nil {
		t.Fatalf("create session file: %v", err)
	}

	// Set mtime to 25 hours ago
	oldTime := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(sessionPath, oldTime, oldTime); err != nil {
		t.Fatalf("set mtime: %v", err)
	}

	// Should be invalid
	if IsValid(dir) {
		t.Error("session should be invalid after 24h")
	}
}

func TestIsValidNoFile(t *testing.T) {
	dir := t.TempDir()

	// No session file
	if IsValid(dir) {
		t.Error("session should be invalid when file doesn't exist")
	}
}

func TestTouch(t *testing.T) {
	dir := t.TempDir()

	// Touch should create file if it doesn't exist
	if err := Touch(dir); err != nil {
		t.Fatalf("Touch failed: %v", err)
	}

	sessionPath := filepath.Join(dir, sessionFile)
	if _, err := os.Stat(sessionPath); os.IsNotExist(err) {
		t.Error("Touch should create session file")
	}

	// Should be valid after touch
	if !IsValid(dir) {
		t.Error("session should be valid after Touch")
	}
}

func TestClear(t *testing.T) {
	dir := t.TempDir()

	// Create session file
	sessionPath := filepath.Join(dir, sessionFile)
	if err := os.WriteFile(sessionPath, []byte{}, 0600); err != nil {
		t.Fatalf("create session file: %v", err)
	}

	// Clear should delete it
	if err := Clear(dir); err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	if _, err := os.Stat(sessionPath); !os.IsNotExist(err) {
		t.Error("Clear should delete session file")
	}
}

func TestStoreAndLoadPassword(t *testing.T) {
	dir := t.TempDir()
	password := "test-master-password-123"

	// Store password
	if err := StorePassword(dir, password); err != nil {
		t.Fatalf("StorePassword failed: %v", err)
	}

	// Load password
	loaded, err := LoadPassword()
	if err != nil {
		t.Fatalf("LoadPassword failed: %v", err)
	}

	if loaded != password {
		t.Errorf("loaded password doesn't match: got %q, want %q", loaded, password)
	}

	// Clean up
	if err := Clear(dir); err != nil {
		t.Fatalf("Clear failed: %v", err)
	}
}
