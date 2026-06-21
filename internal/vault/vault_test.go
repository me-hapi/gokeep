package vault

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/youruser/gokeep/internal/crypto"
)

func testSalt(t *testing.T) []byte {
	t.Helper()
	salt, err := crypto.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	return salt
}

func TestVaultCRUDRoundtrip(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	// Init vault
	if err := Init(dir, key, testSalt(t)); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Open vault
	v, err := Open(dir, key)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Add secret
	s := Secret{
		Name:     "github",
		Username: "user@example.com",
		Password: "secret123",
		URL:      "https://github.com",
	}
	id := v.Add(s)

	// Get secret
	got, ok := v.Get(id)
	if !ok {
		t.Fatalf("Get failed: secret not found")
	}
	if got.Name != s.Name {
		t.Errorf("expected name %q, got %q", s.Name, got.Name)
	}
	if got.Password != s.Password {
		t.Errorf("expected password %q, got %q", s.Password, got.Password)
	}

	// Save vault
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Re-open vault
	v2, err := Open(dir, key)
	if err != nil {
		t.Fatalf("Re-open failed: %v", err)
	}

	// Verify secret persisted
	got2, ok := v2.Get(id)
	if !ok {
		t.Fatalf("Get after re-open failed: secret not found")
	}
	if got2.Name != s.Name {
		t.Errorf("expected name %q after re-open, got %q", s.Name, got2.Name)
	}

	// List secrets
	secrets := v2.List()
	if len(secrets) != 1 {
		t.Errorf("expected 1 secret, got %d", len(secrets))
	}

	// Remove secret
	if !v2.Remove(id) {
		t.Error("Remove returned false, expected true")
	}

	// Verify removed
	if _, ok := v2.Get(id); ok {
		t.Error("secret still exists after Remove")
	}

	// Save and verify persistence
	if err := v2.Save(dir, key); err != nil {
		t.Fatalf("Save after remove failed: %v", err)
	}

	v3, err := Open(dir, key)
	if err != nil {
		t.Fatalf("Re-open after remove failed: %v", err)
	}
	if len(v3.List()) != 0 {
		t.Errorf("expected 0 secrets after remove, got %d", len(v3.List()))
	}
}

func TestRemoveNonexistent(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)

	if err := Init(dir, key, testSalt(t)); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	v, err := Open(dir, key)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if v.Remove("nonexistent") {
		t.Error("Remove returned true for nonexistent ID")
	}
}

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)

	if err := Init(dir, key, testSalt(t)); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	v, err := Open(dir, key)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	v.Add(Secret{Name: "test", Username: "user", Password: "pass"})

	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Check that temp file doesn't exist
	tmpPath := filepath.Join(dir, tmpFileName)
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("temp file should not exist after Save")
	}
}

func TestInitAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)

	if err := Init(dir, key, testSalt(t)); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Try to init again
	err := Init(dir, key, testSalt(t))
	if err != ErrVaultExists {
		t.Errorf("expected ErrVaultExists, got %v", err)
	}
}

func TestOpenNotFound(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)

	_, err := Open(dir, key)
	if err != ErrVaultNotFound {
		t.Errorf("expected ErrVaultNotFound, got %v", err)
	}
}

func TestOpenWrongKey(t *testing.T) {
	dir := t.TempDir()
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	for i := range key1 {
		key1[i] = byte(i)
		key2[i] = byte(i + 1)
	}

	if err := Init(dir, key1, testSalt(t)); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	_, err := Open(dir, key2)
	if err == nil {
		t.Error("expected error opening with wrong key")
	}
}
