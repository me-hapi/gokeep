package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/youruser/gokeep/internal/crypto"
)

// Sentinel errors
var (
	ErrVaultExists     = errors.New("vault already exists")
	ErrVaultNotFound   = errors.New("vault not found: run 'gokeep init' first")
	ErrSecretNotFound  = errors.New("secret not found")
	ErrVersionMismatch = errors.New("vault version mismatch")
)

const (
	vaultFileName = "vault.enc"
	tmpFileName   = "vault.enc.tmp"
	lockFileName  = "vault.lock"
	vaultVersion  = 1
)

// Secret represents a single stored credential.
type Secret struct {
	Name      string    `json:"name"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	URL       string    `json:"url,omitempty"`
	Notes     string    `json:"notes,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Vault is the in-memory secret store.
type Vault struct {
	Secrets map[string]Secret `json:"secrets"`
}

// vaultFile is the on-disk encrypted envelope.
type vaultFile struct {
	Version int    `json:"v"`
	Salt    []byte `json:"salt"`
	Payload []byte `json:"payload"`
}

// lock represents an advisory file lock.
type lock struct {
	file *os.File
}

// acquireLock acquires an exclusive advisory lock on the vault.
func acquireLock(dir string) (*lock, error) {
	lockPath := filepath.Join(dir, lockFileName)

	// Create lock file if it doesn't exist
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}

	// Acquire exclusive lock (non-blocking)
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("vault is locked by another process")
		}
		return nil, fmt.Errorf("acquire lock: %w", err)
	}

	return &lock{file: f}, nil
}

// release releases the advisory lock.
func (l *lock) release() {
	if l.file != nil {
		syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
		l.file.Close()
	}
}

// Init creates a new vault at dir/vault.enc with the given master key and salt.
// The salt must be the same one used to derive key via crypto.DeriveKey.
func Init(dir string, key []byte, salt []byte) error {
	vaultPath := filepath.Join(dir, vaultFileName)

	// Check if vault already exists
	if _, err := os.Stat(vaultPath); err == nil {
		return ErrVaultExists
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	// Explicitly set directory permissions (umask may have loosened them)
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("set directory permissions: %w", err)
	}

	// Create empty vault
	v := &Vault{
		Secrets: make(map[string]Secret),
	}

	// Marshal vault to JSON
	vaultJSON, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal vault: %w", err)
	}

	// Encrypt vault
	payload, err := crypto.Encrypt(key, vaultJSON)
	if err != nil {
		return fmt.Errorf("encrypt vault: %w", err)
	}

	// Create vault file structure
	vf := vaultFile{
		Version: vaultVersion,
		Salt:    salt,
		Payload: payload,
	}

	// Marshal to JSON
	data, err := json.Marshal(vf)
	if err != nil {
		return fmt.Errorf("marshal vault file: %w", err)
	}

	// Write atomically with fsync
	tmpPath := filepath.Join(dir, tmpFileName)
	if err := writeAtomic(tmpPath, data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	if err := os.Rename(tmpPath, vaultPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename temp file: %w", err)
	}

	// Explicitly set file permissions
	if err := os.Chmod(vaultPath, 0600); err != nil {
		return fmt.Errorf("set vault file permissions: %w", err)
	}

	return nil
}

// Open reads and decrypts the vault from dir/vault.enc.
func Open(dir string, key []byte) (*Vault, error) {
	vaultPath := filepath.Join(dir, vaultFileName)

	// Read vault file
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrVaultNotFound
		}
		return nil, fmt.Errorf("read vault file: %w", err)
	}

	// Unmarshal vault file
	var vf vaultFile
	if err := json.Unmarshal(data, &vf); err != nil {
		return nil, fmt.Errorf("unmarshal vault file: %w", err)
	}

	// Validate version
	if vf.Version != vaultVersion {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrVersionMismatch, vaultVersion, vf.Version)
	}

	// Decrypt payload
	vaultJSON, err := crypto.Decrypt(key, vf.Payload)
	if err != nil {
		return nil, fmt.Errorf("decrypt vault: %w", err)
	}

	// Unmarshal vault
	var v Vault
	if err := json.Unmarshal(vaultJSON, &v); err != nil {
		return nil, fmt.Errorf("unmarshal vault: %w", err)
	}

	if v.Secrets == nil {
		v.Secrets = make(map[string]Secret)
	}

	return &v, nil
}

// Save encrypts and writes the vault to dir/vault.enc.
// Acquires an advisory lock to prevent concurrent writes.
func (v *Vault) Save(dir string, key []byte) error {
	// Acquire lock
	lk, err := acquireLock(dir)
	if err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}
	defer lk.release()

	vaultPath := filepath.Join(dir, vaultFileName)

	// Read existing vault file to get salt
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		return fmt.Errorf("read vault file: %w", err)
	}

	var vf vaultFile
	if err := json.Unmarshal(data, &vf); err != nil {
		return fmt.Errorf("unmarshal vault file: %w", err)
	}

	// Marshal vault to JSON
	vaultJSON, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal vault: %w", err)
	}

	// Encrypt vault
	payload, err := crypto.Encrypt(key, vaultJSON)
	if err != nil {
		return fmt.Errorf("encrypt vault: %w", err)
	}

	// Update vault file structure
	vf.Payload = payload

	// Marshal to JSON
	data, err = json.Marshal(vf)
	if err != nil {
		return fmt.Errorf("marshal vault file: %w", err)
	}

	// Write atomically with fsync
	tmpPath := filepath.Join(dir, tmpFileName)
	if err := writeAtomic(tmpPath, data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	if err := os.Rename(tmpPath, vaultPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename temp file: %w", err)
	}

	// Explicitly set file permissions
	if err := os.Chmod(vaultPath, 0600); err != nil {
		return fmt.Errorf("set vault file permissions: %w", err)
	}

	return nil
}

// writeAtomic writes data to a file atomically with fsync.
func writeAtomic(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}

	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}

	return f.Close()
}

// Add inserts a secret, returns its ID.
func (v *Vault) Add(s Secret) string {
	id := fmt.Sprintf("%x", time.Now().UnixNano())
	s.CreatedAt = time.Now()
	s.UpdatedAt = time.Now()
	v.Secrets[id] = s
	return id
}

// Get retrieves a secret by ID.
func (v *Vault) Get(id string) (Secret, bool) {
	s, ok := v.Secrets[id]
	return s, ok
}

// List returns all secrets (keyed by ID).
func (v *Vault) List() map[string]Secret {
	return v.Secrets
}

// Remove deletes a secret by ID. Returns false if not found.
func (v *Vault) Remove(id string) bool {
	if _, ok := v.Secrets[id]; !ok {
		return false
	}
	delete(v.Secrets, id)
	return true
}

// GetSalt reads the salt from the vault file.
func GetSalt(dir string) ([]byte, error) {
	vaultPath := filepath.Join(dir, vaultFileName)

	data, err := os.ReadFile(vaultPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrVaultNotFound
		}
		return nil, fmt.Errorf("read vault file: %w", err)
	}

	var vf vaultFile
	if err := json.Unmarshal(data, &vf); err != nil {
		return nil, fmt.Errorf("unmarshal vault file: %w", err)
	}

	return vf.Salt, nil
}
