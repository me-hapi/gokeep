package vault

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/youruser/fortbyte/internal/crypto"
)

// Sentinel errors
var (
	ErrVaultExists         = errors.New("vault already exists")
	ErrVaultNotFound       = errors.New("vault not found: run 'fort init' first")
	ErrSecretNotFound      = errors.New("secret not found")
	ErrProjectNotFound     = errors.New("project not found")
	ErrEnvironmentNotFound = errors.New("environment not found")
	ErrVersionMismatch     = errors.New("vault version mismatch")
	ErrDuplicateName       = errors.New("name already exists")
)

const (
	FileName     = "vault.enc"
	tmpFileName  = "vault.enc.tmp"
	lockFileName = "vault.lock"
	vaultVersion = 1
)

// Project represents a logical grouping of environments and secrets.
type Project struct {
	UID         string    `json:"uid"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	URL         string    `json:"url,omitempty"`
	Notes       string    `json:"notes,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Environment represents a deployment stage within a project.
type Environment struct {
	UID         string    `json:"uid"`
	Name        string    `json:"name"`
	ProjectUID  string    `json:"project_uid"`
	Description string    `json:"description,omitempty"`
	Notes       string    `json:"notes,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Secret represents a single stored secret value, optionally scoped to a project/env.
type Secret struct {
	UID            string    `json:"uid"`
	Name           string    `json:"name"`
	ProjectUID     string    `json:"project_uid,omitempty"`
	EnvironmentUID string    `json:"environment_uid,omitempty"`
	Value          string    `json:"value"`
	URL            string    `json:"url,omitempty"`
	Notes          string    `json:"notes,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Vault is the in-memory hierarchical secret store.
type Vault struct {
	Projects     map[string]Project     `json:"projects"`
	Environments map[string]Environment `json:"environments"`
	Secrets      map[string]Secret      `json:"secrets"`
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

// generateUID returns a 16-byte crypto/rand hex string (32 chars).
func generateUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("generateUID: crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b[:])
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
func Init(dir string, key []byte, salt []byte) error {
	vaultPath := filepath.Join(dir, FileName)

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
		Projects:     make(map[string]Project),
		Environments: make(map[string]Environment),
		Secrets:      make(map[string]Secret),
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
	vaultPath := filepath.Join(dir, FileName)

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

	if v.Projects == nil {
		v.Projects = make(map[string]Project)
	}
	if v.Environments == nil {
		v.Environments = make(map[string]Environment)
	}
	if v.Secrets == nil {
		v.Secrets = make(map[string]Secret)
	}

	return &v, nil
}

// Save encrypts and writes the vault to dir/vault.enc.
func (v *Vault) Save(dir string, key []byte) error {
	lk, err := acquireLock(dir)
	if err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}
	defer lk.release()

	vaultPath := filepath.Join(dir, FileName)

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

// GetSalt reads the salt from the vault file.
func GetSalt(dir string) ([]byte, error) {
	vaultPath := filepath.Join(dir, FileName)

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

// --- Project CRUD ---

// AddProject generates a UID, sets timestamps, inserts the project, and returns the UID.
func (v *Vault) AddProject(p Project) (string, error) {
	for _, existing := range v.Projects {
		if existing.Name == p.Name {
			return "", fmt.Errorf("project %q: %w", p.Name, ErrDuplicateName)
		}
	}
	p.UID = generateUID()
	p.CreatedAt = time.Now()
	p.UpdatedAt = p.CreatedAt
	v.Projects[p.UID] = p
	return p.UID, nil
}

// GetProject returns the project by UID.
func (v *Vault) GetProject(uid string) (Project, bool) {
	p, ok := v.Projects[uid]
	return p, ok
}

// ListProjects returns a defensive copy of all projects.
func (v *Vault) ListProjects() map[string]Project {
	result := make(map[string]Project, len(v.Projects))
	for k, val := range v.Projects {
		result[k] = val
	}
	return result
}

// UpdateProject applies the updates function to the project and sets UpdatedAt.
func (v *Vault) UpdateProject(uid string, updates func(*Project)) bool {
	p, ok := v.Projects[uid]
	if !ok {
		return false
	}
	updates(&p)
	p.UpdatedAt = time.Now()
	v.Projects[uid] = p
	return true
}

// RemoveProject removes a project and cascades to its environments and secrets.
func (v *Vault) RemoveProject(uid string) bool {
	if _, ok := v.Projects[uid]; !ok {
		return false
	}

	// Collect environment UIDs that belong to this project
	var envUIDs []string
	for eUID, e := range v.Environments {
		if e.ProjectUID == uid {
			envUIDs = append(envUIDs, eUID)
		}
	}

	// Remove environments and their secrets
	for _, eUID := range envUIDs {
		for sUID, s := range v.Secrets {
			if s.EnvironmentUID == eUID {
				delete(v.Secrets, sUID)
			}
		}
		delete(v.Environments, eUID)
	}

	// Remove secrets directly scoped to project
	for sUID, s := range v.Secrets {
		if s.ProjectUID == uid {
			delete(v.Secrets, sUID)
		}
	}

	delete(v.Projects, uid)
	return true
}

// --- Environment CRUD ---

// AddEnvironment generates a UID, sets timestamps, inserts the environment, and returns the UID.
func (v *Vault) AddEnvironment(e Environment) (string, error) {
	for _, existing := range v.Environments {
		if existing.Name == e.Name && existing.ProjectUID == e.ProjectUID {
			return "", fmt.Errorf("environment %q in project %q: %w", e.Name, e.ProjectUID, ErrDuplicateName)
		}
	}
	e.UID = generateUID()
	e.CreatedAt = time.Now()
	e.UpdatedAt = e.CreatedAt
	v.Environments[e.UID] = e
	return e.UID, nil
}

// GetEnvironment returns the environment by UID.
func (v *Vault) GetEnvironment(uid string) (Environment, bool) {
	e, ok := v.Environments[uid]
	return e, ok
}

// ListEnvironments returns a defensive copy of all environments.
func (v *Vault) ListEnvironments() map[string]Environment {
	result := make(map[string]Environment, len(v.Environments))
	for k, val := range v.Environments {
		result[k] = val
	}
	return result
}

// ListEnvironmentsByProject returns environments filtered by ProjectUID.
func (v *Vault) ListEnvironmentsByProject(projectUID string) map[string]Environment {
	result := make(map[string]Environment)
	for uid, e := range v.Environments {
		if e.ProjectUID == projectUID {
			result[uid] = e
		}
	}
	return result
}

// UpdateEnvironment applies the updates function to the environment and sets UpdatedAt.
func (v *Vault) UpdateEnvironment(uid string, updates func(*Environment)) bool {
	e, ok := v.Environments[uid]
	if !ok {
		return false
	}
	updates(&e)
	e.UpdatedAt = time.Now()
	v.Environments[uid] = e
	return true
}

// RemoveEnvironment removes an environment and cascades to its secrets.
func (v *Vault) RemoveEnvironment(uid string) bool {
	if _, ok := v.Environments[uid]; !ok {
		return false
	}

	// Remove secrets scoped to this environment
	for sUID, s := range v.Secrets {
		if s.EnvironmentUID == uid {
			delete(v.Secrets, sUID)
		}
	}

	delete(v.Environments, uid)
	return true
}

// --- Secret CRUD ---

// AddSecret generates a UID, sets timestamps, inserts the secret, and returns the UID.
func (v *Vault) AddSecret(s Secret) (string, error) {
	for _, existing := range v.Secrets {
		if existing.Name != s.Name {
			continue
		}
		if existing.ProjectUID != s.ProjectUID {
			continue
		}
		if existing.EnvironmentUID != s.EnvironmentUID {
			continue
		}
		return "", fmt.Errorf("secret %q in scope (project=%q env=%q): %w", s.Name, s.ProjectUID, s.EnvironmentUID, ErrDuplicateName)
	}
	s.UID = generateUID()
	s.CreatedAt = time.Now()
	s.UpdatedAt = s.CreatedAt
	v.Secrets[s.UID] = s
	return s.UID, nil
}

// GetSecret returns the secret by UID.
func (v *Vault) GetSecret(uid string) (Secret, bool) {
	s, ok := v.Secrets[uid]
	return s, ok
}

// ListSecrets returns a defensive copy of all secrets.
func (v *Vault) ListSecrets() map[string]Secret {
	result := make(map[string]Secret, len(v.Secrets))
	for k, val := range v.Secrets {
		result[k] = val
	}
	return result
}

// ListSecretsByProject returns secrets filtered by ProjectUID.
func (v *Vault) ListSecretsByProject(projectUID string) map[string]Secret {
	result := make(map[string]Secret)
	for uid, s := range v.Secrets {
		if s.ProjectUID == projectUID {
			result[uid] = s
		}
	}
	return result
}

// ListSecretsByEnvironment returns secrets filtered by EnvironmentUID.
func (v *Vault) ListSecretsByEnvironment(envUID string) map[string]Secret {
	result := make(map[string]Secret)
	for uid, s := range v.Secrets {
		if s.EnvironmentUID == envUID {
			result[uid] = s
		}
	}
	return result
}

// ListSecretsByProjectAndEnvironment returns secrets scoped to a specific project and environment.
func (v *Vault) ListSecretsByProjectAndEnvironment(projectUID, envUID string) map[string]Secret {
	result := make(map[string]Secret)
	for uid, s := range v.Secrets {
		if s.ProjectUID == projectUID && s.EnvironmentUID == envUID {
			result[uid] = s
		}
	}
	return result
}

// FindSecretByName finds a secret by name, optionally filtered by project and/or environment.
// Returns (secret, uid, found).
func (v *Vault) FindSecretByName(name string, projectUID, envUID string) (Secret, string, bool) {
	for uid, s := range v.Secrets {
		if s.Name != name {
			continue
		}
		if s.ProjectUID != projectUID {
			continue
		}
		if s.EnvironmentUID != envUID {
			continue
		}
		return s, uid, true
	}
	return Secret{}, "", false
}

// SearchSecrets returns secrets whose Name, URL, or Notes contain the pattern (case-insensitive).
// An empty pattern returns all secrets.
func (v *Vault) SearchSecrets(pattern string) map[string]Secret {
	if pattern == "" {
		return v.ListSecrets()
	}
	lower := strings.ToLower(pattern)
	result := make(map[string]Secret)
	for uid, s := range v.Secrets {
		if strings.Contains(strings.ToLower(s.Name), lower) ||
			strings.Contains(strings.ToLower(s.URL), lower) ||
			strings.Contains(strings.ToLower(s.Notes), lower) {
			result[uid] = s
		}
	}
	return result
}

// UpdateSecret applies the updates function to the secret and sets UpdatedAt.
func (v *Vault) UpdateSecret(uid string, updates func(*Secret)) bool {
	s, ok := v.Secrets[uid]
	if !ok {
		return false
	}
	updates(&s)
	s.UpdatedAt = time.Now()
	v.Secrets[uid] = s
	return true
}

// RemoveSecret removes a secret by UID.
func (v *Vault) RemoveSecret(uid string) bool {
	if _, ok := v.Secrets[uid]; !ok {
		return false
	}
	delete(v.Secrets, uid)
	return true
}
