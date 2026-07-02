package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/youruser/fortbyte/internal/crypto"
)

func testSalt(t *testing.T) []byte {
	t.Helper()
	salt, err := crypto.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	return salt
}

func testKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestVaultCRUDRoundtrip(t *testing.T) {
	dir := t.TempDir()
	key := testKey()

	if err := Init(dir, key, testSalt(t)); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	v, err := Open(dir, key)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Add project
	pUID, err := v.AddProject(Project{Name: "myapp", Description: "Test app"})
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	// Add environment scoped to project
	eUID, err := v.AddEnvironment(Environment{Name: "production", ProjectUID: pUID})
	if err != nil {
		t.Fatalf("AddEnvironment: %v", err)
	}

	// Add secret scoped to env
	sUID, err := v.AddSecret(Secret{Name: "db_url", ProjectUID: pUID, EnvironmentUID: eUID, Value: "postgres://localhost"})
	if err != nil {
		t.Fatalf("AddSecret: %v", err)
	}

	// Verify project
	p, ok := v.GetProject(pUID)
	if !ok {
		t.Fatal("GetProject: not found")
	}
	if p.Name != "myapp" {
		t.Errorf("expected project name %q, got %q", "myapp", p.Name)
	}

	// Verify environment
	e, ok := v.GetEnvironment(eUID)
	if !ok {
		t.Fatal("GetEnvironment: not found")
	}
	if e.Name != "production" {
		t.Errorf("expected env name %q, got %q", "production", e.Name)
	}
	if e.ProjectUID != pUID {
		t.Errorf("expected env ProjectUID %q, got %q", pUID, e.ProjectUID)
	}

	// Verify secret
	s, ok := v.GetSecret(sUID)
	if !ok {
		t.Fatal("GetSecret: not found")
	}
	if s.Value != "postgres://localhost" {
		t.Errorf("expected secret value %q, got %q", "postgres://localhost", s.Value)
	}

	// Persist
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Re-open and verify all persisted
	v2, err := Open(dir, key)
	if err != nil {
		t.Fatalf("Re-open failed: %v", err)
	}

	if _, ok := v2.GetProject(pUID); !ok {
		t.Error("project not persisted")
	}
	if _, ok := v2.GetEnvironment(eUID); !ok {
		t.Error("environment not persisted")
	}
	if _, ok := v2.GetSecret(sUID); !ok {
		t.Error("secret not persisted")
	}

	// Remove secret
	if !v2.RemoveSecret(sUID) {
		t.Error("RemoveSecret: expected true")
	}
	if _, ok := v2.GetSecret(sUID); ok {
		t.Error("secret still exists after RemoveSecret")
	}

	// Remove environment
	if !v2.RemoveEnvironment(eUID) {
		t.Error("RemoveEnvironment: expected true")
	}
	if _, ok := v2.GetEnvironment(eUID); ok {
		t.Error("environment still exists after RemoveEnvironment")
	}

	// Remove project
	if !v2.RemoveProject(pUID) {
		t.Error("RemoveProject: expected true")
	}
	if _, ok := v2.GetProject(pUID); ok {
		t.Error("project still exists after RemoveProject")
	}

	// Persist deletions
	if err := v2.Save(dir, key); err != nil {
		t.Fatalf("Save after removals failed: %v", err)
	}

	// Re-open and verify empty
	v3, err := Open(dir, key)
	if err != nil {
		t.Fatalf("Re-open after removals failed: %v", err)
	}
	if len(v3.Projects) != 0 {
		t.Errorf("expected 0 projects, got %d", len(v3.Projects))
	}
	if len(v3.Environments) != 0 {
		t.Errorf("expected 0 environments, got %d", len(v3.Environments))
	}
	if len(v3.Secrets) != 0 {
		t.Errorf("expected 0 secrets, got %d", len(v3.Secrets))
	}
}

func TestRemoveNonexistent(t *testing.T) {
	dir := t.TempDir()
	key := testKey()

	if err := Init(dir, key, testSalt(t)); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	v, err := Open(dir, key)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if v.RemoveProject("nonexistent") {
		t.Error("RemoveProject returned true for nonexistent UID")
	}
	if v.RemoveEnvironment("nonexistent") {
		t.Error("RemoveEnvironment returned true for nonexistent UID")
	}
	if v.RemoveSecret("nonexistent") {
		t.Error("RemoveSecret returned true for nonexistent UID")
	}
}

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	key := testKey()

	if err := Init(dir, key, testSalt(t)); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	v, err := Open(dir, key)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	pUID, err := v.AddProject(Project{Name: "test"})
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}
	eUID, err := v.AddEnvironment(Environment{Name: "dev", ProjectUID: pUID})
	if err != nil {
		t.Fatalf("AddEnvironment: %v", err)
	}
	if _, err := v.AddSecret(Secret{Name: "key", ProjectUID: pUID, EnvironmentUID: eUID, Value: "secret"}); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}

	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Temp file should not exist after save
	tmpPath := filepath.Join(dir, tmpFileName)
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("temp file should not exist after Save")
	}
}

func TestInitAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	key := testKey()

	if err := Init(dir, key, testSalt(t)); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err := Init(dir, key, testSalt(t))
	if err != ErrVaultExists {
		t.Errorf("expected ErrVaultExists, got %v", err)
	}
}

func TestOpenNotFound(t *testing.T) {
	dir := t.TempDir()
	key := testKey()

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

func TestRemoveProjectCascades(t *testing.T) {
	dir := t.TempDir()
	key := testKey()

	if err := Init(dir, key, testSalt(t)); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	v, err := Open(dir, key)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	pUID, err := v.AddProject(Project{Name: "p1"})
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}
	eUID, err := v.AddEnvironment(Environment{Name: "dev", ProjectUID: pUID})
	if err != nil {
		t.Fatalf("AddEnvironment: %v", err)
	}
	sUID, err := v.AddSecret(Secret{Name: "db", ProjectUID: pUID, EnvironmentUID: eUID, Value: "pass"})
	if err != nil {
		t.Fatalf("AddSecret: %v", err)
	}

	// Remove project
	if !v.RemoveProject(pUID) {
		t.Fatal("RemoveProject returned false")
	}

	// Verify cascade
	if _, ok := v.GetProject(pUID); ok {
		t.Error("project still exists")
	}
	if _, ok := v.GetEnvironment(eUID); ok {
		t.Error("environment still exists after project removed")
	}
	if _, ok := v.GetSecret(sUID); ok {
		t.Error("secret still exists after project removed")
	}
}

func TestRemoveEnvironmentCascades(t *testing.T) {
	dir := t.TempDir()
	key := testKey()

	if err := Init(dir, key, testSalt(t)); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	v, err := Open(dir, key)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	pUID, err := v.AddProject(Project{Name: "p1"})
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}
	eUID, err := v.AddEnvironment(Environment{Name: "dev", ProjectUID: pUID})
	if err != nil {
		t.Fatalf("AddEnvironment: %v", err)
	}
	sUID, err := v.AddSecret(Secret{Name: "db", ProjectUID: pUID, EnvironmentUID: eUID, Value: "pass"})
	if err != nil {
		t.Fatalf("AddSecret: %v", err)
	}

	// Remove environment
	if !v.RemoveEnvironment(eUID) {
		t.Fatal("RemoveEnvironment returned false")
	}

	// Verify cascade
	if _, ok := v.GetEnvironment(eUID); ok {
		t.Error("environment still exists")
	}
	if _, ok := v.GetSecret(sUID); ok {
		t.Error("secret still exists after environment removed")
	}
	// Project should still exist
	if _, ok := v.GetProject(pUID); !ok {
		t.Error("project should not have been removed")
	}
}

func TestListSecretsByProject(t *testing.T) {
	dir := t.TempDir()
	key := testKey()

	if err := Init(dir, key, testSalt(t)); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	v, err := Open(dir, key)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	p1UID, err := v.AddProject(Project{Name: "p1"})
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}
	p2UID, err := v.AddProject(Project{Name: "p2"})
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	if _, err := v.AddSecret(Secret{Name: "a", ProjectUID: p1UID, Value: "1"}); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}
	if _, err := v.AddSecret(Secret{Name: "b", ProjectUID: p1UID, Value: "2"}); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}
	if _, err := v.AddSecret(Secret{Name: "c", ProjectUID: p2UID, Value: "3"}); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}

	p1Secrets := v.ListSecretsByProject(p1UID)
	if len(p1Secrets) != 2 {
		t.Errorf("expected 2 secrets for p1, got %d", len(p1Secrets))
	}

	p2Secrets := v.ListSecretsByProject(p2UID)
	if len(p2Secrets) != 1 {
		t.Errorf("expected 1 secret for p2, got %d", len(p2Secrets))
	}

	// Empty project
	none := v.ListSecretsByProject("nonexistent")
	if len(none) != 0 {
		t.Errorf("expected 0 secrets for nonexistent project, got %d", len(none))
	}
}

func TestFindSecretByName(t *testing.T) {
	dir := t.TempDir()
	key := testKey()

	if err := Init(dir, key, testSalt(t)); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	v, err := Open(dir, key)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	pUID, err := v.AddProject(Project{Name: "p1"})
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}
	eUID, err := v.AddEnvironment(Environment{Name: "dev", ProjectUID: pUID})
	if err != nil {
		t.Fatalf("AddEnvironment: %v", err)
	}

	// Standalone secret (no project, no env)
	if _, err := v.AddSecret(Secret{Name: "standalone", Value: "s"}); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}

	// Project-scoped secret
	if _, err := v.AddSecret(Secret{Name: "scoped", ProjectUID: pUID, Value: "p"}); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}

	// Environment-scoped secret
	if _, err := v.AddSecret(Secret{Name: "scoped", ProjectUID: pUID, EnvironmentUID: eUID, Value: "e"}); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}

	// Find standalone
	_, _, found := v.FindSecretByName("standalone", "", "")
	if !found {
		t.Error("expected to find standalone secret")
	}

	// Find project-scoped
	_, _, found = v.FindSecretByName("scoped", pUID, "")
	if !found {
		t.Error("expected to find project-scoped secret")
	}

	// Find env-scoped
	_, _, found = v.FindSecretByName("scoped", pUID, eUID)
	if !found {
		t.Error("expected to find env-scoped secret")
	}

	// Wrong project
	_, _, found = v.FindSecretByName("scoped", "bad", "")
	if found {
		t.Error("should not find secret with wrong project filter")
	}

	// Wrong env
	_, _, found = v.FindSecretByName("scoped", pUID, "bad")
	if found {
		t.Error("should not find secret with wrong env filter")
	}

	// Nonexistent name
	_, _, found = v.FindSecretByName("nonexistent", "", "")
	if found {
		t.Error("should not find nonexistent secret")
	}
}

func TestStandaloneSecret(t *testing.T) {
	dir := t.TempDir()
	key := testKey()

	if err := Init(dir, key, testSalt(t)); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	v, err := Open(dir, key)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	sUID, err := v.AddSecret(Secret{Name: "api_key", Value: "abc123"})
	if err != nil {
		t.Fatalf("AddSecret: %v", err)
	}

	// Verify in memory
	s, ok := v.GetSecret(sUID)
	if !ok {
		t.Fatal("GetSecret: not found")
	}
	if s.Name != "api_key" || s.Value != "abc123" {
		t.Errorf("unexpected secret: %+v", s)
	}
	if s.ProjectUID != "" || s.EnvironmentUID != "" {
		t.Error("standalone secret should have empty project/env UIDs")
	}

	// Persist and re-open
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	v2, err := Open(dir, key)
	if err != nil {
		t.Fatalf("Re-open failed: %v", err)
	}

	s2, ok := v2.GetSecret(sUID)
	if !ok {
		t.Fatal("standalone secret not persisted")
	}
	if s2.Value != "abc123" {
		t.Errorf("expected value %q, got %q", "abc123", s2.Value)
	}

	// FindSecretByName should find it
	_, _, found := v2.FindSecretByName("api_key", "", "")
	if !found {
		t.Error("FindSecretByName did not find standalone secret")
	}
}

func TestAddProjectDuplicate(t *testing.T) {
	v := &Vault{Projects: map[string]Project{}}
	_, err := v.AddProject(Project{Name: "web"})
	if err != nil {
		t.Fatalf("first AddProject: %v", err)
	}
	_, err = v.AddProject(Project{Name: "web"})
	if !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("second AddProject err = %v, want ErrDuplicateName", err)
	}
}

func TestAddEnvironmentDuplicate(t *testing.T) {
	v := &Vault{Environments: map[string]Environment{}}
	_, err := v.AddEnvironment(Environment{Name: "prod", ProjectUID: "p1"})
	if err != nil {
		t.Fatalf("first AddEnvironment: %v", err)
	}
	_, err = v.AddEnvironment(Environment{Name: "prod", ProjectUID: "p1"})
	if !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("second AddEnvironment in same project: err = %v, want ErrDuplicateName", err)
	}
	// Same name in a different project must succeed
	_, err = v.AddEnvironment(Environment{Name: "prod", ProjectUID: "p2"})
	if err != nil {
		t.Fatalf("AddEnvironment same name in different project: %v", err)
	}
}

func TestAddSecretDuplicate(t *testing.T) {
	v := &Vault{Secrets: map[string]Secret{}}
	_, err := v.AddSecret(Secret{Name: "api", ProjectUID: "p1", EnvironmentUID: "e1"})
	if err != nil {
		t.Fatalf("first AddSecret: %v", err)
	}
	_, err = v.AddSecret(Secret{Name: "api", ProjectUID: "p1", EnvironmentUID: "e1"})
	if !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("second AddSecret in same scope: err = %v, want ErrDuplicateName", err)
	}
}

func TestAddSecretNoCollisionDifferentScope(t *testing.T) {
	v := &Vault{Secrets: map[string]Secret{}}
	// Same name, project-scoped only
	if _, err := v.AddSecret(Secret{Name: "scoped", ProjectUID: "p1", EnvironmentUID: ""}); err != nil {
		t.Fatalf("first: %v", err)
	}
	// Same name, project + env-scoped
	if _, err := v.AddSecret(Secret{Name: "scoped", ProjectUID: "p1", EnvironmentUID: "e1"}); err != nil {
		t.Fatalf("different scope must succeed: %v", err)
	}
	// Same name, different project
	if _, err := v.AddSecret(Secret{Name: "scoped", ProjectUID: "p2", EnvironmentUID: "e1"}); err != nil {
		t.Fatalf("different project must succeed: %v", err)
	}
}

func TestSearchSecrets(t *testing.T) {
	v := &Vault{
		Projects:     make(map[string]Project),
		Environments: make(map[string]Environment),
		Secrets:      make(map[string]Secret),
	}
	v.Secrets["uid1"] = Secret{Name: "GitHub Token", URL: "https://github.com", Notes: "personal access token"}
	v.Secrets["uid2"] = Secret{Name: "AWS Key", URL: "https://aws.amazon.com", Notes: "IAM user key"}
	v.Secrets["uid3"] = Secret{Name: "Database", URL: "", Notes: "postgres connection"}
	v.Secrets["uid4"] = Secret{Name: "token fallback", URL: "", Notes: ""}

	tests := []struct {
		name    string
		pattern string
		want    int
	}{
		{"empty pattern returns all", "", 4},
		{"exact name match", "GitHub Token", 1},
		{"partial name match lowercase", "token", 2}, // GitHub Token + token fallback
		{"url match", "aws.amazon.com", 1},
		{"notes match", "postgres", 1},
		{"case insensitive name", "github token", 1},
		{"case insensitive url", "AWS.AMAZON.COM", 1},
		{"case insensitive notes", "POSTGRES", 1},
		{"no match", "nonexistent", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := v.SearchSecrets(tt.pattern)
			if len(results) != tt.want {
				t.Errorf("SearchSecrets(%q) returned %d results, want %d", tt.pattern, len(results), tt.want)
			}
		})
	}
}

func TestAddRemoveReAdd(t *testing.T) {
	v := &Vault{Projects: map[string]Project{}}
	uid1, err := v.AddProject(Project{Name: "web"})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !v.RemoveProject(uid1) {
		t.Fatalf("RemoveProject")
	}
	uid2, err := v.AddProject(Project{Name: "web"})
	if err != nil {
		t.Fatalf("re-Add: %v", err)
	}
	if uid1 == uid2 {
		t.Errorf("expected fresh UID, got same: %s", uid1)
	}
}
