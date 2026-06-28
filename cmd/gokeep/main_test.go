package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/youruser/gokeep/internal/crypto"
	"github.com/youruser/gokeep/internal/session"
	"github.com/youruser/gokeep/internal/vault"
)

// mockReadPassword overrides readPasswordFn for tests that call rootCmd.Execute()
// on paths that hit getKey (which reads a password from the terminal).
func mockReadPassword(t *testing.T, password string, err error) {
	t.Helper()
	orig := readPasswordFn
	readPasswordFn = func() (string, error) { return password, err }
	t.Cleanup(func() { readPasswordFn = orig })
}

// stubSession overrides session.StorePassword/LoadPassword/Clear for tests
// that would otherwise touch the host OS keyring.
func stubSession(t *testing.T) {
	t.Helper()
	origStore, origLoad, origClear := session.StorePassword, session.LoadPassword, session.Clear
	session.StorePassword = func(string, string) error { return nil }
	session.LoadPassword = func() (string, error) { return "stub-password-1234", nil }
	session.Clear = func(string) error { return nil }
	t.Cleanup(func() {
		session.StorePassword, session.LoadPassword, session.Clear = origStore, origLoad, origClear
	})
}

// --- helper tests ---

func TestShortUID(t *testing.T) {
	tests := []struct {
		name     string
		uid      string
		expected string
	}{
		{"full uid", "abcdef1234567890abcdef1234567890", "abcdef12"},
		{"short uid", "abc", "abc"},
		{"empty", "", ""},
		{"exactly 8", "12345678", "12345678"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shortUID(tt.uid)
			if got != tt.expected {
				t.Errorf("shortUID(%q) = %q, want %q", tt.uid, got, tt.expected)
			}
		})
	}
}

func TestSortedProjectKeys(t *testing.T) {
	tests := []struct {
		name     string
		projects map[string]vault.Project
		wantLen  int
	}{
		{"empty", map[string]vault.Project{}, 0},
		{
			"single",
			map[string]vault.Project{"uid1": {Name: "foo"}},
			1,
		},
		{
			"multiple sorted",
			map[string]vault.Project{
				"uid1": {Name: "c"},
				"uid2": {Name: "a"},
				"uid3": {Name: "b"},
			},
			3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sortedKeysByName(tt.projects, func(p vault.Project) string { return p.Name })
			if len(got) != tt.wantLen {
				t.Errorf("len = %d, want %d", len(got), tt.wantLen)
			}
			// Verify sorted by name
			for i := 1; i < len(got); i++ {
				if tt.projects[got[i-1]].Name > tt.projects[got[i]].Name {
					t.Errorf("not sorted: %q > %q", tt.projects[got[i-1]].Name, tt.projects[got[i]].Name)
				}
			}
		})
	}
}

//nolint:dupl // same pattern for different types (project/env/secret)
func TestSortedEnvKeys(t *testing.T) {
	tests := []struct {
		name    string
		envs    map[string]vault.Environment
		wantLen int
	}{
		{"empty", map[string]vault.Environment{}, 0},
		{
			"multiple sorted",
			map[string]vault.Environment{
				"uid1": {Name: "prod"},
				"uid2": {Name: "dev"},
				"uid3": {Name: "staging"},
			},
			3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sortedKeysByName(tt.envs, func(e vault.Environment) string { return e.Name })
			if len(got) != tt.wantLen {
				t.Errorf("len = %d, want %d", len(got), tt.wantLen)
			}
			for i := 1; i < len(got); i++ {
				if tt.envs[got[i-1]].Name > tt.envs[got[i]].Name {
					t.Errorf("not sorted: %q > %q", tt.envs[got[i-1]].Name, tt.envs[got[i]].Name)
				}
			}
		})
	}
}

//nolint:dupl // same pattern for different types (project/env/secret)
func TestSortedSecretKeys(t *testing.T) {
	tests := []struct {
		name    string
		secrets map[string]vault.Secret
		wantLen int
	}{
		{"empty", map[string]vault.Secret{}, 0},
		{
			"multiple sorted",
			map[string]vault.Secret{
				"uid1": {Name: "api_key"},
				"uid2": {Name: "db_pass"},
				"uid3": {Name: "aws_key"},
			},
			3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sortedKeysByName(tt.secrets, func(s vault.Secret) string { return s.Name })
			if len(got) != tt.wantLen {
				t.Errorf("len = %d, want %d", len(got), tt.wantLen)
			}
			for i := 1; i < len(got); i++ {
				if tt.secrets[got[i-1]].Name > tt.secrets[got[i]].Name {
					t.Errorf("not sorted: %q > %q", tt.secrets[got[i-1]].Name, tt.secrets[got[i]].Name)
				}
			}
		})
	}
}

func TestFindProjectByName(t *testing.T) {
	v := &vault.Vault{
		Projects:     make(map[string]vault.Project),
		Environments: make(map[string]vault.Environment),
		Secrets:      make(map[string]vault.Secret),
	}
	if _, err := v.AddProject(vault.Project{Name: "myproject"}); err != nil {
		t.Fatalf("AddProject: %v", err)
	}
	if _, err := v.AddProject(vault.Project{Name: "other"}); err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	tests := []struct {
		name      string
		projName  string
		wantFound bool
	}{
		{"present", "myproject", true},
		{"absent", "nonexistent", false},
		{"case sensitive", "MyProject", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, _, found := findProjectByName(v, tt.projName)
			if found != tt.wantFound {
				t.Errorf("findProjectByName(%q) found=%v, want %v", tt.projName, found, tt.wantFound)
			}
			if found && p.Name != tt.projName {
				t.Errorf("expected name %q, got %q", tt.projName, p.Name)
			}
		})
	}
}

func TestFindEnvironmentByName(t *testing.T) {
	v := &vault.Vault{
		Projects:     make(map[string]vault.Project),
		Environments: make(map[string]vault.Environment),
		Secrets:      make(map[string]vault.Secret),
	}
	if _, err := v.AddProject(vault.Project{Name: "p1"}); err != nil {
		t.Fatalf("AddProject: %v", err)
	}
	if _, err := v.AddProject(vault.Project{Name: "p2"}); err != nil {
		t.Fatalf("AddProject: %v", err)
	}
	projUID1 := ""
	projUID2 := ""
	for uid, p := range v.ListProjects() {
		if p.Name == "p1" {
			projUID1 = uid
		} else {
			projUID2 = uid
		}
	}
	if _, err := v.AddEnvironment(vault.Environment{Name: "dev", ProjectUID: projUID1}); err != nil {
		t.Fatalf("AddEnvironment: %v", err)
	}
	if _, err := v.AddEnvironment(vault.Environment{Name: "prod", ProjectUID: projUID1}); err != nil {
		t.Fatalf("AddEnvironment: %v", err)
	}

	tests := []struct {
		name       string
		envName    string
		projectUID string
		wantFound  bool
	}{
		{"present in project", "dev", projUID1, true},
		{"present but different project", "dev", projUID2, false},
		{"absent", "staging", projUID1, false},
		{"scoping works", "prod", projUID1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, found := findEnvironmentByName(v, tt.envName, tt.projectUID)
			if found != tt.wantFound {
				t.Errorf("findEnvironmentByName(%q, %q) found=%v, want %v", tt.envName, tt.projectUID, found, tt.wantFound)
			}
		})
	}
}

func TestPromptLine(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"normal", "hello\n", "hello", false},
		{"trimmed", "  world  \n", "world", false},
		{"empty", "\n", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.input)
			var buf strings.Builder
			got, err := promptLine(&buf, r, "prompt: ")
			if (err != nil) != tt.wantErr {
				t.Errorf("promptLine() err=%v, wantErr=%v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("promptLine() = %q, want %q", got, tt.want)
			}
			if !strings.Contains(buf.String(), "prompt:") {
				t.Errorf("prompt not written to writer")
			}
		})
	}
}

func TestPromptLineEOF(t *testing.T) {
	r := strings.NewReader("")
	var buf strings.Builder
	_, err := promptLine(&buf, r, "prompt: ")
	if err == nil {
		t.Error("expected error on EOF")
	}
}

func TestConfirmDeletion(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"yes", "yes\n", true},
		{"y", "y\n", true},
		{"no", "no\n", false},
		{"reset", "RESET\n", false}, // only yes/y are accepted
		{"yes caps", "Yes\n", true},
		{"empty", "\n", false},
		{"garbage", "blah\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.in)
			var buf strings.Builder
			got, err := confirmDeletion(&buf, r, "test-secret")
			if err != nil {
				t.Errorf("confirmDeletion() unexpected err: %v", err)
			}
			if got != tt.want {
				t.Errorf("confirmDeletion(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestConfirmDeletionEOF(t *testing.T) {
	r := strings.NewReader("")
	var buf strings.Builder
	_, err := confirmDeletion(&buf, r, "test")
	if err == nil {
		t.Error("expected error on EOF")
	}
}

// --- cobra command tree tests ---

func TestRootCommandStructure(t *testing.T) {
	subs := rootCmd.Commands()
	names := make(map[string]bool)
	for _, c := range subs {
		names[c.Name()] = true
	}
	expected := []string{"init", "lock", "reset", "list", "project", "env", "secret", "status", "find"}
	for _, n := range expected {
		if !names[n] {
			t.Errorf("root missing subcommand: %s", n)
		}
	}
	if len(subs) != len(expected) {
		t.Errorf("root has %d subcommands, want %d", len(subs), len(expected))
	}
}

func TestProjectSubcommands(t *testing.T) {
	subs := projectCmd.Commands()
	names := make(map[string]bool)
	for _, c := range subs {
		names[c.Name()] = true
	}
	expected := []string{"add", "edit", "remove", "list", "show"}
	for _, n := range expected {
		if !names[n] {
			t.Errorf("project missing subcommand: %s", n)
		}
	}
	if len(subs) != len(expected) {
		t.Errorf("project has %d subcommands, want %d", len(subs), len(expected))
	}
}

func TestEnvSubcommands(t *testing.T) {
	subs := envCmd.Commands()
	names := make(map[string]bool)
	for _, c := range subs {
		names[c.Name()] = true
	}
	expected := []string{"add", "edit", "remove", "list", "show"}
	for _, n := range expected {
		if !names[n] {
			t.Errorf("env missing subcommand: %s", n)
		}
	}
	if len(subs) != len(expected) {
		t.Errorf("env has %d subcommands, want %d", len(subs), len(expected))
	}

	// Check that --project is a PersistentFlag on envCmd
	flag := envCmd.PersistentFlags().Lookup("project")
	if flag == nil {
		t.Error("envCmd missing persistent --project flag")
	}
}

func TestSecretSubcommands(t *testing.T) {
	subs := secretCmd.Commands()
	names := make(map[string]bool)
	for _, c := range subs {
		names[c.Name()] = true
	}
	expected := []string{"add", "edit", "remove", "list", "reveal", "show"}
	for _, n := range expected {
		if !names[n] {
			t.Errorf("secret missing subcommand: %s", n)
		}
	}
	if len(subs) != len(expected) {
		t.Errorf("secret has %d subcommands, want %d", len(subs), len(expected))
	}

	// Check that --project is a PersistentFlag on secretCmd
	flag := secretCmd.PersistentFlags().Lookup("project")
	if flag == nil {
		t.Error("secretCmd missing persistent --project flag")
	}
}

func TestSecretAddFlags(t *testing.T) {
	// --project is a persistent flag on the parent secretCmd
	if secretCmd.PersistentFlags().Lookup("project") == nil {
		t.Error("secret missing persistent --project flag")
	}
	// --env, --value, --url, --notes are local flags on secretAddCmd
	localFlags := []string{"env", "value", "url", "notes"}
	for _, name := range localFlags {
		if secretAddCmd.Flags().Lookup(name) == nil {
			t.Errorf("secret add missing flag: %s", name)
		}
	}
}

func TestEnvAddRequiresProject(t *testing.T) {
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	rootCmd.SetArgs([]string{"env", "add", "foo"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error running env add without --project")
	}
	if !strings.Contains(err.Error(), "project") {
		t.Errorf("error should mention 'project', got: %v", err)
	}
}

func TestSecretEnvRequiresProject(t *testing.T) {
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	rootCmd.SetArgs([]string{"secret", "list", "--env", "prod"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error running secret list --env without --project")
	}
	if !strings.Contains(err.Error(), "requires") {
		t.Errorf("error should mention 'requires', got: %v", err)
	}
}

func TestProjectAddRequiresName(t *testing.T) {
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	rootCmd.SetArgs([]string{"project", "add"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing name argument")
	}
}

func TestProjectRemoveRequiresName(t *testing.T) {
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	rootCmd.SetArgs([]string{"project", "remove"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing name argument")
	}
}

func TestEnvListAllowsNoArgs(t *testing.T) {
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	mockReadPassword(t, "test-password-1234", nil)
	rootCmd.SetArgs([]string{"env", "list"})
	err := rootCmd.Execute()
	if err == nil {
		t.Skip("vault exists in test environment — ok")
	}
	// Should not be an arg-count error
	if strings.Contains(err.Error(), "accepts") {
		t.Errorf("env list should not require args, got: %v", err)
	}
}

// --- init tests ---

func TestInitRejectsExistingVault(t *testing.T) {
	stubSession(t)
	warnOut = io.Discard
	t.Cleanup(func() { warnOut = os.Stderr })
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, vault.FileName)
	if err := os.WriteFile(vaultPath, []byte("fake"), 0600); err != nil {
		t.Fatalf("create fake vault: %v", err)
	}
	err := runInit(dir, "password1234", "password1234")
	if err == nil {
		t.Fatal("expected error for existing vault")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should say 'already exists', got: %v", err)
	}
}

func TestInitValidatesPasswordLength(t *testing.T) {
	stubSession(t)
	warnOut = io.Discard
	t.Cleanup(func() { warnOut = os.Stderr })
	dir := t.TempDir()
	tests := []struct {
		name     string
		password string
		confirm  string
		wantErr  bool
	}{
		{"too short", "short", "short", true},
		{"min length", "12345678", "12345678", false}, // 8 chars = OK
		{"too long", strings.Repeat("a", 1025), strings.Repeat("a", 1025), true},
		{"max length", strings.Repeat("a", 1024), strings.Repeat("a", 1024), false}, // 1024 = OK
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh dir for each test
			d := filepath.Join(dir, tt.name)
			if err := os.MkdirAll(d, 0700); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			err := runInit(d, tt.password, tt.confirm)
			if tt.wantErr && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestInitRejectsMismatchedConfirm(t *testing.T) {
	stubSession(t)
	warnOut = io.Discard
	t.Cleanup(func() { warnOut = os.Stderr })
	dir := t.TempDir()
	err := runInit(dir, "password1234", "different1234")
	if err == nil {
		t.Fatal("expected error for mismatched confirm")
	}
	if !strings.Contains(err.Error(), "do not match") {
		t.Errorf("error should say 'do not match', got: %v", err)
	}
}

func TestInitCreatesVault(t *testing.T) {
	stubSession(t)
	warnOut = io.Discard
	t.Cleanup(func() { warnOut = os.Stderr })
	dir := t.TempDir()
	if err := runInit(dir, "password1234", "password1234"); err != nil {
		t.Fatalf("runInit failed: %v", err)
	}

	vaultPath := filepath.Join(dir, vault.FileName)
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		t.Fatal("vault file was not created")
	}
}

func TestStatusSubcommand(t *testing.T) {
	found := false
	for _, c := range rootCmd.Commands() {
		if c.Name() == "status" {
			found = true
			break
		}
	}
	if !found {
		t.Error("status subcommand not registered with rootCmd")
	}
}

// setupTestVault creates a fresh vault in a temp dir, overrides vaultDir,
// and stubs session + password reading. Returns the temp dir.
func setupTestVault(t *testing.T) string {
	t.Helper()
	stubSession(t)
	mockReadPassword(t, "password1234", nil)
	origWarn := warnOut
	warnOut = io.Discard
	t.Cleanup(func() { warnOut = origWarn })
	dir := t.TempDir()
	origDir := vaultDir
	vaultDir = dir
	t.Cleanup(func() { vaultDir = origDir })
	if err := runInit(dir, "password1234", "password1234"); err != nil {
		t.Fatalf("runInit: %v", err)
	}
	return dir
}

func TestFindCmdRequiresPattern(t *testing.T) {
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	rootCmd.SetArgs([]string{"find"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing pattern argument")
	}
}

func TestFindCmdMatchesSecrets(t *testing.T) {
	dir := setupTestVault(t)
	// Add test data directly
	salt, err := vault.GetSalt(dir)
	if err != nil {
		t.Fatalf("GetSalt: %v", err)
	}
	key := crypto.DeriveKey("password1234", salt)
	v, err := vault.Open(dir, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	pUID, _ := v.AddProject(vault.Project{Name: "myapp"})
	eUID, _ := v.AddEnvironment(vault.Environment{Name: "prod", ProjectUID: pUID})
	v.AddSecret(vault.Secret{Name: "GitHub Token", ProjectUID: pUID, EnvironmentUID: eUID, Value: "x", URL: "https://github.com", Notes: "PAT"})
	v.AddSecret(vault.Secret{Name: "AWS Key", Value: "x", URL: "https://aws.amazon.com", Notes: "IAM"})
	v.AddSecret(vault.Secret{Name: "Database", Value: "x", Notes: "postgres connection"})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	tests := []struct {
		name    string
		args    []string
		want    string
		wantNot string
	}{
		{"match by name", []string{"find", "GitHub"}, "GitHub Token", ""},
		{"match by URL", []string{"find", "aws.amazon"}, "AWS Key", ""},
		{"match by notes", []string{"find", "postgres"}, "Database", ""},
		{"case insensitive", []string{"find", "github token"}, "GitHub Token", ""},
		{"no match", []string{"find", "nonexistent"}, "No secrets matching 'nonexistent'", ""},
		// Additional tests for project/env scoping
		{"match by project name", []string{"find", "GitHub", "--project", "myapp"}, "GitHub Token", "AWS Key"},
		{"match by project and env", []string{"find", "GitHub", "--project", "myapp", "--env", "prod"}, "GitHub Token", "AWS Key"},
		{"no match by wrong project", []string{"find", "GitHub", "--project", "nonexistent"}, "No secrets matching 'GitHub'", "GitHub Token"},
		{"no match by wrong env", []string{"find", "GitHub", "--project", "myapp", "--env", "nonexistent"}, "No secrets matching 'GitHub'", "GitHub Token"},
		{"env without project (expect error)", []string{"find", "any_pattern", "--env", "prod"}, "Error: --env requires --project", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			rootCmd.SetOut(&buf)
			rootCmd.SetErr(io.Discard)
			rootCmd.SetArgs(tt.args)
			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("find: %v", err)
			}
			output := buf.String()
			if tt.want != "" && !strings.Contains(output, tt.want) {
				t.Errorf("output should contain %q, got:\n%s", tt.want, output)
			}
			if tt.wantNot != "" && strings.Contains(output, tt.wantNot) {
				t.Errorf("output should NOT contain %q, got:\n%s", tt.wantNot, output)
			}
		})
	}
}

func TestSecretListFilter(t *testing.T) {
	// Reset flags that may persist from previous cobra Execute() calls.
	secretListCmd.Flags().Set("env", "")
	dir := setupTestVault(t)
	salt, err := vault.GetSalt(dir)
	if err != nil {
		t.Fatalf("GetSalt: %v", err)
	}
	key := crypto.DeriveKey("password1234", salt)
	v, err := vault.Open(dir, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	v.AddSecret(vault.Secret{Name: "GitHub Token", Value: "x", URL: "https://github.com", Notes: "PAT"})
	v.AddSecret(vault.Secret{Name: "AWS Key", Value: "x", URL: "https://aws.amazon.com", Notes: "IAM"})
	v.AddSecret(vault.Secret{Name: "Database", Value: "x", Notes: "postgres"})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	tests := []struct {
		name    string
		filter  string
		want    string
		wantNot string
	}{
		{"filter by name", "github", "GitHub Token", "AWS Key"},
		{"filter by URL", "aws", "AWS Key", "GitHub Token"},
		{"filter by notes", "postgres", "Database", "AWS Key"},
		{"no match", "nonexistent", "No secrets.", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			rootCmd.SetOut(&buf)
			rootCmd.SetErr(io.Discard)
			rootCmd.SetArgs([]string{"secret", "list", "--filter", tt.filter})
			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("secret list: %v", err)
			}
			output := buf.String()
			if tt.want != "" && !strings.Contains(output, tt.want) {
				t.Errorf("output should contain %q, got:\n%s", tt.want, output)
			}
			if tt.wantNot != "" && strings.Contains(output, tt.wantNot) {
				t.Errorf("output should NOT contain %q, got:\n%s", tt.wantNot, output)
			}
		})
	}
}
