package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/youruser/fortbyte/internal/crypto"
	"github.com/youruser/fortbyte/internal/session"
	"github.com/youruser/fortbyte/internal/vault"
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
	expected := []string{"init", "lock", "reset", "list", "project", "env", "secret", "status", "find", "export", "import"}
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
	expected := []string{"add", "edit", "remove", "list", "reveal", "show", "move", "copy"}
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

// --- secret move/copy tests ---

// resetMoveCopyFlags resets cobra flag state for secret move/copy commands
// and the parent secretCmd persistent flags. pflag.Set() marks Changed=true
// permanently; this resets both the value and Changed so required flag checks
// and scoped lookups work correctly across table-driven subtests.
func resetMoveCopyFlags(t *testing.T) {
	t.Helper()
	resetFlag(t, secretCmd.PersistentFlags(), "project")
	for _, name := range []string{"dest-project", "dest-env", "env"} {
		resetFlag(t, secretMoveCmd.Flags(), name)
	}
	for _, name := range []string{"dest-project", "dest-env", "env", "name"} {
		resetFlag(t, secretCopyCmd.Flags(), name)
	}
}

func resetFlag(t *testing.T, fs *pflag.FlagSet, name string) {
	t.Helper()
	f := fs.Lookup(name)
	if f == nil {
		return
	}
	_ = f.Value.Set("")
	f.Changed = false
}

func TestSecretMoveFlags(t *testing.T) {
	if secretMoveCmd.Flags().Lookup("dest-project") == nil {
		t.Error("secret move missing --dest-project flag")
	}
	if secretMoveCmd.Flags().Lookup("dest-env") == nil {
		t.Error("secret move missing --dest-env flag")
	}
	if secretMoveCmd.Flags().Lookup("env") == nil {
		t.Error("secret move missing --env flag")
	}
	if secretMoveCmd.Flags().Lookup("dest-project").Annotations[cobra.BashCompOneRequiredFlag] == nil {
		t.Error("--dest-project should be required")
	}
}

func TestSecretCopyFlags(t *testing.T) {
	if secretCopyCmd.Flags().Lookup("dest-project") == nil {
		t.Error("secret copy missing --dest-project flag")
	}
	if secretCopyCmd.Flags().Lookup("dest-env") == nil {
		t.Error("secret copy missing --dest-env flag")
	}
	if secretCopyCmd.Flags().Lookup("env") == nil {
		t.Error("secret copy missing --env flag")
	}
	if secretCopyCmd.Flags().Lookup("name") == nil {
		t.Error("secret copy missing --name flag")
	}
	if secretCopyCmd.Flags().Lookup("dest-project").Annotations[cobra.BashCompOneRequiredFlag] == nil {
		t.Error("--dest-project should be required")
	}
}

func TestSecretMove(t *testing.T) {
	resetCmdFlags(t)
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
	pSrcUID, _ := v.AddProject(vault.Project{Name: "src"})
	pDstUID, _ := v.AddProject(vault.Project{Name: "dst"})
	v.AddSecret(vault.Secret{Name: "MY_SECRET", Value: "s3cret", ProjectUID: pSrcUID, URL: "https://example.com", Notes: "test"})
	v.AddSecret(vault.Secret{Name: "DUP_SECRET", Value: "dup", ProjectUID: pSrcUID})
	v.AddSecret(vault.Secret{Name: "DUP_SECRET", Value: "dup", ProjectUID: pDstUID})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}
	vaultFile := filepath.Join(dir, vault.FileName)
	origVaultBytes, err := os.ReadFile(vaultFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		resetMoveCopyFlags(t)
	})

	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr string
	}{
		{
			"dest project required",
			[]string{"secret", "move", "DUP_SECRET", "--project", "dst"},
			"",
			"required flag(s) \"dest-project\" not set",
		},
		{
			"dest duplicate",
			[]string{"secret", "move", "DUP_SECRET", "--project", "dst", "--dest-project", "src"},
			"",
			"secret 'DUP_SECRET' already exists at destination",
		},
		{
			"move to different project",
			[]string{"secret", "move", "MY_SECRET", "--project", "src", "--dest-project", "dst"},
			"Secret 'MY_SECRET' moved to project 'dst'",
			"",
		},
		{
			"source not found",
			[]string{"secret", "move", "NONEXISTENT", "--project", "src", "--dest-project", "dst"},
			"",
			"secret 'NONEXISTENT' not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Restore vault to pristine state and reset leaked flags.
			if err := os.WriteFile(vaultFile, origVaultBytes, 0600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			resetMoveCopyFlags(t)

			var buf bytes.Buffer
			rootCmd.SetOut(&buf)
			rootCmd.SetErr(io.Discard)
			rootCmd.SetArgs(tt.args)
			err := rootCmd.Execute()
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error should contain %q, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("execute: %v", err)
			}
			output := buf.String()
			if !strings.Contains(output, tt.want) {
				t.Errorf("output should contain %q, got:\n%s", tt.want, output)
			}
		})
	}
}

func TestSecretCopy(t *testing.T) {
	resetCmdFlags(t)
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
	pSrcUID, _ := v.AddProject(vault.Project{Name: "src"})
	_, _ = v.AddProject(vault.Project{Name: "dst"})
	v.AddSecret(vault.Secret{Name: "MY_SECRET", Value: "s3cret", ProjectUID: pSrcUID, URL: "https://example.com", Notes: "test"})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}
	vaultFile := filepath.Join(dir, vault.FileName)
	origVaultBytes, err := os.ReadFile(vaultFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		resetMoveCopyFlags(t)
	})

	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr string
	}{
		{
			"dest project required",
			[]string{"secret", "copy", "MY_SECRET"},
			"",
			"required flag(s) \"dest-project\" not set",
		},
		{
			"dest duplicate",
			[]string{"secret", "copy", "MY_SECRET", "--project", "src", "--dest-project", "src"},
			"",
			"secret 'MY_SECRET' already exists at destination",
		},
		{
			"copy to different project",
			[]string{"secret", "copy", "MY_SECRET", "--project", "src", "--dest-project", "dst"},
			"Secret 'MY_SECRET' copied as 'MY_SECRET' to project 'dst'",
			"",
		},
		{
			"copy with rename",
			[]string{"secret", "copy", "MY_SECRET", "--project", "src", "--dest-project", "dst", "--name", "RENAMED"},
			"Secret 'MY_SECRET' copied as 'RENAMED' to project 'dst'",
			"",
		},
		{
			"source not found",
			[]string{"secret", "copy", "NONEXISTENT", "--project", "src", "--dest-project", "dst"},
			"",
			"secret 'NONEXISTENT' not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Restore vault to pristine state and reset leaked flags.
			if err := os.WriteFile(vaultFile, origVaultBytes, 0600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			resetMoveCopyFlags(t)

			var buf bytes.Buffer
			rootCmd.SetOut(&buf)
			rootCmd.SetErr(io.Discard)
			rootCmd.SetArgs(tt.args)
			err := rootCmd.Execute()
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error should contain %q, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("execute: %v", err)
			}
			output := buf.String()
			if !strings.Contains(output, tt.want) {
				t.Errorf("output should contain %q, got:\n%s", tt.want, output)
			}
		})
	}
}

func TestSecretMoveWithEnv(t *testing.T) {
	resetCmdFlags(t)
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
	pUID, _ := v.AddProject(vault.Project{Name: "myapp"})
	devUID, _ := v.AddEnvironment(vault.Environment{Name: "dev", ProjectUID: pUID})
	_, _ = v.AddEnvironment(vault.Environment{Name: "prod", ProjectUID: pUID})
	v.AddSecret(vault.Secret{Name: "MY_SECRET", Value: "s3cret", ProjectUID: pUID, EnvironmentUID: devUID})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		resetMoveCopyFlags(t)
	})

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"secret", "move", "MY_SECRET", "--project", "myapp", "--env", "dev", "--dest-project", "myapp", "--dest-env", "prod"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "moved to project 'myapp' (env: 'prod')") {
		t.Errorf("expected env context in output, got:\n%s", output)
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
	resetCmdFlags(t)
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
		wantErr string // if non-empty, expect error containing this string
	}{
		{"match by name", []string{"find", "GitHub"}, "GitHub Token", "", ""},
		{"match by URL", []string{"find", "aws.amazon"}, "AWS Key", "", ""},
		{"match by notes", []string{"find", "postgres"}, "Database", "", ""},
		{"case insensitive", []string{"find", "github token"}, "GitHub Token", "", ""},
		{"no match", []string{"find", "nonexistent"}, "No secrets matching 'nonexistent'", "", ""},
		// Additional tests for project/env scoping
		{"match by project name", []string{"find", "GitHub", "--project", "myapp"}, "GitHub Token", "AWS Key", ""},
		{"match by project and env", []string{"find", "GitHub", "--project", "myapp", "--env", "prod"}, "GitHub Token", "AWS Key", ""},
		{"no match by wrong project", []string{"find", "GitHub", "--project", "nonexistent"}, "", "", "project 'nonexistent' not found"},
		{"no match by wrong env", []string{"find", "GitHub", "--project", "myapp", "--env", "nonexistent"}, "", "", "environment 'nonexistent' not found"},
		{"env without project (expect error)", []string{"find", "any_pattern", "--env", "prod"}, "", "", "--env requires --project"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetExportImportFlags()
			var buf bytes.Buffer
			rootCmd.SetOut(&buf)
			rootCmd.SetErr(io.Discard)
			rootCmd.SetArgs(tt.args)
			err := rootCmd.Execute()
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error should contain %q, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
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

// --- export/import tests ---

// seedVault adds test data to the vault and saves it.
func seedVault(t *testing.T, dir string) {
	t.Helper()
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
	v.AddSecret(vault.Secret{Name: "DB_PASS", Value: "s3cret", ProjectUID: pUID, EnvironmentUID: eUID, URL: "https://db.example.com", Notes: "database"})
	v.AddSecret(vault.Secret{Name: "API_KEY", Value: "key123", ProjectUID: pUID, EnvironmentUID: eUID})
	v.AddSecret(vault.Secret{Name: "STANDALONE", Value: "solo"})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}
}

// resetCmdFlags resets cobra flag values that leak between Execute() calls.
// pflag doesn't reset unset flags between parses, so we must do it explicitly.
func resetCmdFlags(t *testing.T) {
	t.Helper()
	resetExportImportFlags()
	t.Cleanup(resetExportImportFlags)
}

func resetExportImportFlags() {
	rootCmd.SetArgs(nil)
	// Reset secretCmd persistent flags (project leaks between subcommands)
	_ = secretCmd.PersistentFlags().Set("project", "")
	for _, name := range []string{"project", "env", "format"} {
		_ = exportCmd.Flags().Set(name, "")
		_ = importCmd.Flags().Set(name, "")
	}
	for _, name := range []string{"project", "env", "format"} {
		_ = findCmd.Flags().Set(name, "")
	}
	for _, name := range []string{"env", "format"} {
		_ = secretRevealCmd.Flags().Set(name, "")
		_ = secretShowCmd.Flags().Set(name, "")
	}
	for _, name := range []string{"env", "format", "filter"} {
		_ = secretListCmd.Flags().Set(name, "")
	}
	// Reset listCmd flags (project/env/format leak between tests)
	for _, name := range []string{"project", "env", "format"} {
		_ = listCmd.Flags().Set(name, "")
	}
	// Reset envCmd persistent flags (project leaks between tests)
	_ = envCmd.PersistentFlags().Set("project", "")
}

func TestExportJSON(t *testing.T) {
	resetCmdFlags(t)
	dir := setupTestVault(t)
	seedVault(t, dir)

	outFile := filepath.Join(t.TempDir(), "export.json")
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"export", outFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("export: %v", err)
	}
	if !strings.Contains(buf.String(), "Exported 3 secrets") {
		t.Errorf("expected 3 secrets exported, got: %s", buf.String())
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var entries []exportEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	for _, e := range entries {
		switch e.Name {
		case "DB_PASS":
			if e.Value != "s3cret" {
				t.Errorf("DB_PASS value = %q, want %q", e.Value, "s3cret")
			}
			if e.Project != "myapp" {
				t.Errorf("DB_PASS project = %q, want %q", e.Project, "myapp")
			}
			if e.URL != "https://db.example.com" {
				t.Errorf("DB_PASS URL = %q", e.URL)
			}
		case "API_KEY", "STANDALONE":
			// ok
		default:
			t.Errorf("unexpected entry: %s", e.Name)
		}
	}
}

func TestExportJSONScoped(t *testing.T) {
	resetCmdFlags(t)
	dir := setupTestVault(t)
	seedVault(t, dir)

	outFile := filepath.Join(t.TempDir(), "scoped.json")
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"export", outFile, "--project", "myapp"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("export: %v", err)
	}
	if !strings.Contains(buf.String(), "Exported 2 secrets") {
		t.Errorf("expected 2 secrets, got: %s", buf.String())
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var entries []exportEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Project != "myapp" {
			t.Errorf("entry %q has project %q, want %q", e.Name, e.Project, "myapp")
		}
	}
}

func TestExportEnv(t *testing.T) {
	resetCmdFlags(t)
	dir := setupTestVault(t)
	seedVault(t, dir)

	outFile := filepath.Join(t.TempDir(), "export.env")
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"export", outFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("export: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "DB_PASS=s3cret") {
		t.Errorf("missing DB_PASS=s3cret in .env output:\n%s", content)
	}
	if !strings.Contains(content, "API_KEY=key123") {
		t.Errorf("missing API_KEY=key123 in .env output:\n%s", content)
	}
	if !strings.Contains(content, "# Project: myapp | Env: prod") {
		t.Errorf("missing scope comment in .env output:\n%s", content)
	}
}

func TestExportAutoDetect(t *testing.T) {
	resetCmdFlags(t)
	dir := setupTestVault(t)
	seedVault(t, dir)

	outJSON := filepath.Join(t.TempDir(), "auto.json")
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"export", outJSON})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("export json: %v", err)
	}
	data, _ := os.ReadFile(outJSON)
	var entries []exportEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Errorf("expected JSON output, got parse error: %v", err)
	}

	outEnv := filepath.Join(t.TempDir(), "auto.env")
	buf.Reset()
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"export", outEnv})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("export env: %v", err)
	}
	envData, _ := os.ReadFile(outEnv)
	if !strings.Contains(string(envData), "=") {
		t.Errorf("expected .env output with KEY=value, got:\n%s", envData)
	}
}

func TestExportUnknownFormat(t *testing.T) {
	resetCmdFlags(t)
	dir := setupTestVault(t)
	seedVault(t, dir)

	outFile := filepath.Join(t.TempDir(), "export.txt")
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"export", outFile})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for .txt extension")
	}
	if !strings.Contains(err.Error(), "cannot detect format") {
		t.Errorf("error should mention 'cannot detect format', got: %v", err)
	}
}

func TestExportEnvRequiresProject(t *testing.T) {
	resetCmdFlags(t)
	dir := setupTestVault(t)
	seedVault(t, dir)

	outFile := filepath.Join(t.TempDir(), "export.env")
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"export", outFile, "--env", "prod"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for --env without --project")
	}
	if !strings.Contains(err.Error(), "--env requires --project") {
		t.Errorf("error should mention '--env requires --project', got: %v", err)
	}
}

func TestImportJSON(t *testing.T) {
	resetCmdFlags(t)
	dir := setupTestVault(t)

	importData := `[{"name":"NEW_SECRET","project":"myapp","env":"prod","value":"imported","url":"https://example.com","notes":"from json"}]`
	importFile := filepath.Join(t.TempDir(), "import.json")
	if err := os.WriteFile(importFile, []byte(importData), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"import", importFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("import: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "Added:   1 secrets") {
		t.Errorf("expected 1 added secret, got:\n%s", output)
	}

	salt, _ := vault.GetSalt(dir)
	key := crypto.DeriveKey("password1234", salt)
	v, _ := vault.Open(dir, key)
	p, _, pf := findProjectByName(v, "myapp")
	if !pf {
		t.Fatal("project 'myapp' not found after import")
	}
	e, _, ef := findEnvironmentByName(v, "prod", p.UID)
	if !ef {
		t.Fatal("environment 'prod' not found after import")
	}
	_, _, found := v.FindSecretByName("NEW_SECRET", p.UID, e.UID)
	if !found {
		t.Error("NEW_SECRET not found after import")
	}
}

func TestImportJSONCreatesProjectEnv(t *testing.T) {
	resetCmdFlags(t)
	dir := setupTestVault(t)

	importData := `[{"name":"CREATED_SECRET","project":"brand-new","env":"staging","value":"test123"}]`
	importFile := filepath.Join(t.TempDir(), "create.json")
	if err := os.WriteFile(importFile, []byte(importData), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"import", importFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("import: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "Added:   1 secrets") {
		t.Errorf("expected 1 added, got:\n%s", output)
	}

	salt, _ := vault.GetSalt(dir)
	key := crypto.DeriveKey("password1234", salt)
	v, _ := vault.Open(dir, key)
	p, _, found := findProjectByName(v, "brand-new")
	if !found {
		t.Fatal("project 'brand-new' not created")
	}
	_, _, found = findEnvironmentByName(v, "staging", p.UID)
	if !found {
		t.Fatal("environment 'staging' not created in project 'brand-new'")
	}
}

func TestImportEnv(t *testing.T) {
	resetCmdFlags(t)
	dir := setupTestVault(t)
	salt, _ := vault.GetSalt(dir)
	key := crypto.DeriveKey("password1234", salt)
	v, _ := vault.Open(dir, key)
	pUID, _ := v.AddProject(vault.Project{Name: "myapp"})
	v.AddEnvironment(vault.Environment{Name: "dev", ProjectUID: pUID})
	v.Save(dir, key)

	importFile := filepath.Join(t.TempDir(), "import.env")
	if err := os.WriteFile(importFile, []byte("NEW_VAR=hello\nOTHER_VAR=world\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"import", importFile, "--project", "myapp", "--env", "dev"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("import: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "Added:   2 secrets") {
		t.Errorf("expected 2 added, got:\n%s", output)
	}
}

func TestImportEnvRequiresProject(t *testing.T) {
	resetCmdFlags(t)
	importFile := filepath.Join(t.TempDir(), "import.env")
	if err := os.WriteFile(importFile, []byte("KEY=val\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"import", importFile})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for .env import without --project")
	}
	if !strings.Contains(err.Error(), "--project is required") {
		t.Errorf("error should mention '--project is required', got: %v", err)
	}
}

func TestImportSkipsDuplicates(t *testing.T) {
	resetCmdFlags(t)
	dir := setupTestVault(t)
	seedVault(t, dir)

	importData := `[{"name":"DB_PASS","value":"new_value","project":"myapp","env":"prod"}]`
	importFile := filepath.Join(t.TempDir(), "dup.json")
	if err := os.WriteFile(importFile, []byte(importData), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"import", importFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("import: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "Added:   0 secrets") {
		t.Errorf("expected 0 added, got:\n%s", output)
	}
	if !strings.Contains(output, "Skipped: 1 secrets") {
		t.Errorf("expected 1 skipped, got:\n%s", output)
	}
	if !strings.Contains(output, "DB_PASS") {
		t.Errorf("skipped list should mention DB_PASS, got:\n%s", output)
	}
}

func TestImportSummaryOutput(t *testing.T) {
	resetCmdFlags(t)
	setupTestVault(t)

	importData := `[{"name":"A","value":"1","project":"p1"},{"name":"B","value":"2","project":"p1"}]`
	importFile := filepath.Join(t.TempDir(), "summary.json")
	if err := os.WriteFile(importFile, []byte(importData), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"import", importFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("import: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "Import complete:") {
		t.Errorf("missing header:\n%s", output)
	}
	if !strings.Contains(output, "Added:   2 secrets") {
		t.Errorf("expected 2 added, got:\n%s", output)
	}

	// Re-import — should skip both
	buf.Reset()
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"import", importFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("import (re-import): %v", err)
	}
	output = buf.String()
	if !strings.Contains(output, "Added:   0 secrets") {
		t.Errorf("re-import: expected 0 added, got:\n%s", output)
	}
	if !strings.Contains(output, "Skipped: 2 secrets") {
		t.Errorf("re-import: expected 2 skipped, got:\n%s", output)
	}
}

func TestImportEnvParsesComments(t *testing.T) {
	resetCmdFlags(t)
	dir := setupTestVault(t)
	salt, _ := vault.GetSalt(dir)
	key := crypto.DeriveKey("password1234", salt)
	v, _ := vault.Open(dir, key)
	pUID, _ := v.AddProject(vault.Project{Name: "myapp"})
	v.Save(dir, key)

	envContent := "# This is a comment\nREAL_VALUE=hello\n# Another comment\n\n\nANOTHER=world\n"
	importFile := filepath.Join(t.TempDir(), "comments.env")
	if err := os.WriteFile(importFile, []byte(envContent), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"import", importFile, "--project", "myapp"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("import: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "Added:   2 secrets") {
		t.Errorf("expected 2 added (comments/blanks skipped), got:\n%s", output)
	}

	v2, _ := vault.Open(dir, key)
	_, _, f1 := v2.FindSecretByName("REAL_VALUE", pUID, "")
	_, _, f2 := v2.FindSecretByName("ANOTHER", pUID, "")
	if !f1 || !f2 {
		t.Error("secrets not found after import with comments")
	}
}

func TestImportEnvParsesQuotes(t *testing.T) {
	resetCmdFlags(t)
	dir := setupTestVault(t)
	salt, _ := vault.GetSalt(dir)
	key := crypto.DeriveKey("password1234", salt)
	v, _ := vault.Open(dir, key)
	pUID, _ := v.AddProject(vault.Project{Name: "myapp"})
	v.Save(dir, key)

	envContent := "DB_HOST=\"localhost\"\nDB_PORT='5432'\nDB_CONN=\"host=localhost port=5432\"\n"
	importFile := filepath.Join(t.TempDir(), "quoted.env")
	if err := os.WriteFile(importFile, []byte(envContent), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"import", importFile, "--project", "myapp"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("import: %v", err)
	}

	v2, _ := vault.Open(dir, key)
	s1, _, f1 := v2.FindSecretByName("DB_HOST", pUID, "")
	s2, _, f2 := v2.FindSecretByName("DB_PORT", pUID, "")
	s3, _, f3 := v2.FindSecretByName("DB_CONN", pUID, "")
	if !f1 || !f2 || !f3 {
		t.Fatal("secrets not found after quoted import")
	}
	if s1.Value != "localhost" {
		t.Errorf("DB_HOST value = %q, want %q", s1.Value, "localhost")
	}
	if s2.Value != "5432" {
		t.Errorf("DB_PORT value = %q, want %q", s2.Value, "5432")
	}
	if s3.Value != "host=localhost port=5432" {
		t.Errorf("DB_CONN value = %q, want %q", s3.Value, "host=localhost port=5432")
	}
}

func TestExportImportRoundtrip(t *testing.T) {
	resetCmdFlags(t)
	dir := setupTestVault(t)
	seedVault(t, dir)

	// Export to JSON
	outFile := filepath.Join(t.TempDir(), "roundtrip.json")
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"export", outFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("export: %v", err)
	}

	// Create a fresh vault with the same project name
	dir2 := setupTestVault(t)
	salt2, _ := vault.GetSalt(dir2)
	key2 := crypto.DeriveKey("password1234", salt2)
	v2, _ := vault.Open(dir2, key2)
	v2.AddProject(vault.Project{Name: "myapp"})
	v2.Save(dir2, key2)

	// Import into fresh vault
	buf.Reset()
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"import", outFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("import: %v", err)
	}
	if !strings.Contains(buf.String(), "Added:   3 secrets") {
		t.Errorf("roundtrip: expected 3 added, got:\n%s", buf.String())
	}

	v3, _ := vault.Open(dir2, key2)
	secrets := v3.ListSecrets()
	if len(secrets) != 3 {
		t.Errorf("expected 3 secrets after roundtrip, got %d", len(secrets))
	}
	names := make(map[string]bool)
	for _, s := range secrets {
		names[s.Name] = true
	}
	for _, name := range []string{"DB_PASS", "API_KEY", "STANDALONE"} {
		if !names[name] {
			t.Errorf("secret %q not found after roundtrip", name)
		}
	}
}

// --- JSON output tests ---

func TestSecretRevealJSON(t *testing.T) {
	resetCmdFlags(t)
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
	pUID, _ := v.AddProject(vault.Project{Name: "myapp"})
	eUID, _ := v.AddEnvironment(vault.Environment{Name: "prod", ProjectUID: pUID})
	v.AddSecret(vault.Secret{
		Name: "DB_PASS", Value: "s3cret", ProjectUID: pUID, EnvironmentUID: eUID,
		URL: "https://db.example.com", Notes: "database",
	})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"secret", "reveal", "DB_PASS", "--project", "myapp", "--env", "prod", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("reveal: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, buf.String())
	}
	if got["name"] != "DB_PASS" {
		t.Errorf("name = %v, want DB_PASS", got["name"])
	}
	if got["value"] != "s3cret" {
		t.Errorf("value = %v, want s3cret", got["value"])
	}
	if got["project"] != "myapp" {
		t.Errorf("project = %v, want myapp", got["project"])
	}
	if got["env"] != "prod" {
		t.Errorf("env = %v, want prod", got["env"])
	}
	if got["url"] != "https://db.example.com" {
		t.Errorf("url = %v", got["url"])
	}
	if got["notes"] != "database" {
		t.Errorf("notes = %v", got["notes"])
	}
}

func TestSecretRevealHumanStillWorks(t *testing.T) {
	resetCmdFlags(t)
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
	pUID, _ := v.AddProject(vault.Project{Name: "myapp"})
	v.AddSecret(vault.Secret{Name: "MY_SECRET", Value: "val", ProjectUID: pUID})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"secret", "reveal", "MY_SECRET", "--project", "myapp"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("reveal: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "Name:    MY_SECRET") {
		t.Errorf("human output missing name, got:\n%s", output)
	}
	if !strings.Contains(output, "Value:   val") {
		t.Errorf("human output missing value, got:\n%s", output)
	}
	if strings.Contains(output, "{") {
		t.Errorf("human output contains JSON: %s", output)
	}
}

func TestFindJSON(t *testing.T) {
	resetCmdFlags(t)
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
	pUID, _ := v.AddProject(vault.Project{Name: "myapp"})
	eUID, _ := v.AddEnvironment(vault.Environment{Name: "prod", ProjectUID: pUID})
	v.AddSecret(vault.Secret{Name: "GitHub API Key", ProjectUID: pUID, EnvironmentUID: eUID, Value: "x", URL: "https://github.com"})
	v.AddSecret(vault.Secret{Name: "AWS Key", Value: "x", URL: "https://aws.amazon.com"})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	tests := []struct {
		name    string
		args    []string
		wantLen int
		wantKey string
	}{
		{"find all", []string{"find", "key", "--format", "json"}, 2, ""},
		{"find scoped", []string{"find", "GitHub", "--project", "myapp", "--format", "json"}, 1, "GitHub API Key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetExportImportFlags()
			var buf bytes.Buffer
			rootCmd.SetOut(&buf)
			rootCmd.SetErr(io.Discard)
			rootCmd.SetArgs(tt.args)
			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("find: %v", err)
			}
			var items []map[string]any
			if err := json.Unmarshal(buf.Bytes(), &items); err != nil {
				t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
			}
			if len(items) != tt.wantLen {
				t.Errorf("got %d items, want %d", len(items), tt.wantLen)
			}
			if tt.wantKey != "" && len(items) > 0 {
				if items[0]["name"] != tt.wantKey {
					t.Errorf("first item name = %v, want %s", items[0]["name"], tt.wantKey)
				}
			}
		})
	}
}

func TestFindEmptyJSON(t *testing.T) {
	resetCmdFlags(t)
	setupTestVault(t)

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"find", "nonexistent", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("find: %v", err)
	}
	var items []any
	if err := json.Unmarshal(buf.Bytes(), &items); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(items) != 0 {
		t.Errorf("expected empty array, got %d items", len(items))
	}
}

func TestSecretListJSONEmpty(t *testing.T) {
	resetCmdFlags(t)
	setupTestVault(t)

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"secret", "list", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("secret list: %v", err)
	}
	var items []any
	if err := json.Unmarshal(buf.Bytes(), &items); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(items) != 0 {
		t.Errorf("expected empty array, got %d items", len(items))
	}
}

func TestListJSONEmpty(t *testing.T) {
	resetCmdFlags(t)
	setupTestVault(t)

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"list", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("list: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	projects, ok := got["projects"].([]any)
	if !ok {
		t.Fatalf("projects field missing or wrong type: %v", got["projects"])
	}
	if len(projects) != 0 {
		t.Errorf("expected empty projects array, got %d", len(projects))
	}
}

func TestSecretShowJSON(t *testing.T) {
	resetCmdFlags(t)
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
	pUID, _ := v.AddProject(vault.Project{Name: "myapp"})
	eUID, _ := v.AddEnvironment(vault.Environment{Name: "prod", ProjectUID: pUID})
	secretUID, _ := v.AddSecret(vault.Secret{
		Name: "DB_PASS", Value: "s3cret", ProjectUID: pUID, EnvironmentUID: eUID,
		URL: "https://db.example.com", Notes: "database",
	})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"secret", "show", "DB_PASS", "--project", "myapp", "--env", "prod", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("secret show: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if got["name"] != "DB_PASS" {
		t.Errorf("name = %v, want DB_PASS", got["name"])
	}
	if got["project"] != "myapp" {
		t.Errorf("project = %v, want myapp", got["project"])
	}
	if got["env"] != "prod" {
		t.Errorf("env = %v, want prod", got["env"])
	}
	if got["url"] != "https://db.example.com" {
		t.Errorf("url = %v", got["url"])
	}
	if got["notes"] != "database" {
		t.Errorf("notes = %v", got["notes"])
	}
	uid, ok := got["uid"].(string)
	if !ok {
		t.Errorf("uid missing or not a string: %v", got["uid"])
	} else if uid != secretUID {
		t.Errorf("uid = %q, want full uid %q", uid, secretUID)
	}
}

func TestListJSONPopulated(t *testing.T) {
	resetCmdFlags(t)
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
	pUID, _ := v.AddProject(vault.Project{Name: "myapp"})
	eUID1, _ := v.AddEnvironment(vault.Environment{Name: "prod", ProjectUID: pUID})
	eUID2, _ := v.AddEnvironment(vault.Environment{Name: "dev", ProjectUID: pUID})
	v.AddSecret(vault.Secret{Name: "SECRET_A", Value: "a", ProjectUID: pUID, EnvironmentUID: eUID1})
	v.AddSecret(vault.Secret{Name: "SECRET_B", Value: "b", ProjectUID: pUID, EnvironmentUID: eUID2})
	v.AddSecret(vault.Secret{Name: "STANDALONE_SECRET", Value: "c"})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"list", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("list: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	projects, ok := got["projects"].([]any)
	if !ok {
		t.Fatalf("projects field missing or wrong type: %v", got["projects"])
	}
	if len(projects) != 1 {
		t.Fatalf("expected 1 project, got %d", len(projects))
	}
	p := projects[0].(map[string]any)
	if p["name"] != "myapp" {
		t.Errorf("project name = %v, want myapp", p["name"])
	}
	envs, ok := p["envs"].([]any)
	if !ok {
		t.Fatalf("envs field missing or wrong type: %v", p["envs"])
	}
	if len(envs) != 2 {
		t.Fatalf("expected 2 envs, got %d", len(envs))
	}
	for _, e := range envs {
		env := e.(map[string]any)
		secrets, ok := env["secrets"].([]any)
		if !ok {
			t.Fatalf("secrets missing for env %v", env["name"])
		}
		if len(secrets) != 1 {
			t.Errorf("expected 1 secret in env %v, got %d", env["name"], len(secrets))
		}
	}
	standalone, ok := got["standalone"].([]any)
	if !ok {
		t.Fatalf("standalone field missing or wrong type: %v", got["standalone"])
	}
	if len(standalone) != 1 {
		t.Fatalf("expected 1 standalone secret, got %d", len(standalone))
	}
	s := standalone[0].(map[string]any)
	if s["name"] != "STANDALONE_SECRET" {
		t.Errorf("standalone name = %v, want STANDALONE_SECRET", s["name"])
	}
}

// --- project list/show JSON tests ---

func TestProjectListJSONEmpty(t *testing.T) {
	resetCmdFlags(t)
	setupTestVault(t)

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"project", "list", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("project list: %v", err)
	}
	var items []any
	if err := json.Unmarshal(buf.Bytes(), &items); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(items) != 0 {
		t.Errorf("expected empty array, got %d items", len(items))
	}
}

func TestProjectListJSONPopulated(t *testing.T) {
	resetCmdFlags(t)
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
	v.AddProject(vault.Project{Name: "alpha", Description: "first", URL: "https://alpha.example.com"})
	v.AddProject(vault.Project{Name: "beta", Description: "second"})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"project", "list", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("project list: %v", err)
	}
	var items []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &items); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 projects, got %d", len(items))
	}
	// Sorted by name: alpha, beta
	if items[0]["name"] != "alpha" {
		t.Errorf("first project name = %v, want alpha", items[0]["name"])
	}
	if items[0]["description"] != "first" {
		t.Errorf("alpha description = %v, want first", items[0]["description"])
	}
	if items[0]["url"] != "https://alpha.example.com" {
		t.Errorf("alpha url = %v, want https://alpha.example.com", items[0]["url"])
	}
	if items[1]["name"] != "beta" {
		t.Errorf("second project name = %v, want beta", items[1]["name"])
	}
	// UIDs should be full strings (not short)
	uid, ok := items[0]["uid"].(string)
	if !ok || len(uid) < 16 {
		t.Errorf("uid should be a full string, got: %v", items[0]["uid"])
	}
}

func TestProjectShowJSON(t *testing.T) {
	resetCmdFlags(t)
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
	pUID, _ := v.AddProject(vault.Project{Name: "myapp", Description: "app", URL: "https://app.example.com", Notes: "notes here"})
	eUID, _ := v.AddEnvironment(vault.Environment{Name: "prod", ProjectUID: pUID})
	v.AddSecret(vault.Secret{Name: "DB_PASS", Value: "s3cret", ProjectUID: pUID, EnvironmentUID: eUID})
	v.AddSecret(vault.Secret{Name: "API_KEY", Value: "key123", ProjectUID: pUID})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"project", "show", "myapp", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("project show: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if got["name"] != "myapp" {
		t.Errorf("name = %v, want myapp", got["name"])
	}
	if got["description"] != "app" {
		t.Errorf("description = %v, want app", got["description"])
	}
	if got["url"] != "https://app.example.com" {
		t.Errorf("url = %v, want https://app.example.com", got["url"])
	}
	if got["notes"] != "notes here" {
		t.Errorf("notes = %v, want notes here", got["notes"])
	}
	if got["created"] == nil || got["created"] == "" {
		t.Error("created should not be empty")
	}
	if got["updated"] == nil || got["updated"] == "" {
		t.Error("updated should not be empty")
	}
	envs, ok := got["environments"].([]any)
	if !ok {
		t.Fatalf("environments missing or wrong type: %v", got["environments"])
	}
	if len(envs) != 1 {
		t.Errorf("expected 1 environment, got %d", len(envs))
	}
	env := envs[0].(map[string]any)
	if env["name"] != "prod" {
		t.Errorf("env name = %v, want prod", env["name"])
	}
	if got["secret_count"] != float64(2) {
		t.Errorf("secret_count = %v, want 2", got["secret_count"])
	}
}

func TestProjectShowJSONNotFound(t *testing.T) {
	resetCmdFlags(t)
	setupTestVault(t)

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	rootCmd.SetArgs([]string{"project", "show", "nonexistent", "--format", "json"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent project")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}

// --- env list/show JSON tests ---

func TestEnvListJSONEmpty(t *testing.T) {
	resetCmdFlags(t)
	setupTestVault(t)

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"env", "list", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("env list: %v", err)
	}
	var items []any
	if err := json.Unmarshal(buf.Bytes(), &items); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(items) != 0 {
		t.Errorf("expected empty array, got %d items", len(items))
	}
}

func TestEnvListJSONPopulated(t *testing.T) {
	resetCmdFlags(t)
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
	p1UID, _ := v.AddProject(vault.Project{Name: "myapp"})
	p2UID, _ := v.AddProject(vault.Project{Name: "other"})
	v.AddEnvironment(vault.Environment{Name: "prod", ProjectUID: p1UID})
	v.AddEnvironment(vault.Environment{Name: "dev", ProjectUID: p1UID})
	v.AddEnvironment(vault.Environment{Name: "staging", ProjectUID: p2UID})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"env", "list", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("env list: %v", err)
	}
	var items []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &items); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 envs, got %d", len(items))
	}
	// Each env should have name, uid, and project
	for _, item := range items {
		if item["name"] == nil || item["name"] == "" {
			t.Errorf("env missing name: %v", item)
		}
		if item["uid"] == nil || item["uid"] == "" {
			t.Errorf("env missing uid: %v", item)
		}
		if item["project"] == nil || item["project"] == "" {
			t.Errorf("env missing project: %v", item)
		}
	}
}

func TestEnvListJSONScoped(t *testing.T) {
	resetCmdFlags(t)
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
	p1UID, _ := v.AddProject(vault.Project{Name: "myapp"})
	p2UID, _ := v.AddProject(vault.Project{Name: "other"})
	v.AddEnvironment(vault.Environment{Name: "prod", ProjectUID: p1UID})
	v.AddEnvironment(vault.Environment{Name: "dev", ProjectUID: p1UID})
	v.AddEnvironment(vault.Environment{Name: "staging", ProjectUID: p2UID})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"env", "list", "--project", "myapp", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("env list: %v", err)
	}
	var items []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &items); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 envs in myapp, got %d", len(items))
	}
	for _, item := range items {
		if item["project"] != "myapp" {
			t.Errorf("env project = %v, want myapp", item["project"])
		}
	}
}

func TestEnvListJSONProjectNotFound(t *testing.T) {
	resetCmdFlags(t)
	setupTestVault(t)

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"env", "list", "--project", "nonexistent", "--format", "json"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent project")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}

func TestEnvShowJSON(t *testing.T) {
	resetCmdFlags(t)
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
	pUID, _ := v.AddProject(vault.Project{Name: "myapp"})
	eUID, _ := v.AddEnvironment(vault.Environment{Name: "prod", ProjectUID: pUID, Description: "production", Notes: "be careful"})
	v.AddSecret(vault.Secret{Name: "DB_PASS", Value: "s3cret", ProjectUID: pUID, EnvironmentUID: eUID})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"env", "show", "prod", "--project", "myapp", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("env show: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if got["name"] != "prod" {
		t.Errorf("name = %v, want prod", got["name"])
	}
	if got["project"] != "myapp" {
		t.Errorf("project = %v, want myapp", got["project"])
	}
	if got["description"] != "production" {
		t.Errorf("description = %v, want production", got["description"])
	}
	if got["notes"] != "be careful" {
		t.Errorf("notes = %v, want be careful", got["notes"])
	}
	if got["created"] == nil || got["created"] == "" {
		t.Error("created should not be empty")
	}
	secrets, ok := got["secrets"].([]any)
	if !ok {
		t.Fatalf("secrets missing or wrong type: %v", got["secrets"])
	}
	if len(secrets) != 1 {
		t.Errorf("expected 1 secret, got %d", len(secrets))
	}
}

// --- list command scope filtering tests ---

func TestListJSONScopedByProject(t *testing.T) {
	resetCmdFlags(t)
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
	p1UID, _ := v.AddProject(vault.Project{Name: "myapp"})
	p2UID, _ := v.AddProject(vault.Project{Name: "other"})
	eUID1, _ := v.AddEnvironment(vault.Environment{Name: "prod", ProjectUID: p1UID})
	v.AddEnvironment(vault.Environment{Name: "staging", ProjectUID: p2UID})
	v.AddSecret(vault.Secret{Name: "SECRET_A", Value: "a", ProjectUID: p1UID, EnvironmentUID: eUID1})
	v.AddSecret(vault.Secret{Name: "SECRET_B", Value: "b", ProjectUID: p2UID})
	v.AddSecret(vault.Secret{Name: "STANDALONE", Value: "s"})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"list", "--project", "myapp", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("list: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	projects, ok := got["projects"].([]any)
	if !ok {
		t.Fatalf("projects missing: %v", got)
	}
	if len(projects) != 1 {
		t.Fatalf("expected 1 project, got %d", len(projects))
	}
	p := projects[0].(map[string]any)
	if p["name"] != "myapp" {
		t.Errorf("project name = %v, want myapp", p["name"])
	}
	// Standalone should not appear when scoped to a project
	if _, ok := got["standalone"]; ok {
		t.Error("standalone should not appear when scoped to a project")
	}
}

func TestListJSONScopedByProjectAndEnv(t *testing.T) {
	resetCmdFlags(t)
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
	pUID, _ := v.AddProject(vault.Project{Name: "myapp"})
	prodUID, _ := v.AddEnvironment(vault.Environment{Name: "prod", ProjectUID: pUID})
	devUID, _ := v.AddEnvironment(vault.Environment{Name: "dev", ProjectUID: pUID})
	v.AddSecret(vault.Secret{Name: "PROD_SECRET", Value: "p", ProjectUID: pUID, EnvironmentUID: prodUID})
	v.AddSecret(vault.Secret{Name: "DEV_SECRET", Value: "d", ProjectUID: pUID, EnvironmentUID: devUID})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"list", "--project", "myapp", "--env", "prod", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("list: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	projects := got["projects"].([]any)
	if len(projects) != 1 {
		t.Fatalf("expected 1 project, got %d", len(projects))
	}
	p := projects[0].(map[string]any)
	envs, ok := p["envs"].([]any)
	if !ok {
		t.Fatalf("envs missing: %v", p)
	}
	if len(envs) != 1 {
		t.Fatalf("expected 1 env, got %d", len(envs))
	}
	env := envs[0].(map[string]any)
	if env["name"] != "prod" {
		t.Errorf("env name = %v, want prod", env["name"])
	}
	secrets := env["secrets"].([]any)
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret in prod, got %d", len(secrets))
	}
	sec := secrets[0].(map[string]any)
	if sec["name"] != "PROD_SECRET" {
		t.Errorf("secret name = %v, want PROD_SECRET", sec["name"])
	}
}

func TestListEnvRequiresProject(t *testing.T) {
	resetCmdFlags(t)
	setupTestVault(t)

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	rootCmd.SetArgs([]string{"list", "--env", "prod"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for --env without --project")
	}
	if !strings.Contains(err.Error(), "--env requires --project") {
		t.Errorf("error should mention '--env requires --project', got: %v", err)
	}
}

func TestEnvListWithoutProjectFlag(t *testing.T) {
	resetCmdFlags(t)
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
	p1UID, _ := v.AddProject(vault.Project{Name: "app1"})
	p2UID, _ := v.AddProject(vault.Project{Name: "app2"})
	v.AddEnvironment(vault.Environment{Name: "dev", ProjectUID: p1UID})
	v.AddEnvironment(vault.Environment{Name: "prod", ProjectUID: p2UID})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"env", "list", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("env list: %v", err)
	}
	var items []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &items); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 envs across all projects, got %d", len(items))
	}
}

func TestListJSONPopulatedProjectScopes(t *testing.T) {
	resetCmdFlags(t)
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
	pUID, _ := v.AddProject(vault.Project{Name: "myapp"})
	eUID, _ := v.AddEnvironment(vault.Environment{Name: "prod", ProjectUID: pUID})
	v.AddSecret(vault.Secret{Name: "SECRET_A", Value: "a", ProjectUID: pUID, EnvironmentUID: eUID})
	v.AddSecret(vault.Secret{Name: "STANDALONE", Value: "s"})
	if err := v.Save(dir, key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	// Without scope: should show standalone
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"list", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("list: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	standalone, ok := got["standalone"].([]any)
	if !ok {
		t.Fatalf("standalone missing: %v", got)
	}
	if len(standalone) != 1 {
		t.Errorf("expected 1 standalone, got %d", len(standalone))
	}

	// With --project scope: standalone should NOT appear
	buf.Reset()
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"list", "--project", "myapp", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("list scoped: %v", err)
	}
	var got2 map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got2); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if _, ok := got2["standalone"]; ok {
		t.Error("standalone should not appear when scoped to a project")
	}
}
