package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/youruser/gokeep/internal/crypto"
	"github.com/youruser/gokeep/internal/session"
	"github.com/youruser/gokeep/internal/vault"
	"golang.org/x/term"
)

const (
	minPasswordLen = 8
	maxPasswordLen = 1024 // Prevent DoS via Argon2 memory pressure
	gokeepDir      = ".gokeep"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot determine home directory: %v\n", err)
		os.Exit(1)
	}

	dir := filepath.Join(homeDir, gokeepDir)
	cmd := os.Args[1]

	switch cmd {
	case "init":
		cmdInit(dir)
	case "add":
		cmdAdd(dir)
	case "get":
		cmdGet(dir)
	case "list":
		cmdList(dir)
	case "remove":
		cmdRemove(dir)
	case "lock":
		cmdLock(dir)
	case "reset":
		cmdReset(dir)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: gokeep <command> [args]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  init              Create a new vault")
	fmt.Println("  add <name>        Add a secret")
	fmt.Println("  get <name>        Retrieve a secret")
	fmt.Println("  list              List all secret names")
	fmt.Println("  remove <name>     Delete a secret")
	fmt.Println("  lock              Lock the vault (clear session)")
	fmt.Println("  reset             Delete vault and start fresh (irreversible)")
}

func cmdInit(dir string) {
	// Check if vault already exists
	vaultPath := filepath.Join(dir, "vault.enc")
	if _, err := os.Stat(vaultPath); err == nil {
		fmt.Fprintf(os.Stderr, "Error: vault already exists at %s\n", vaultPath)
		os.Exit(1)
	}

	// Prompt for master password
	password, err := promptPassword("Enter master password (min 8 chars): ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
		os.Exit(1)
	}

	if len(password) < minPasswordLen {
		fmt.Fprintf(os.Stderr, "Error: password must be at least %d characters\n", minPasswordLen)
		os.Exit(1)
	}

	if len(password) > maxPasswordLen {
		fmt.Fprintf(os.Stderr, "Error: password must be at most %d characters\n", maxPasswordLen)
		os.Exit(1)
	}

	// Confirm password
	confirm, err := promptPassword("Confirm master password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
		os.Exit(1)
	}

	if password != confirm {
		fmt.Fprintf(os.Stderr, "Error: passwords do not match\n")
		os.Exit(1)
	}

	// Generate salt and derive key
	salt, err := crypto.GenerateSalt()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating salt: %v\n", err)
		os.Exit(1)
	}

	key := crypto.DeriveKey(password, salt)

	// Initialize vault
	if err := vault.Init(dir, key, salt); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating vault: %v\n", err)
		os.Exit(1)
	}

	// Store password in session (not the derived key)
	if err := session.StorePassword(dir, password); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not store session: %v\n", err)
	}

	fmt.Println("Vault created successfully!")
	fmt.Printf("Location: %s\n", vaultPath)
}

func cmdAdd(dir string) {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: gokeep add <name>\n")
		os.Exit(1)
	}

	name := os.Args[2]

	// Get key
	key, err := getKey(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Open vault
	v, err := vault.Open(dir, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening vault: %v\n", err)
		os.Exit(1)
	}

	// Check if name already exists
	for _, s := range v.List() {
		if s.Name == name {
			fmt.Fprintf(os.Stderr, "Error: secret '%s' already exists\n", name)
			os.Exit(1)
		}
	}

	// Prompt for details
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading username: %v\n", err)
		os.Exit(1)
	}
	username = strings.TrimSpace(username)

	password, err := promptPassword("Password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
		os.Exit(1)
	}

	fmt.Print("URL (optional): ")
	url, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading URL: %v\n", err)
		os.Exit(1)
	}
	url = strings.TrimSpace(url)

	fmt.Print("Notes (optional): ")
	notes, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading notes: %v\n", err)
		os.Exit(1)
	}
	notes = strings.TrimSpace(notes)

	// Add secret
	s := vault.Secret{
		Name:     name,
		Username: username,
		Password: password,
		URL:      url,
		Notes:    notes,
	}

	id := v.Add(s)

	// Save vault
	if err := v.Save(dir, key); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving vault: %v\n", err)
		os.Exit(1)
	}

	// Touch session
	if err := session.Touch(dir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not update session: %v\n", err)
	}

	fmt.Printf("Secret '%s' added (ID: %s)\n", name, id)
}

func cmdGet(dir string) {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: gokeep get <name>\n")
		os.Exit(1)
	}

	name := os.Args[2]

	// Get key
	key, err := getKey(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Open vault
	v, err := vault.Open(dir, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening vault: %v\n", err)
		os.Exit(1)
	}

	// Find secret by name
	var found *vault.Secret
	var foundID string
	for id, s := range v.List() {
		if s.Name == name {
			found = &s
			foundID = id
			break
		}
	}

	if found == nil {
		fmt.Fprintf(os.Stderr, "Error: secret '%s' not found\n", name)
		os.Exit(1)
	}

	// Touch session
	if err := session.Touch(dir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not update session: %v\n", err)
	}

	// Print secret
	fmt.Printf("Name:     %s\n", found.Name)
	fmt.Printf("ID:       %s\n", foundID)
	fmt.Printf("Username: %s\n", found.Username)
	fmt.Printf("Password: %s\n", found.Password)
	if found.URL != "" {
		fmt.Printf("URL:      %s\n", found.URL)
	}
	if found.Notes != "" {
		fmt.Printf("Notes:    %s\n", found.Notes)
	}
}

func cmdList(dir string) {
	// Get key
	key, err := getKey(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Open vault
	v, err := vault.Open(dir, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening vault: %v\n", err)
		os.Exit(1)
	}

	secrets := v.List()
	if len(secrets) == 0 {
		fmt.Println("No secrets stored.")
		return
	}

	// Touch session
	if err := session.Touch(dir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not update session: %v\n", err)
	}

	fmt.Println("Stored secrets:")
	for id, s := range secrets {
		fmt.Printf("  %-20s (ID: %s)\n", s.Name, id)
	}
}

func cmdRemove(dir string) {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: gokeep remove <name>\n")
		os.Exit(1)
	}

	name := os.Args[2]

	// Get key
	key, err := getKey(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Open vault
	v, err := vault.Open(dir, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening vault: %v\n", err)
		os.Exit(1)
	}

	// Find secret by name
	var foundID string
	for id, s := range v.List() {
		if s.Name == name {
			foundID = id
			break
		}
	}

	if foundID == "" {
		fmt.Fprintf(os.Stderr, "Error: secret '%s' not found\n", name)
		os.Exit(1)
	}

	// Confirm deletion
	fmt.Printf("Are you sure you want to delete '%s'? (yes/no): ", name)
	reader := bufio.NewReader(os.Stdin)
	confirm, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading confirmation: %v\n", err)
		os.Exit(1)
	}
	confirm = strings.TrimSpace(strings.ToLower(confirm))

	if confirm != "yes" && confirm != "y" {
		fmt.Println("Cancelled.")
		return
	}

	// Remove secret
	if !v.Remove(foundID) {
		fmt.Fprintf(os.Stderr, "Error: could not remove secret\n")
		os.Exit(1)
	}

	// Save vault
	if err := v.Save(dir, key); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving vault: %v\n", err)
		os.Exit(1)
	}

	// Touch session
	if err := session.Touch(dir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not update session: %v\n", err)
	}

	fmt.Printf("Secret '%s' removed.\n", name)
}

func cmdLock(dir string) {
	if err := session.Clear(dir); err != nil {
		fmt.Fprintf(os.Stderr, "Error locking vault: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Vault locked. Session cleared.")
}

func cmdReset(dir string) {
	vaultPath := filepath.Join(dir, "vault.enc")

	// Check if vault exists
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: no vault found at %s\n", vaultPath)
		os.Exit(1)
	}

	// Show warning
	fmt.Println("WARNING: This will permanently delete your vault and all secrets!")
	fmt.Println("This action is IRREVERSIBLE. All data will be lost.")
	fmt.Println()
	fmt.Printf("Vault location: %s\n", vaultPath)
	fmt.Println()
	fmt.Print("Type 'RESET' to confirm: ")

	reader := bufio.NewReader(os.Stdin)
	confirm, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading confirmation: %v\n", err)
		os.Exit(1)
	}
	confirm = strings.TrimSpace(confirm)

	if confirm != "RESET" {
		fmt.Println("Cancelled.")
		return
	}

	// Clear session
	if err := session.Clear(dir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not clear session: %v\n", err)
	}

	// Delete vault file
	if err := os.Remove(vaultPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error deleting vault: %v\n", err)
		os.Exit(1)
	}

	// Delete session file if it still exists
	sessionPath := filepath.Join(dir, "session")
	os.Remove(sessionPath) // Ignore error if already deleted

	fmt.Println("Vault deleted successfully. All secrets have been removed.")
}

// getKey retrieves the encryption key, prompting for password if session expired.
func getKey(dir string) ([]byte, error) {
	// Check if session is valid
	if session.IsValid(dir) {
		password, err := session.LoadPassword()
		if err == nil {
			// Get salt from vault
			salt, err := vault.GetSalt(dir)
			if err == nil {
				// Derive key from stored password
				key := crypto.DeriveKey(password, salt)
				// Verify key works
				if _, err := vault.Open(dir, key); err == nil {
					return key, nil
				}
			}
		}
		// If session file exists but keyring failed, fall through to prompt
	}

	// Session expired or invalid, prompt for password
	fmt.Print("Enter master password: ")
	password, err := readPassword()
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}

	// Get salt from vault
	salt, err := vault.GetSalt(dir)
	if err != nil {
		if errors.Is(err, vault.ErrVaultNotFound) {
			return nil, fmt.Errorf("vault not found: run 'gokeep init' first")
		}
		return nil, fmt.Errorf("read vault: %w", err)
	}

	// Derive key
	key := crypto.DeriveKey(password, salt)

	// Verify key works by trying to open vault
	if _, err := vault.Open(dir, key); err != nil {
		if errors.Is(err, crypto.ErrDecrypt) {
			return nil, fmt.Errorf("incorrect master password")
		}
		return nil, fmt.Errorf("vault error: %w", err)
	}

	// Store password in session (not the derived key)
	if err := session.StorePassword(dir, password); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not store session: %v\n", err)
	}

	return key, nil
}

// promptPassword prompts for a password with confirmation.
func promptPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := readPassword()
	if err != nil {
		return "", err
	}
	fmt.Println() // newline after hidden input
	return password, nil
}

// readPassword reads a password from stdin without echoing.
func readPassword() (string, error) {
	pw, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	return string(pw), nil
}
