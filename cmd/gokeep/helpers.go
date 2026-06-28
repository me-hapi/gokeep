package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/youruser/gokeep/internal/crypto"
	"github.com/youruser/gokeep/internal/session"
	"github.com/youruser/gokeep/internal/vault"
)

// openVault unlocks and opens the vault. Returns vault, key, error.
// promptOut receives the password prompt; warnOut receives non-fatal warnings.
func openVault(dir string, promptOut io.Writer, warnOut io.Writer) (*vault.Vault, []byte, error) {
	key, err := getKey(dir, promptOut, warnOut)
	if err != nil {
		return nil, nil, err
	}
	v, err := vault.Open(dir, key)
	if err != nil {
		return nil, nil, fmt.Errorf("open vault: %w", err)
	}
	return v, key, nil
}

// saveVault writes the vault and touches the session. Returns error.
func saveVault(v *vault.Vault, dir string, key []byte, warnOut io.Writer) error {
	if err := v.Save(dir, key); err != nil {
		return fmt.Errorf("save vault: %w", err)
	}
	if err := session.Touch(dir); err != nil {
		fmt.Fprintf(warnOut, "Warning: could not update session: %v\n", err)
	}
	return nil
}

// getKey retrieves the encryption key, prompting for password if session expired.
// promptOut receives the "Enter master password: " prompt; warnOut receives
// non-fatal warnings (e.g., keyring store failures).
func getKey(dir string, promptOut io.Writer, warnOut io.Writer) ([]byte, error) {
	if session.IsValid(dir) {
		password, err := session.LoadPassword()
		if err == nil {
			salt, err := vault.GetSalt(dir)
			if err == nil {
				key := crypto.DeriveKey(password, salt)
				if _, err := vault.Open(dir, key); err == nil {
					return key, nil
				}
			}
		}
	}
	fmt.Fprint(promptOut, "Enter master password: ")
	password, err := readPasswordFn()
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	fmt.Fprintln(promptOut)
	salt, err := vault.GetSalt(dir)
	if err != nil {
		if errors.Is(err, vault.ErrVaultNotFound) {
			return nil, fmt.Errorf("vault not found: run 'gokeep init' first")
		}
		return nil, fmt.Errorf("read vault: %w", err)
	}
	key := crypto.DeriveKey(password, salt)
	if _, err := vault.Open(dir, key); err != nil {
		if errors.Is(err, crypto.ErrDecrypt) {
			return nil, fmt.Errorf("incorrect master password")
		}
		return nil, fmt.Errorf("vault error: %w", err)
	}
	if err := session.StorePassword(dir, password); err != nil {
		fmt.Fprintf(warnOut, "Warning: could not store session: %v\n", err)
	}
	return key, nil
}

// promptLine reads a line from r (visible input).
func promptLine(w io.Writer, r io.Reader, prompt string) (string, error) {
	fmt.Fprint(w, prompt)
	reader := bufio.NewReader(r)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read input: %w", err)
	}
	return strings.TrimSpace(input), nil
}

// confirmDeletion asks for yes/no and returns (true, nil) if confirmed.
func confirmDeletion(w io.Writer, r io.Reader, name string) (bool, error) {
	fmt.Fprintf(w, "Are you sure you want to delete '%s'? (yes/no): ", name)
	reader := bufio.NewReader(r)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "yes" || input == "y", nil
}

// printJSON marshals v as indented JSON and writes it to w.
func printJSON(w io.Writer, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}
