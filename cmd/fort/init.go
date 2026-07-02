package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/youruser/fortbyte/internal/crypto"
	"github.com/youruser/fortbyte/internal/session"
	"github.com/youruser/fortbyte/internal/vault"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a new vault",
	RunE: func(cmd *cobra.Command, _ []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Enter master password (min %d chars): ", minPasswordLen)
		password, err := readPasswordFn()
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		fmt.Fprintln(cmd.ErrOrStderr())
		fmt.Fprint(cmd.ErrOrStderr(), "Confirm master password: ")
		confirm, err := readPasswordFn()
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		fmt.Fprintln(cmd.ErrOrStderr())
		if err := runInit(vaultDir, password, confirm); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Vault created successfully!")
		fmt.Fprintf(cmd.OutOrStdout(), "Location: %s\n", filepath.Join(vaultDir, vault.FileName))
		return nil
	},
}

// runInit is the core init logic. Called by initCmd.RunE and by tests.
func runInit(dir, password, confirm string) error {
	vaultPath := filepath.Join(dir, vault.FileName)
	if _, err := os.Stat(vaultPath); err == nil {
		return fmt.Errorf("vault already exists at %s", vaultPath)
	}
	if len(password) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	if len(password) > maxPasswordLen {
		return fmt.Errorf("password must be at most %d characters", maxPasswordLen)
	}
	if subtle.ConstantTimeCompare([]byte(password), []byte(confirm)) != 1 {
		return errors.New("passwords do not match")
	}
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	key := crypto.DeriveKey(password, salt)
	if err := vault.Init(dir, key, salt); err != nil {
		return fmt.Errorf("create vault: %w", err)
	}
	if err := session.StorePassword(dir, password); err != nil {
		fmt.Fprintf(warnOut, "Warning: could not store session: %v\n", err)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(initCmd)
}
