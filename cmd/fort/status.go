// Package main — fortbyte status subcommand.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/youruser/fortbyte/internal/crypto"
	"github.com/youruser/fortbyte/internal/session"
	"github.com/youruser/fortbyte/internal/vault"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show vault status (locked/unlocked, expiry, counts)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		vaultPath := filepath.Join(vaultDir, vault.FileName)
		sessionPath := filepath.Join(vaultDir, "session")

		fmt.Fprintf(cmd.OutOrStdout(), "Vault:   %s\n", vaultPath)

		if !session.IsValid(vaultDir) {
			fmt.Fprintln(cmd.OutOrStdout(), "State:   locked")
			info, err := os.Stat(sessionPath)
			switch {
			case os.IsNotExist(err):
				fmt.Fprintln(cmd.OutOrStdout(), "Session: none")
			case err != nil:
				fmt.Fprintf(cmd.OutOrStdout(), "Session: unknown (%v)\n", err)
			default:
				age := time.Since(info.ModTime())
				if age >= session.SessionMaxAge {
					fmt.Fprintf(cmd.OutOrStdout(), "Session: expired %s ago\n", age.Truncate(time.Second))
				} else {
					fmt.Fprintln(cmd.OutOrStdout(), "Session: invalid")
				}
			}
			return nil
		}

		// Unlocked
		info, err := os.Stat(sessionPath)
		if err != nil {
			return fmt.Errorf("stat session: %w", err)
		}
		remaining := session.SessionMaxAge - time.Since(info.ModTime())
		if remaining < 0 {
			remaining = 0
		}
		fmt.Fprintln(cmd.OutOrStdout(), "State:   unlocked")
		fmt.Fprintf(cmd.OutOrStdout(), "Expires: in %s\n", remaining.Truncate(time.Second))

		// If the vault or keyring is unavailable here, still show what we know
		// (state/expiry). Same graceful-degrade pattern as LoadPassword above.
		fmt.Fprint(cmd.OutOrStdout(), "Counts:  ")
		password, err := session.LoadPassword()
		if err != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "unavailable (%v)\n", err)
			return nil
		}
		salt, err := vault.GetSalt(vaultDir)
		if err != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "unavailable (read salt: %v)\n", err)
			return nil
		}
		key := crypto.DeriveKey(password, salt)
		v, err := vault.Open(vaultDir, key)
		if err != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "unavailable (open vault: %v)\n", err)
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Projects:     %d\n", len(v.ListProjects()))
		fmt.Fprintf(cmd.OutOrStdout(), "Environments: %d\n", len(v.ListEnvironments()))
		fmt.Fprintf(cmd.OutOrStdout(), "Secrets:      %d\n", len(v.ListSecrets()))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
