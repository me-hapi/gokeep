package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/youruser/fortbyte/internal/session"
)

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Lock the vault (clear session)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		if err := session.Clear(vaultDir); err != nil {
			return fmt.Errorf("lock vault: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Vault locked. Session cleared.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(lockCmd)
}
