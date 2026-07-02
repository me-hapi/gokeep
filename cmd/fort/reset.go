package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/youruser/fortbyte/internal/session"
	"github.com/youruser/fortbyte/internal/vault"
)

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Delete vault and start fresh (irreversible)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		vaultPath := filepath.Join(vaultDir, vault.FileName)
		if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
			return fmt.Errorf("no vault found at %s", vaultPath)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "WARNING: This will permanently delete your vault and all secrets!")
		fmt.Fprintln(cmd.OutOrStdout(), "This action is IRREVERSIBLE. All data will be lost.")
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintf(cmd.OutOrStdout(), "Vault location: %s\n", vaultPath)
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprint(cmd.OutOrStdout(), "Type 'RESET' to confirm: ")
		reader := bufio.NewReader(cmd.InOrStdin())
		confirm, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read confirmation: %w", err)
		}
		if confirm == "" {
			return fmt.Errorf("read confirmation: unexpected EOF")
		}
		confirm = strings.TrimSpace(confirm)
		if confirm != "RESET" {
			fmt.Fprintln(cmd.OutOrStdout(), "Cancelled.")
			return nil
		}
		if err := session.Clear(vaultDir); err != nil {
			return fmt.Errorf("clear session: %w", err)
		}
		if err := os.Remove(vaultPath); err != nil {
			return fmt.Errorf("delete vault: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Vault deleted successfully. All secrets have been removed.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(resetCmd)
}
