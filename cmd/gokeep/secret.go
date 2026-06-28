package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/youruser/gokeep/internal/vault"
)

var secretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Manage secrets",
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		envName, _ := cmd.Flags().GetString("env")
		projectName, _ := cmd.Flags().GetString("project")
		if envName != "" && projectName == "" {
			return errors.New("--env requires --project")
		}
		return nil
	},
}

var secretAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add a new secret",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		name := args[0]
		projectName, _ := cmd.Flags().GetString("project")
		envName, _ := cmd.Flags().GetString("env")
		v, key, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		projectUID, envUID, err := resolveScope(v, projectName, envName)
		if err != nil {
			return err
		}
		// ponytail: pre-check the duplicate BEFORE prompting for value/notes/url.
		// The vault-layer ErrDuplicateName check in AddSecret below is defense-in-depth
		// (catches races, future API callers); this pre-check is the UX layer that
		// saves the user from typing a no-echo secret value into a name that already
		// exists. Project/env add don't need this because they don't have expensive
		// no-echo prompts.
		if _, _, found := v.FindSecretByName(name, projectUID, envUID); found {
			return fmt.Errorf("secret '%s' already exists in this scope", name)
		}
		value, _ := cmd.Flags().GetString("value")
		if !cmd.Flags().Changed("value") {
			fmt.Fprint(cmd.ErrOrStderr(), "Enter secret value: ")
			pw, err := readPasswordFn()
			if err != nil {
				return fmt.Errorf("read value: %w", err)
			}
			fmt.Fprintln(cmd.ErrOrStderr())
			value = pw
		}
		url, _ := cmd.Flags().GetString("url")
		if !cmd.Flags().Changed("url") {
			var err error
			url, err = promptLine(cmd.OutOrStdout(), cmd.InOrStdin(), "URL (optional): ")
			if err != nil {
				return err
			}
		}
		notes, _ := cmd.Flags().GetString("notes")
		if !cmd.Flags().Changed("notes") {
			var err error
			notes, err = promptLine(cmd.OutOrStdout(), cmd.InOrStdin(), "Notes (optional): ")
			if err != nil {
				return err
			}
		}
		uid, err := v.AddSecret(vault.Secret{
			Name:           name,
			ProjectUID:     projectUID,
			EnvironmentUID: envUID,
			Value:          value,
			URL:            url,
			Notes:          notes,
		})
		if err != nil {
			if errors.Is(err, vault.ErrDuplicateName) {
				return fmt.Errorf("secret '%s' already exists in this scope", name)
			}
			return err
		}
		if err := saveVault(v, vaultDir, key, cmd.ErrOrStderr()); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Secret '%s' added (UID: %s)\n", name, shortUID(uid))
		return nil
	},
}

var secretEditCmd = &cobra.Command{
	Use:   "edit <name>",
	Short: "Edit a secret",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		name := args[0]
		projectName, _ := cmd.Flags().GetString("project")
		envName, _ := cmd.Flags().GetString("env")
		v, key, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		projectUID, envUID, err := resolveScope(v, projectName, envName)
		if err != nil {
			return err
		}
		_, uid, found := v.FindSecretByName(name, projectUID, envUID)
		if !found {
			return fmt.Errorf("secret '%s' not found in the given scope", name)
		}
		v.UpdateSecret(uid, func(s *vault.Secret) {
			if cmd.Flags().Changed("value") {
				val, _ := cmd.Flags().GetString("value")
				s.Value = val
			}
			if cmd.Flags().Changed("url") {
				url, _ := cmd.Flags().GetString("url")
				s.URL = url
			}
			if cmd.Flags().Changed("notes") {
				notes, _ := cmd.Flags().GetString("notes")
				s.Notes = notes
			}
		})
		if err := saveVault(v, vaultDir, key, cmd.ErrOrStderr()); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Secret '%s' updated.\n", name)
		return nil
	},
}

var secretRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a secret",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		name := args[0]
		projectName, _ := cmd.Flags().GetString("project")
		envName, _ := cmd.Flags().GetString("env")
		v, key, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		projectUID, envUID, err := resolveScope(v, projectName, envName)
		if err != nil {
			return err
		}
		_, uid, found := v.FindSecretByName(name, projectUID, envUID)
		if !found {
			return fmt.Errorf("secret '%s' not found in the given scope", name)
		}
		ok, err := confirmDeletion(cmd.OutOrStdout(), cmd.InOrStdin(), name)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(cmd.OutOrStdout(), "Cancelled.")
			return nil
		}
		if !v.RemoveSecret(uid) {
			return errors.New("could not remove secret")
		}
		if err := saveVault(v, vaultDir, key, cmd.ErrOrStderr()); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Secret '%s' removed.\n", name)
		return nil
	},
}

var secretMoveCmd = &cobra.Command{
	Use:   "move <name>",
	Short: "Move a secret to a different scope",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		name := args[0]
		projectName, _ := cmd.Flags().GetString("project")
		envName, _ := cmd.Flags().GetString("env")
		destProjectName, _ := cmd.Flags().GetString("dest-project")
		destEnvName, _ := cmd.Flags().GetString("dest-env")
		v, key, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		projectUID, envUID, err := resolveScope(v, projectName, envName)
		if err != nil {
			return err
		}
		_, uid, found := v.FindSecretByName(name, projectUID, envUID)
		if !found {
			return fmt.Errorf("secret '%s' not found in the given scope", name)
		}
		destProjectUID, destEnvUID, err := resolveScope(v, destProjectName, destEnvName)
		if err != nil {
			return err
		}
		if _, _, found := v.FindSecretByName(name, destProjectUID, destEnvUID); found {
			return fmt.Errorf("secret '%s' already exists at destination", name)
		}
		v.UpdateSecret(uid, func(s *vault.Secret) {
			s.ProjectUID = destProjectUID
			s.EnvironmentUID = destEnvUID
		})
		if err := saveVault(v, vaultDir, key, cmd.ErrOrStderr()); err != nil {
			return err
		}
		msg := fmt.Sprintf("Secret '%s' moved to project '%s'", name, destProjectName)
		if destEnvName != "" {
			msg += fmt.Sprintf(" (env: '%s')", destEnvName)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s.\n", msg)
		return nil
	},
}

var secretCopyCmd = &cobra.Command{
	Use:   "copy <name>",
	Short: "Copy a secret to a different scope",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		name := args[0]
		projectName, _ := cmd.Flags().GetString("project")
		envName, _ := cmd.Flags().GetString("env")
		destProjectName, _ := cmd.Flags().GetString("dest-project")
		destEnvName, _ := cmd.Flags().GetString("dest-env")
		v, key, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		projectUID, envUID, err := resolveScope(v, projectName, envName)
		if err != nil {
			return err
		}
		secret, _, found := v.FindSecretByName(name, projectUID, envUID)
		if !found {
			return fmt.Errorf("secret '%s' not found in the given scope", name)
		}
		destName := name
		if cmd.Flags().Changed("name") {
			destName, _ = cmd.Flags().GetString("name")
		}
		if strings.TrimSpace(destName) == "" {
			return errors.New("secret name cannot be empty")
		}
		destProjectUID, destEnvUID, err := resolveScope(v, destProjectName, destEnvName)
		if err != nil {
			return err
		}
		if _, _, found := v.FindSecretByName(destName, destProjectUID, destEnvUID); found {
			return fmt.Errorf("secret '%s' already exists at destination", destName)
		}
		uid, err := v.AddSecret(vault.Secret{
			Name:           destName,
			ProjectUID:     destProjectUID,
			EnvironmentUID: destEnvUID,
			Value:          secret.Value,
			URL:            secret.URL,
			Notes:          secret.Notes,
		})
		if err != nil {
			return err
		}
		if err := saveVault(v, vaultDir, key, cmd.ErrOrStderr()); err != nil {
			return err
		}
		msg := fmt.Sprintf("Secret '%s' copied as '%s' to project '%s'", name, destName, destProjectName)
		if destEnvName != "" {
			msg += fmt.Sprintf(" (env: '%s')", destEnvName)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s (UID: %s).\n", msg, shortUID(uid))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(secretCmd)
	secretCmd.PersistentFlags().String("project", "", "Project name")
	secretCmd.AddCommand(secretAddCmd, secretEditCmd, secretRemoveCmd, secretListCmd, secretRevealCmd, secretShowCmd, secretMoveCmd, secretCopyCmd)
	secretAddCmd.Flags().String("env", "", "Environment name")
	secretAddCmd.Flags().String("value", "", "Secret value")
	secretAddCmd.Flags().String("url", "", "URL")
	secretAddCmd.Flags().String("notes", "", "Notes")
	secretEditCmd.Flags().String("env", "", "Environment name")
	secretEditCmd.Flags().String("value", "", "Secret value")
	secretEditCmd.Flags().String("url", "", "URL")
	secretEditCmd.Flags().String("notes", "", "Notes")
	secretRemoveCmd.Flags().String("env", "", "Environment name")
	secretListCmd.Flags().String("env", "", "Environment name")
	secretListCmd.Flags().String("filter", "", "Filter secrets by name, URL, or notes")
	secretRevealCmd.Flags().String("env", "", "Environment name")
	secretShowCmd.Flags().String("env", "", "Environment name")
	secretMoveCmd.Flags().String("dest-project", "", "Destination project name")
	secretMoveCmd.Flags().String("dest-env", "", "Destination environment name")
	secretMoveCmd.Flags().String("env", "", "Source environment name")
	secretCopyCmd.Flags().String("dest-project", "", "Destination project name")
	secretCopyCmd.Flags().String("dest-env", "", "Destination environment name")
	secretCopyCmd.Flags().String("env", "", "Source environment name")
	secretCopyCmd.Flags().String("name", "", "Name for the copy")
	secretMoveCmd.MarkFlagRequired("dest-project")
	secretCopyCmd.MarkFlagRequired("dest-project")
}
