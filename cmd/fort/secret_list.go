package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/youruser/fortbyte/internal/session"
	"github.com/youruser/fortbyte/internal/vault"
)

var secretListCmd = &cobra.Command{
	Use:   "list",
	Short: "List secrets",
	RunE: func(cmd *cobra.Command, _ []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		projectName, _ := cmd.Flags().GetString("project")
		envName, _ := cmd.Flags().GetString("env")
		v, _, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		projectUID, envUID, err := resolveScope(v, projectName, envName)
		if err != nil {
			return err
		}
		var secrets map[string]vault.Secret
		switch {
		case projectUID != "" && envUID != "":
			secrets = v.ListSecretsByProjectAndEnvironment(projectUID, envUID)
		case projectUID != "":
			secrets = v.ListSecretsByProject(projectUID)
		default:
			secrets = v.ListSecrets()
		}
		filter, _ := cmd.Flags().GetString("filter")
		if filter != "" {
			lower := strings.ToLower(filter)
			filtered := make(map[string]vault.Secret)
			for uid, s := range secrets {
				if strings.Contains(strings.ToLower(s.Name), lower) ||
					strings.Contains(strings.ToLower(s.URL), lower) ||
					strings.Contains(strings.ToLower(s.Notes), lower) {
					filtered[uid] = s
				}
			}
			secrets = filtered
		}
		keys := sortedKeysByName(secrets, func(s vault.Secret) string { return s.Name })
		format, _ := cmd.Flags().GetString("format")
		if format == "json" {
			if len(secrets) == 0 {
				return printJSON(cmd.OutOrStdout(), []any{})
			}
			type secretItem struct {
				Name    string `json:"name"`
				UID     string `json:"uid"`
				URL     string `json:"url,omitempty"`
				Project string `json:"project,omitempty"`
				Env     string `json:"env,omitempty"`
			}
			var items []secretItem
			for _, uid := range keys {
				s := secrets[uid]
				item := secretItem{Name: s.Name, UID: uid, URL: s.URL}
				if s.ProjectUID != "" {
					if p, ok := v.GetProject(s.ProjectUID); ok {
						item.Project = p.Name
					}
				}
				if s.EnvironmentUID != "" {
					if e, ok := v.GetEnvironment(s.EnvironmentUID); ok {
						item.Env = e.Name
					}
				}
				items = append(items, item)
			}
			return printJSON(cmd.OutOrStdout(), items)
		}
		if len(secrets) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "No secrets.")
			return nil
		}
		for _, uid := range keys {
			s := secrets[uid]
			fmt.Fprintf(cmd.OutOrStdout(), "  %-20s (UID: %s)\n", s.Name, shortUID(uid))
		}
		return nil
	},
}

var secretRevealCmd = &cobra.Command{
	Use:   "reveal <name>",
	Short: "Reveal a secret's value",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		name := args[0]
		projectName, _ := cmd.Flags().GetString("project")
		envName, _ := cmd.Flags().GetString("env")
		v, _, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		projectUID, envUID, err := resolveScope(v, projectName, envName)
		if err != nil {
			return err
		}
		s, uid, found := v.FindSecretByName(name, projectUID, envUID)
		if !found {
			return fmt.Errorf("secret '%s' not found in the given scope", name)
		}
		if err := session.Touch(vaultDir); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not update session: %v\n", err)
		}
		format, _ := cmd.Flags().GetString("format")
		if format == "json" {
			type secretReveal struct {
				Name    string `json:"name"`
				UID     string `json:"uid"`
				Value   string `json:"value"`
				URL     string `json:"url,omitempty"`
				Notes   string `json:"notes,omitempty"`
				Project string `json:"project,omitempty"`
				Env     string `json:"env,omitempty"`
				Created string `json:"created"`
				Updated string `json:"updated"`
			}
			detail := secretReveal{
				Name:    s.Name,
				UID:     uid,
				Value:   s.Value,
				URL:     s.URL,
				Notes:   s.Notes,
				Created: s.CreatedAt.Format("2006-01-02 15:04:05"),
				Updated: s.UpdatedAt.Format("2006-01-02 15:04:05"),
			}
			if s.ProjectUID != "" {
				if p, ok := v.GetProject(s.ProjectUID); ok {
					detail.Project = p.Name
				}
			}
			if s.EnvironmentUID != "" {
				if e, ok := v.GetEnvironment(s.EnvironmentUID); ok {
					detail.Env = e.Name
				}
			}
			return printJSON(cmd.OutOrStdout(), detail)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Name:    %s\n", s.Name)
		fmt.Fprintf(cmd.OutOrStdout(), "UID:     %s\n", shortUID(uid))
		fmt.Fprintf(cmd.OutOrStdout(), "Value:   %s\n", s.Value)
		if s.URL != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "URL:     %s\n", s.URL)
		}
		if s.Notes != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "Notes:   %s\n", s.Notes)
		}
		if s.ProjectUID != "" {
			if p, ok := v.GetProject(s.ProjectUID); ok {
				fmt.Fprintf(cmd.OutOrStdout(), "Project: %s\n", p.Name)
			}
		}
		if s.EnvironmentUID != "" {
			if e, ok := v.GetEnvironment(s.EnvironmentUID); ok {
				fmt.Fprintf(cmd.OutOrStdout(), "Env:     %s\n", e.Name)
			}
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Created: %s\n", s.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(cmd.OutOrStdout(), "Updated: %s\n", s.UpdatedAt.Format("2006-01-02 15:04:05"))
		return nil
	},
}

var secretShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show a secret's metadata (no value)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		name := args[0]
		projectName, _ := cmd.Flags().GetString("project")
		envName, _ := cmd.Flags().GetString("env")
		v, _, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		projectUID, envUID, err := resolveScope(v, projectName, envName)
		if err != nil {
			return err
		}
		s, uid, found := v.FindSecretByName(name, projectUID, envUID)
		if !found {
			return fmt.Errorf("secret '%s' not found in the given scope", name)
		}
		if err := session.Touch(vaultDir); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not update session: %v\n", err)
		}
		format, _ := cmd.Flags().GetString("format")
		if format == "json" {
			type secretDetail struct {
				Name    string `json:"name"`
				UID     string `json:"uid"`
				URL     string `json:"url,omitempty"`
				Notes   string `json:"notes,omitempty"`
				Project string `json:"project,omitempty"`
				Env     string `json:"env,omitempty"`
				Created string `json:"created"`
				Updated string `json:"updated"`
			}
			detail := secretDetail{
				Name:    s.Name,
				UID:     uid,
				URL:     s.URL,
				Notes:   s.Notes,
				Created: s.CreatedAt.Format("2006-01-02 15:04:05"),
				Updated: s.UpdatedAt.Format("2006-01-02 15:04:05"),
			}
			if s.ProjectUID != "" {
				if p, ok := v.GetProject(s.ProjectUID); ok {
					detail.Project = p.Name
				}
			}
			if s.EnvironmentUID != "" {
				if e, ok := v.GetEnvironment(s.EnvironmentUID); ok {
					detail.Env = e.Name
				}
			}
			return printJSON(cmd.OutOrStdout(), detail)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Name:    %s\n", s.Name)
		fmt.Fprintf(cmd.OutOrStdout(), "UID:     %s\n", shortUID(uid))
		if s.URL != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "URL:     %s\n", s.URL)
		}
		if s.Notes != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "Notes:   %s\n", s.Notes)
		}
		if s.ProjectUID != "" {
			if p, ok := v.GetProject(s.ProjectUID); ok {
				fmt.Fprintf(cmd.OutOrStdout(), "Project: %s\n", p.Name)
			}
		}
		if s.EnvironmentUID != "" {
			if e, ok := v.GetEnvironment(s.EnvironmentUID); ok {
				fmt.Fprintf(cmd.OutOrStdout(), "Env:     %s\n", e.Name)
			}
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Created: %s\n", s.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(cmd.OutOrStdout(), "Updated: %s\n", s.UpdatedAt.Format("2006-01-02 15:04:05"))
		return nil
	},
}
