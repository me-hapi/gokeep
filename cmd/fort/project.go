package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/youruser/fortbyte/internal/vault"
)

var projectCmd = &cobra.Command{
	Use:   "project",
	Short: "Manage projects",
}

var projectAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add a new project",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		name := args[0]
		desc, _ := cmd.Flags().GetString("desc")
		url, _ := cmd.Flags().GetString("url")
		notes, _ := cmd.Flags().GetString("notes")
		v, key, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		uid, err := v.AddProject(vault.Project{
			Name:        name,
			Description: desc,
			URL:         url,
			Notes:       notes,
		})
		if err != nil {
			if errors.Is(err, vault.ErrDuplicateName) {
				return fmt.Errorf("project '%s' already exists", name)
			}
			return err
		}
		if err := saveVault(v, vaultDir, key, cmd.ErrOrStderr()); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Project '%s' added (UID: %s)\n", name, shortUID(uid))
		return nil
	},
}

var projectEditCmd = &cobra.Command{
	Use:   "edit <name>",
	Short: "Edit a project",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		name := args[0]
		newName, _ := cmd.Flags().GetString("name")
		desc, _ := cmd.Flags().GetString("desc")
		url, _ := cmd.Flags().GetString("url")
		notes, _ := cmd.Flags().GetString("notes")
		v, key, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		_, uid, found := findProjectByName(v, name)
		if !found {
			return fmt.Errorf("project '%s' not found", name)
		}
		if cmd.Flags().Changed("name") && newName != name {
			if _, _, exists := findProjectByName(v, newName); exists {
				return fmt.Errorf("project '%s' already exists", newName)
			}
		}
		v.UpdateProject(uid, func(p *vault.Project) {
			if cmd.Flags().Changed("name") {
				p.Name = newName
			}
			if cmd.Flags().Changed("desc") {
				p.Description = desc
			}
			if cmd.Flags().Changed("url") {
				p.URL = url
			}
			if cmd.Flags().Changed("notes") {
				p.Notes = notes
			}
		})
		if err := saveVault(v, vaultDir, key, cmd.ErrOrStderr()); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Project '%s' updated.\n", name)
		return nil
	},
}

var projectRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a project",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		name := args[0]
		v, key, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		_, uid, found := findProjectByName(v, name)
		if !found {
			return fmt.Errorf("project '%s' not found", name)
		}
		ok, err := confirmDeletion(cmd.OutOrStdout(), cmd.InOrStdin(), name)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(cmd.OutOrStdout(), "Cancelled.")
			return nil
		}
		if !v.RemoveProject(uid) {
			return errors.New("could not remove project")
		}
		if err := saveVault(v, vaultDir, key, cmd.ErrOrStderr()); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Project '%s' removed.\n", name)
		return nil
	},
}

var projectListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all projects",
	RunE: func(cmd *cobra.Command, _ []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		v, _, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		projects := v.ListProjects()
		keys := sortedKeysByName(projects, func(p vault.Project) string { return p.Name })
		format, _ := cmd.Flags().GetString("format")
		if format == "json" {
			if len(projects) == 0 {
				return printJSON(cmd.OutOrStdout(), []any{})
			}
			type projectItem struct {
				Name        string `json:"name"`
				UID         string `json:"uid"`
				Description string `json:"description,omitempty"`
				URL         string `json:"url,omitempty"`
			}
			var items []projectItem
			for _, uid := range keys {
				p := projects[uid]
				items = append(items, projectItem{Name: p.Name, UID: uid, Description: p.Description, URL: p.URL})
			}
			return printJSON(cmd.OutOrStdout(), items)
		}
		if len(projects) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "No projects.")
			return nil
		}
		for _, uid := range keys {
			p := projects[uid]
			fmt.Fprintf(cmd.OutOrStdout(), "  %-20s (UID: %s)\n", p.Name, shortUID(uid))
		}
		return nil
	},
}

var projectShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show project details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		name := args[0]
		v, _, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		p, uid, found := findProjectByName(v, name)
		if !found {
			return fmt.Errorf("project '%s' not found", name)
		}
		format, _ := cmd.Flags().GetString("format")
		if format == "json" {
			type envRef struct {
				Name string `json:"name"`
				UID  string `json:"uid"`
			}
			type projectDetail struct {
				Name         string   `json:"name"`
				UID          string   `json:"uid"`
				Description  string   `json:"description,omitempty"`
				URL          string   `json:"url,omitempty"`
				Notes        string   `json:"notes,omitempty"`
				Created      string   `json:"created"`
				Updated      string   `json:"updated"`
				Environments []envRef `json:"environments"`
				SecretCount  int      `json:"secret_count"`
			}
			detail := projectDetail{
				Name:        p.Name,
				UID:         uid,
				Description: p.Description,
				URL:         p.URL,
				Notes:       p.Notes,
				Created:     p.CreatedAt.Format("2006-01-02 15:04:05"),
				Updated:     p.UpdatedAt.Format("2006-01-02 15:04:05"),
			}
			envs := v.ListEnvironmentsByProject(uid)
			envKeys := sortedKeysByName(envs, func(e vault.Environment) string { return e.Name })
			for _, eUID := range envKeys {
				e := envs[eUID]
				detail.Environments = append(detail.Environments, envRef{Name: e.Name, UID: eUID})
			}
			detail.SecretCount = len(v.ListSecretsByProject(uid))
			return printJSON(cmd.OutOrStdout(), detail)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Name:        %s\n", p.Name)
		fmt.Fprintf(cmd.OutOrStdout(), "UID:         %s\n", shortUID(uid))
		if p.Description != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "Description: %s\n", p.Description)
		}
		if p.URL != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "URL:         %s\n", p.URL)
		}
		if p.Notes != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "Notes:       %s\n", p.Notes)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Created:     %s\n", p.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(cmd.OutOrStdout(), "Updated:     %s\n", p.UpdatedAt.Format("2006-01-02 15:04:05"))
		envs := v.ListEnvironmentsByProject(uid)
		fmt.Fprintf(cmd.OutOrStdout(), "\nEnvironments (%d):\n", len(envs))
		if len(envs) > 0 {
			envKeys := sortedKeysByName(envs, func(e vault.Environment) string { return e.Name })
			for _, eUID := range envKeys {
				e := envs[eUID]
				fmt.Fprintf(cmd.OutOrStdout(), "  %s (UID: %s)\n", e.Name, shortUID(eUID))
			}
		}
		projSecrets := v.ListSecretsByProject(uid)
		fmt.Fprintf(cmd.OutOrStdout(), "\nSecrets: %d\n", len(projSecrets))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(projectCmd)
	projectCmd.AddCommand(projectAddCmd, projectEditCmd, projectRemoveCmd, projectListCmd, projectShowCmd)
	projectAddCmd.Flags().String("desc", "", "Description")
	projectAddCmd.Flags().String("url", "", "URL")
	projectAddCmd.Flags().String("notes", "", "Notes")
	projectEditCmd.Flags().String("name", "", "New name")
	projectEditCmd.Flags().String("desc", "", "Description")
	projectEditCmd.Flags().String("url", "", "URL")
	projectEditCmd.Flags().String("notes", "", "Notes")
	projectListCmd.Flags().StringP("format", "o", "", "Output format: json")
	projectShowCmd.Flags().StringP("format", "o", "", "Output format: json")
}
