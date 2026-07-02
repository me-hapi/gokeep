package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/youruser/fortbyte/internal/vault"
)

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Manage environments within a project",
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		if cmd == envListCmd {
			return nil
		}
		projectName, _ := cmd.Flags().GetString("project")
		if projectName == "" {
			return errors.New("--project is required")
		}
		return nil
	},
}

var envAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add a new environment",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		name := args[0]
		projectName, _ := cmd.Flags().GetString("project")
		desc, _ := cmd.Flags().GetString("desc")
		notes, _ := cmd.Flags().GetString("notes")
		v, key, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		_, projectUID, found := findProjectByName(v, projectName)
		if !found {
			return fmt.Errorf("project '%s' not found", projectName)
		}
		uid, err := v.AddEnvironment(vault.Environment{
			Name:        name,
			ProjectUID:  projectUID,
			Description: desc,
			Notes:       notes,
		})
		if err != nil {
			if errors.Is(err, vault.ErrDuplicateName) {
				return fmt.Errorf("environment '%s' already exists in project '%s'", name, projectName)
			}
			return err
		}
		if err := saveVault(v, vaultDir, key, cmd.ErrOrStderr()); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Environment '%s' added (UID: %s)\n", name, shortUID(uid))
		return nil
	},
}

var envEditCmd = &cobra.Command{
	Use:   "edit <name>",
	Short: "Edit an environment",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		name := args[0]
		projectName, _ := cmd.Flags().GetString("project")
		newName, _ := cmd.Flags().GetString("name")
		desc, _ := cmd.Flags().GetString("desc")
		notes, _ := cmd.Flags().GetString("notes")
		v, key, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		_, projectUID, found := findProjectByName(v, projectName)
		if !found {
			return fmt.Errorf("project '%s' not found", projectName)
		}
		_, uid, found := findEnvironmentByName(v, name, projectUID)
		if !found {
			return fmt.Errorf("environment '%s' not found in project '%s'", name, projectName)
		}
		if cmd.Flags().Changed("name") && newName != name {
			if _, _, exists := findEnvironmentByName(v, newName, projectUID); exists {
				return fmt.Errorf("environment '%s' already exists in project '%s'", newName, projectName)
			}
		}
		v.UpdateEnvironment(uid, func(e *vault.Environment) {
			if cmd.Flags().Changed("name") {
				e.Name = newName
			}
			if cmd.Flags().Changed("desc") {
				e.Description = desc
			}
			if cmd.Flags().Changed("notes") {
				e.Notes = notes
			}
		})
		if err := saveVault(v, vaultDir, key, cmd.ErrOrStderr()); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Environment '%s' updated.\n", name)
		return nil
	},
}

var envRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove an environment",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		name := args[0]
		projectName, _ := cmd.Flags().GetString("project")
		v, key, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		_, projectUID, found := findProjectByName(v, projectName)
		if !found {
			return fmt.Errorf("project '%s' not found", projectName)
		}
		_, uid, found := findEnvironmentByName(v, name, projectUID)
		if !found {
			return fmt.Errorf("environment '%s' not found in project '%s'", name, projectName)
		}
		ok, err := confirmDeletion(cmd.OutOrStdout(), cmd.InOrStdin(), name)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(cmd.OutOrStdout(), "Cancelled.")
			return nil
		}
		if !v.RemoveEnvironment(uid) {
			return errors.New("could not remove environment")
		}
		if err := saveVault(v, vaultDir, key, cmd.ErrOrStderr()); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Environment '%s' removed.\n", name)
		return nil
	},
}

var envListCmd = &cobra.Command{
	Use:   "list",
	Short: "List environments",
	RunE: func(cmd *cobra.Command, _ []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		projectName, _ := cmd.Flags().GetString("project")
		v, _, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		var envs map[string]vault.Environment
		var projectNameForOutput string
		if projectName != "" {
			_, projectUID, found := findProjectByName(v, projectName)
			if !found {
				return fmt.Errorf("project '%s' not found", projectName)
			}
			envs = v.ListEnvironmentsByProject(projectUID)
			projectNameForOutput = projectName
		} else {
			envs = v.ListEnvironments()
		}
		keys := sortedKeysByName(envs, func(e vault.Environment) string { return e.Name })
		format, _ := cmd.Flags().GetString("format")
		if format == "json" {
			if len(envs) == 0 {
				return printJSON(cmd.OutOrStdout(), []any{})
			}
			type envItem struct {
				Name    string `json:"name"`
				UID     string `json:"uid"`
				Project string `json:"project,omitempty"`
			}
			var items []envItem
			for _, uid := range keys {
				e := envs[uid]
				item := envItem{Name: e.Name, UID: uid}
				if p, ok := v.GetProject(e.ProjectUID); ok {
					item.Project = p.Name
				}
				items = append(items, item)
			}
			return printJSON(cmd.OutOrStdout(), items)
		}
		if projectNameForOutput != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "Environments in '%s':\n", projectNameForOutput)
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "All environments:")
		}
		if len(envs) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "  (none)")
			return nil
		}
		for _, uid := range keys {
			e := envs[uid]
			fmt.Fprintf(cmd.OutOrStdout(), "  %-20s (UID: %s)\n", e.Name, shortUID(uid))
		}
		return nil
	},
}

var envShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show environment details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		name := args[0]
		projectName, _ := cmd.Flags().GetString("project")
		v, _, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		p, _, found := findProjectByName(v, projectName)
		if !found {
			return fmt.Errorf("project '%s' not found", projectName)
		}
		e, uid, found := findEnvironmentByName(v, name, p.UID)
		if !found {
			return fmt.Errorf("environment '%s' not found in project '%s'", name, projectName)
		}
		format, _ := cmd.Flags().GetString("format")
		if format == "json" {
			type secretRef struct {
				Name string `json:"name"`
				UID  string `json:"uid"`
			}
			type envDetail struct {
				Name        string      `json:"name"`
				UID         string      `json:"uid"`
				Project     string      `json:"project"`
				Description string      `json:"description,omitempty"`
				Notes       string      `json:"notes,omitempty"`
				Created     string      `json:"created"`
				Updated     string      `json:"updated"`
				Secrets     []secretRef `json:"secrets"`
			}
			detail := envDetail{
				Name:        e.Name,
				UID:         uid,
				Project:     p.Name,
				Description: e.Description,
				Notes:       e.Notes,
				Created:     e.CreatedAt.Format("2006-01-02 15:04:05"),
				Updated:     e.UpdatedAt.Format("2006-01-02 15:04:05"),
			}
			envSecrets := v.ListSecretsByProjectAndEnvironment(p.UID, uid)
			secKeys := sortedKeysByName(envSecrets, func(s vault.Secret) string { return s.Name })
			for _, sUID := range secKeys {
				s := envSecrets[sUID]
				detail.Secrets = append(detail.Secrets, secretRef{Name: s.Name, UID: sUID})
			}
			return printJSON(cmd.OutOrStdout(), detail)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Name:        %s\n", e.Name)
		fmt.Fprintf(cmd.OutOrStdout(), "UID:         %s\n", shortUID(uid))
		fmt.Fprintf(cmd.OutOrStdout(), "Project:     %s\n", p.Name)
		if e.Description != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "Description: %s\n", e.Description)
		}
		if e.Notes != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "Notes:       %s\n", e.Notes)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Created:     %s\n", e.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(cmd.OutOrStdout(), "Updated:     %s\n", e.UpdatedAt.Format("2006-01-02 15:04:05"))
		envSecrets := v.ListSecretsByProjectAndEnvironment(p.UID, uid)
		fmt.Fprintf(cmd.OutOrStdout(), "\nSecrets (%d):\n", len(envSecrets))
		if len(envSecrets) > 0 {
			secKeys := sortedKeysByName(envSecrets, func(s vault.Secret) string { return s.Name })
			for _, sUID := range secKeys {
				s := envSecrets[sUID]
				fmt.Fprintf(cmd.OutOrStdout(), "  %s (UID: %s)\n", s.Name, shortUID(sUID))
			}
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(envCmd)
	envCmd.PersistentFlags().String("project", "", "Project name")
	envCmd.AddCommand(envAddCmd, envEditCmd, envRemoveCmd, envListCmd, envShowCmd)
	envAddCmd.Flags().String("desc", "", "Description")
	envAddCmd.Flags().String("notes", "", "Notes")
	envEditCmd.Flags().String("name", "", "New name")
	envEditCmd.Flags().String("desc", "", "Description")
	envEditCmd.Flags().String("notes", "", "Notes")
	envListCmd.Flags().StringP("format", "o", "", "Output format: json")
	envShowCmd.Flags().StringP("format", "o", "", "Output format: json")
}
