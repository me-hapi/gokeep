package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/youruser/gokeep/internal/vault"
)

var findCmd = &cobra.Command{
	Use:   "find <pattern>",
	Short: "Search secrets by name, URL, or notes",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		pattern := args[0]
		projectName, _ := cmd.Flags().GetString("project")
		envName, _ := cmd.Flags().GetString("env")
		if envName != "" && projectName == "" {
			return errors.New("--env requires --project")
		}
		v, _, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		projectUID, envUID, err := resolveScope(v, projectName, envName)
		if err != nil {
			return err
		}
		results := v.SearchSecrets(pattern)
		if projectUID != "" || envUID != "" {
			filtered := make(map[string]vault.Secret)
			for uid, s := range results {
				if projectUID != "" && s.ProjectUID != projectUID {
					continue
				}
				if envUID != "" && s.EnvironmentUID != envUID {
					continue
				}
				filtered[uid] = s
			}
			results = filtered
		}
		keys := sortedKeysByName(results, func(s vault.Secret) string { return s.Name })
		format, _ := cmd.Flags().GetString("format")
		if format == "json" {
			if len(results) == 0 {
				return printJSON(cmd.OutOrStdout(), []any{})
			}
			type findResult struct {
				Name    string `json:"name"`
				UID     string `json:"uid"`
				URL     string `json:"url,omitempty"`
				Project string `json:"project,omitempty"`
				Env     string `json:"env,omitempty"`
			}
			var items []findResult
			for _, uid := range keys {
				s := results[uid]
				item := findResult{Name: s.Name, UID: shortUID(uid), URL: s.URL}
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
		if len(results) == 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "No secrets matching '%s'.\n", pattern)
			return nil
		}
		for _, uid := range keys {
			s := results[uid]
			line := fmt.Sprintf("  %-20s (UID: %s)", s.Name, shortUID(uid))
			if s.ProjectUID != "" {
				if p, ok := v.GetProject(s.ProjectUID); ok {
					line += fmt.Sprintf("  project:%s", p.Name)
				}
			}
			if s.EnvironmentUID != "" {
				if e, ok := v.GetEnvironment(s.EnvironmentUID); ok {
					line += fmt.Sprintf(" env:%s", e.Name)
				}
			}
			if s.URL != "" {
				line += fmt.Sprintf("  %s", s.URL)
			}
			fmt.Fprintln(cmd.OutOrStdout(), line)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(findCmd)
	findCmd.Flags().String("project", "", "Scope to project")
	findCmd.Flags().String("env", "", "Scope to environment")
	findCmd.Flags().StringP("format", "o", "", "Output format: json")
}
