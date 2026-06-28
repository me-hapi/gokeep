package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/youruser/gokeep/internal/vault"
)

var exportCmd = &cobra.Command{
	Use:   "export <file>",
	Short: "Export secrets to a file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		filename := args[0]
		projectName, _ := cmd.Flags().GetString("project")
		envName, _ := cmd.Flags().GetString("env")
		format, _ := cmd.Flags().GetString("format")

		if envName != "" && projectName == "" {
			return errors.New("--env requires --project")
		}

		if format == "" {
			ext := strings.ToLower(filepath.Ext(filename))
			switch ext {
			case ".json":
				format = "json"
			case ".env":
				format = "env"
			default:
				return fmt.Errorf("cannot detect format from extension %q; use --format json or --format env", ext)
			}
		}
		if format != "json" && format != "env" {
			return fmt.Errorf("unknown format %q; use json or env", format)
		}

		// Check if file exists + overwrite prompt
		if _, err := os.Stat(filename); err == nil {
			answer, err := promptLine(cmd.OutOrStdout(), cmd.InOrStdin(),
				fmt.Sprintf("File '%s' already exists. Overwrite? (yes/no): ", filename))
			if err != nil {
				return err
			}
			answer = strings.ToLower(strings.TrimSpace(answer))
			if answer != "yes" && answer != "y" {
				fmt.Fprintln(cmd.OutOrStdout(), "Export cancelled.")
				return nil
			}
		}

		v, key, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}

		_ = key // key not needed for export (vault is only read)

		projectUID, envUID, err := resolveScope(v, projectName, envName)
		if err != nil {
			return err
		}

		var secrets map[string]vault.Secret
		if envUID != "" {
			secrets = v.ListSecretsByProjectAndEnvironment(projectUID, envUID)
		} else if projectUID != "" {
			secrets = v.ListSecretsByProject(projectUID)
		} else {
			secrets = v.ListSecrets()
		}

		if err := writeExport(filename, format, v, secrets); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Exported %d secrets to %s\n", len(secrets), filename)
		return nil
	},
}

func writeExport(filename, format string, v *vault.Vault, secrets map[string]vault.Secret) error {
	switch format {
	case "json":
		return writeJSONExport(filename, v, secrets)
	case "env":
		return writeEnvExport(filename, v, secrets)
	default:
		return fmt.Errorf("unknown format %q", format)
	}
}

type exportEntry struct {
	Name    string `json:"name"`
	Project string `json:"project,omitempty"`
	Env     string `json:"env,omitempty"`
	Value   string `json:"value"`
	URL     string `json:"url,omitempty"`
	Notes   string `json:"notes,omitempty"`
}

func writeJSONExport(filename string, v *vault.Vault, secrets map[string]vault.Secret) error {
	entries := make([]exportEntry, 0, len(secrets))
	keys := sortedKeysByName(secrets, func(s vault.Secret) string { return s.Name })
	for _, uid := range keys {
		s := secrets[uid]
		var projectName, envName string
		if s.ProjectUID != "" {
			if p, ok := v.GetProject(s.ProjectUID); ok {
				projectName = p.Name
			}
			if s.EnvironmentUID != "" {
				if e, ok := v.GetEnvironment(s.EnvironmentUID); ok {
					envName = e.Name
				}
			}
		}
		entries = append(entries, exportEntry{
			Name:    s.Name,
			Project: projectName,
			Env:     envName,
			Value:   s.Value,
			URL:     s.URL,
			Notes:   s.Notes,
		})
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	if err := os.Chmod(filename, 0600); err != nil {
		return fmt.Errorf("set file permissions: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

type envGroup struct {
	projectName string
	envName     string
	secrets     []vault.Secret
}

func writeEnvExport(filename string, v *vault.Vault, secrets map[string]vault.Secret) error {
	groups := groupByScope(v, secrets)

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	if err := os.Chmod(filename, 0600); err != nil {
		return fmt.Errorf("set file permissions: %w", err)
	}

	fw := func(format string, args ...any) error {
		_, err := fmt.Fprintf(f, format, args...)
		return err
	}

	for _, g := range groups {
		sort.Slice(g.secrets, func(i, j int) bool { return g.secrets[i].Name < g.secrets[j].Name })

		if err := fw("# Exported from gokeep\n"); err != nil {
			return fmt.Errorf("write header: %w", err)
		}
		if g.projectName == "" {
			// no-op: just the header line
		} else if g.envName == "" {
			if err := fw("# Project: %s\n", g.projectName); err != nil {
				return fmt.Errorf("write project header: %w", err)
			}
		} else {
			if err := fw("# Project: %s | Env: %s\n", g.projectName, g.envName); err != nil {
				return fmt.Errorf("write project/env header: %w", err)
			}
		}

		for _, s := range g.secrets {
			val := s.Value
			if needsQuoting(val) {
				val = quoteValue(val)
			}
			if err := fw("%s=%s\n", s.Name, val); err != nil {
				return fmt.Errorf("write secret %s: %w", s.Name, err)
			}
		}
		if err := fw("\n"); err != nil {
			return fmt.Errorf("write trailing newline: %w", err)
		}
	}

	return nil
}

// groupByScope groups secrets by (project, env) for .env export.
func groupByScope(v *vault.Vault, secrets map[string]vault.Secret) []envGroup {
	groups := make(map[string]*envGroup) // key: projectUID + "\x00" + envUID
	var order []string

	for _, s := range secrets {
		key := s.ProjectUID + "\x00" + s.EnvironmentUID
		if _, ok := groups[key]; !ok {
			var projectName, envName string
			if s.ProjectUID != "" {
				if p, ok := v.GetProject(s.ProjectUID); ok {
					projectName = p.Name
				}
				if s.EnvironmentUID != "" {
					if e, ok := v.GetEnvironment(s.EnvironmentUID); ok {
						envName = e.Name
					}
				}
			}
			groups[key] = &envGroup{projectName: projectName, envName: envName}
			order = append(order, key)
		}
		groups[key].secrets = append(groups[key].secrets, s)
	}

	result := make([]envGroup, len(order))
	for i, k := range order {
		result[i] = *groups[k]
	}
	sort.Slice(result, func(i, j int) bool {
		keyI := result[i].projectName + "\x00" + result[i].envName
		keyJ := result[j].projectName + "\x00" + result[j].envName
		return keyI < keyJ
	})
	return result
}

func needsQuoting(s string) bool {
	for _, c := range s {
		switch c {
		case ' ', '\t', '\n', '\r', '=', '#', '"', '\'':
			return true
		}
	}
	return false
}

func quoteValue(s string) string {
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	escaped = strings.ReplaceAll(escaped, "\n", `\n`)
	escaped = strings.ReplaceAll(escaped, "\r", `\r`)
	return `"` + escaped + `"`
}

func init() {
	rootCmd.AddCommand(exportCmd)
	exportCmd.Flags().String("project", "", "Project name (optional, export only this project)")
	exportCmd.Flags().String("env", "", "Environment name (requires --project)")
	exportCmd.Flags().String("format", "", "Output format: json or env (auto-detect from extension if empty)")
}
