package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/youruser/fortbyte/internal/vault"
)

const maxImportSize = 10 << 20 // 10 MB

var importCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import secrets from a file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		filename := args[0]
		projectName, _ := cmd.Flags().GetString("project")
		envName, _ := cmd.Flags().GetString("env")
		format, _ := cmd.Flags().GetString("format")

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

		if envName != "" && projectName == "" {
			return errors.New("--project is required when --env is specified")
		}
		// .env import requires --project
		if format == "env" && projectName == "" {
			return errors.New("--project is required for .env import")
		}

		v, key, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}

		var entries []importEntry
		switch format {
		case "json":
			entries, err = readJSONImport(filename)
		case "env":
			entries, err = readEnvImport(filename)
		}
		if err != nil {
			return err
		}

		stats := processImport(v, entries, projectName, envName, format, cmd.ErrOrStderr())
		printImportSummary(cmd.OutOrStdout(), stats)

		// Only save if we actually changed something
		if stats.added > 0 {
			if err := saveVault(v, vaultDir, key, cmd.ErrOrStderr()); err != nil {
				return err
			}
		}

		return nil
	},
}

// importEntry is a parsed secret ready for import.
type importEntry struct {
	Name    string
	Project string
	Env     string
	Value   string
	URL     string
	Notes   string
}

type importStats struct {
	added            int
	skipped          int
	skippedNames     []string
	errored          int
	errorDetails     []string // "name: error"
	addedByScopeDesc map[string]int
}

func readJSONImport(filename string) ([]importEntry, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	lr := io.LimitReader(f, maxImportSize)
	var raw []exportEntry
	if err := json.NewDecoder(lr).Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}

	entries := make([]importEntry, len(raw))
	for i, e := range raw {
		entries[i] = importEntry{
			Name:    e.Name,
			Project: e.Project,
			Env:     e.Env,
			Value:   e.Value,
			URL:     e.URL,
			Notes:   e.Notes,
		}
	}
	return entries, nil
}

func readEnvImport(filename string) ([]importEntry, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	lr := io.LimitReader(f, maxImportSize)
	var entries []importEntry
	scanner := bufio.NewScanner(lr)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		val = stripQuotes(val)
		if key == "" {
			continue
		}
		entries = append(entries, importEntry{Name: key, Value: val})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return entries, nil
}

func stripQuotes(s string) string {
	if len(s) >= 2 {
		if s[0] == '"' && s[len(s)-1] == '"' {
			inner := s[1 : len(s)-1]
			// Unescape double-quoted .env values (reverse of quoteValue in export.go)
			inner = strings.ReplaceAll(inner, `\\`, "\x00") // temporary placeholder
			inner = strings.ReplaceAll(inner, `\"`, `"`)
			inner = strings.ReplaceAll(inner, `\n`, "\n")
			inner = strings.ReplaceAll(inner, `\r`, "\r")
			inner = strings.ReplaceAll(inner, "\x00", `\`) // restore escaped backslashes
			return inner
		}
		if s[0] == '\'' && s[len(s)-1] == '\'' {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// processImport imports entries into the vault and returns stats.
func processImport(v *vault.Vault, entries []importEntry, overrideProject, overrideEnv, format string, errOut io.Writer) importStats {
	stats := importStats{
		addedByScopeDesc: make(map[string]int),
	}

	for _, e := range entries {
		var projectUID, envUID string
		var projectName, envName string

		if format == "env" || (format == "json" && overrideProject != "") {
			// Use the CLI flag overrides
			projectName = overrideProject
			_, pUID, found := findProjectByName(v, projectName)
			if !found {
				stats.errored++
				stats.errorDetails = append(stats.errorDetails, fmt.Sprintf("%s: project '%s' not found", e.Name, projectName))
				continue
			}
			projectUID = pUID

			if overrideEnv != "" {
				envName = overrideEnv
				_, eUID, found := findEnvironmentByName(v, envName, projectUID)
				if !found {
					stats.errored++
					stats.errorDetails = append(stats.errorDetails, fmt.Sprintf("%s: environment '%s' not found in project '%s'", e.Name, envName, projectName))
					continue
				}
				envUID = eUID
			}
		} else {
			// JSON: resolve/create from entry fields
			if e.Project != "" {
				p, pUID, found := findProjectByName(v, e.Project)
				if !found {
					var err error
					pUID, err = v.AddProject(vault.Project{Name: e.Project})
					if err != nil {
						stats.errored++
						stats.errorDetails = append(stats.errorDetails, fmt.Sprintf("%s: create project '%s': %v", e.Name, e.Project, err))
						continue
					}
					p = vault.Project{Name: e.Project} // for display
				}
				projectUID = pUID
				projectName = p.Name

				if e.Env != "" {
					ev, eUID, found := findEnvironmentByName(v, e.Env, projectUID)
					if !found {
						var err error
						eUID, err = v.AddEnvironment(vault.Environment{Name: e.Env, ProjectUID: projectUID})
						if err != nil {
							stats.errored++
							stats.errorDetails = append(stats.errorDetails, fmt.Sprintf("%s: create env '%s': %v", e.Name, e.Env, err))
							continue
						}
						ev = vault.Environment{Name: e.Env} // for display
					}
					envUID = eUID
					envName = ev.Name
				}
			}
		}

		// Check duplicate
		if _, _, found := v.FindSecretByName(e.Name, projectUID, envUID); found {
			stats.skipped++
			stats.skippedNames = append(stats.skippedNames, e.Name)
			continue
		}

		_, err := v.AddSecret(vault.Secret{
			Name:           e.Name,
			ProjectUID:     projectUID,
			EnvironmentUID: envUID,
			Value:          e.Value,
			URL:            e.URL,
			Notes:          e.Notes,
		})
		if err != nil {
			stats.errored++
			stats.errorDetails = append(stats.errorDetails, fmt.Sprintf("%s: %v", e.Name, err))
			continue
		}

		stats.added++
		scopeDesc := scopeDescription(projectName, envName)
		stats.addedByScopeDesc[scopeDesc]++
		_ = errOut // ponytail: unused param but signature is for future
	}

	return stats
}

func scopeDescription(projectName, envName string) string {
	if projectName == "" {
		return "(no project)"
	}
	if envName == "" {
		return projectName
	}
	return projectName + "/" + envName
}

func printImportSummary(w io.Writer, stats importStats) {
	fmt.Fprintln(w, "Import complete:")
	if stats.added > 0 {
		var parts []string
		for scope, n := range stats.addedByScopeDesc {
			parts = append(parts, fmt.Sprintf("%d to %s", n, scope))
		}
		fmt.Fprintf(w, "  Added:   %d secrets (%s)\n", stats.added, strings.Join(parts, ", "))
	} else {
		fmt.Fprintln(w, "  Added:   0 secrets")
	}
	if stats.skipped > 0 {
		fmt.Fprintf(w, "  Skipped: %d secrets (already exist): %s\n", stats.skipped, strings.Join(stats.skippedNames, ", "))
	}
	if stats.errored > 0 {
		for _, detail := range stats.errorDetails {
			fmt.Fprintf(w, "  Error:   %s\n", detail)
		}
	}
}

func init() {
	rootCmd.AddCommand(importCmd)
	importCmd.Flags().String("project", "", "Project name (required for .env; optional override for json)")
	importCmd.Flags().String("env", "", "Environment name (optional override)")
	importCmd.Flags().String("format", "", "Input format: json or env (auto-detect from extension if empty)")
}
