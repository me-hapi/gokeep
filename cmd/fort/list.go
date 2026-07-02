package main

import (
	"errors"
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/youruser/fortbyte/internal/session"
	"github.com/youruser/fortbyte/internal/vault"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Tree view of all projects, envs, and secrets",
	RunE: func(cmd *cobra.Command, _ []string) error {
		if vaultDir == "" {
			return errors.New("cannot determine home directory")
		}
		v, _, err := openVault(vaultDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		if err := session.Touch(vaultDir); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not update session: %v\n", err)
		}
		projects := v.ListProjects()
		secrets := v.ListSecrets()
		format, _ := cmd.Flags().GetString("format")
		if format == "json" {
			type secretRef struct {
				Name string `json:"name"`
				UID  string `json:"uid"`
			}
			type envNode struct {
				Name    string      `json:"name"`
				Secrets []secretRef `json:"secrets"`
			}
			type projectNode struct {
				Name    string      `json:"name"`
				Envs    []envNode   `json:"envs,omitempty"`
				Secrets []secretRef `json:"secrets,omitempty"`
			}
			type listOutput struct {
				Projects   []projectNode `json:"projects"`
				Standalone []secretRef   `json:"standalone,omitempty"`
			}
			out := listOutput{
				Projects:   make([]projectNode, 0),
				Standalone: make([]secretRef, 0),
			}
			if len(projects) > 0 {
				projectKeys := sortedKeysByName(projects, func(p vault.Project) string { return p.Name })
				for _, pUID := range projectKeys {
					p := projects[pUID]
					pn := projectNode{Name: p.Name}
					envs := v.ListEnvironmentsByProject(pUID)
					if len(envs) > 0 {
						envKeys := sortedKeysByName(envs, func(e vault.Environment) string { return e.Name })
						for _, eUID := range envKeys {
							e := envs[eUID]
							en := envNode{Name: e.Name}
							envSecrets := v.ListSecretsByProjectAndEnvironment(pUID, eUID)
							secKeys := sortedKeysByName(envSecrets, func(s vault.Secret) string { return s.Name })
							for _, sUID := range secKeys {
								s := envSecrets[sUID]
								en.Secrets = append(en.Secrets, secretRef{Name: s.Name, UID: sUID})
							}
							pn.Envs = append(pn.Envs, en)
						}
					}
					projSecrets := v.ListSecretsByProject(pUID)
					var projSecRefs []secretRef
					for sUID, s := range projSecrets {
						if s.EnvironmentUID == "" {
							projSecRefs = append(projSecRefs, secretRef{Name: s.Name, UID: sUID})
						}
					}
					sort.Slice(projSecRefs, func(i, j int) bool { return projSecRefs[i].Name < projSecRefs[j].Name })
					pn.Secrets = append(pn.Secrets, projSecRefs...)
					out.Projects = append(out.Projects, pn)
				}
			}
			var standaloneRefs []secretRef
			for sUID, s := range secrets {
				if s.ProjectUID == "" {
					standaloneRefs = append(standaloneRefs, secretRef{Name: s.Name, UID: sUID})
				}
			}
			sort.Slice(standaloneRefs, func(i, j int) bool { return standaloneRefs[i].Name < standaloneRefs[j].Name })
			out.Standalone = append(out.Standalone, standaloneRefs...)
			return printJSON(cmd.OutOrStdout(), out)
		}
		if len(projects) == 0 && len(secrets) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "No projects or secrets stored.")
			return nil
		}
		if len(projects) > 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "Projects:")
			projectKeys := sortedKeysByName(projects, func(p vault.Project) string { return p.Name })
			for _, pUID := range projectKeys {
				p := projects[pUID]
				fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", p.Name)
				envs := v.ListEnvironmentsByProject(pUID)
				if len(envs) > 0 {
					envKeys := sortedKeysByName(envs, func(e vault.Environment) string { return e.Name })
					for _, eUID := range envKeys {
						e := envs[eUID]
						fmt.Fprintf(cmd.OutOrStdout(), "    %s\n", e.Name)
						envSecrets := v.ListSecretsByProjectAndEnvironment(pUID, eUID)
						secKeys := sortedKeysByName(envSecrets, func(s vault.Secret) string { return s.Name })
						for _, sUID := range secKeys {
							s := envSecrets[sUID]
							fmt.Fprintf(cmd.OutOrStdout(), "      %s (UID: %s)\n", s.Name, shortUID(sUID))
						}
					}
				}
				projSecrets := v.ListSecretsByProject(pUID)
				secKeys := sortedKeysByName(projSecrets, func(s vault.Secret) string { return s.Name })
				for _, sUID := range secKeys {
					s := projSecrets[sUID]
					if s.EnvironmentUID == "" {
						fmt.Fprintf(cmd.OutOrStdout(), "    %s (UID: %s)\n", s.Name, shortUID(sUID))
					}
				}
			}
		}
		var standalone []secretEntry
		for sUID, s := range secrets {
			if s.ProjectUID == "" {
				standalone = append(standalone, secretEntry{name: s.Name, uid: sUID})
			}
		}
		if len(standalone) > 0 {
			if len(projects) > 0 {
				fmt.Fprintln(cmd.OutOrStdout())
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Standalone secrets:")
			sort.Slice(standalone, func(i, j int) bool { return standalone[i].name < standalone[j].name })
			for _, se := range standalone {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s (UID: %s)\n", se.name, shortUID(se.uid))
			}
		}
		return nil
	},
}

type secretEntry struct {
	name string
	uid  string
}

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.Flags().StringP("format", "o", "", "Output format: json")
}
