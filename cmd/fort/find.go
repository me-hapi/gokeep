package main

import (
	"fmt"

	"github.com/youruser/fortbyte/internal/vault"
)

// findProjectByName returns (project, uid, found).
func findProjectByName(v *vault.Vault, name string) (vault.Project, string, bool) {
	for uid, p := range v.ListProjects() {
		if p.Name == name {
			return p, uid, true
		}
	}
	return vault.Project{}, "", false
}

// findEnvironmentByName returns (env, uid, found) scoped to projectUID.
func findEnvironmentByName(v *vault.Vault, name, projectUID string) (vault.Environment, string, bool) {
	for uid, e := range v.ListEnvironments() {
		if e.Name == name && e.ProjectUID == projectUID {
			return e, uid, true
		}
	}
	return vault.Environment{}, "", false
}

// resolveScope maps projectName/envName to UIDs, returning user-facing errors
// when not found. Pass empty strings to skip a lookup.
func resolveScope(v *vault.Vault, projectName, envName string) (string, string, error) {
	var projectUID, envUID string
	if projectName != "" {
		_, pUID, found := findProjectByName(v, projectName)
		if !found {
			return "", "", fmt.Errorf("project '%s' not found", projectName)
		}
		projectUID = pUID
	}
	if envName != "" {
		_, eUID, found := findEnvironmentByName(v, envName, projectUID)
		if !found {
			return "", "", fmt.Errorf("environment '%s' not found in project '%s'", envName, projectName)
		}
		envUID = eUID
	}
	return projectUID, envUID, nil
}
