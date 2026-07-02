// Package main is the CLI for fortbyte, a personal secrets manager.
package main

import "os"

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
