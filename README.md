# fortbyte

A personal secrets manager CLI built in Go. Stores encrypted credentials (username/password pairs with optional URL and notes) in a local vault file, unlocked with a master password.

## Features

- **AES-256-GCM** encryption with **Argon2id** key derivation
- Master password cached in the **OS keyring** (macOS Keychain, Linux Secret Service, Windows Credential Manager) with a 24-hour session
- Atomic vault writes with file locking to prevent corruption
- Restrictive file permissions (`0600` vault, `0700` directory)
- Zero external services — everything stays on your machine

## Prerequisites

- Go 1.22+
- A supported OS keyring backend:
  - **macOS**: Keychain (built-in)
  - **Linux**: `secret-tool` (libsecret) or GNOME Keyring / KDE Wallet
  - **Windows**: Credential Manager (built-in)

## Installation

### From source

```bash
git clone https://github.com/youruser/fortbyte.git
cd fortbyte
go build -o fort ./cmd/fort
```

Move the binary to a directory in your `$PATH`:

```bash
sudo mv fort /usr/local/bin/
```

## Usage

### Initialize a new vault

```bash
fort init
```

Creates `~/.fort/vault.enc` and prompts for a master password (min 8 characters).

### Manage projects

```bash
fort project add <name>       # Add a new project
fort project edit <name>      # Edit a project
fort project remove <name>    # Remove a project (cascading delete)
fort project list             # List all projects
fort project show <name>      # Show project details
```

### Manage environments

```bash
fort env add <name> --project <name>      # Add an environment to a project
fort env edit <name> --project <name>     # Edit an environment
fort env remove <name> --project <name>   # Remove an environment
fort env list [--project <name>]          # List environments (optionally filtered by project)
fort env show <name> --project <name>     # Show environment details
```

### Manage secrets

```bash
fort secret add <name> --project <name> [--env <name>]      # Add a secret
fort secret edit <name> --project <name> [--env <name>]     # Edit a secret
fort secret remove <name> --project <name> [--env <name>]   # Remove a secret
fort secret list [--project <name>] [--env <name>]          # List secrets
fort secret reveal <name> --project <name> [--env <name>]   # Reveal a secret's value
fort secret show <name> --project <name> [--env <name>]     # Show secret metadata (no value)
```

### Other commands

```bash
fort list        # Tree view of projects, envs, and secrets
fort status      # Show vault state, session expiry, and counts
fort lock        # Clear the cached master password from the OS keyring
fort reset       # Irreversibly delete the vault and all secrets (requires typing RESET)
```

## Security

| Component | Detail |
|-----------|--------|
| Key derivation | Argon2id — 64 MB memory, 3 iterations, 4 threads, 256-bit output |
| Encryption | AES-256-GCM with a fresh 12-byte random nonce per operation |
| Vault format | JSON envelope: `{"v": 1, "salt": [...], "payload": [...]}` |
| Vault location | `~/.fort/vault.enc` |
| File permissions | Vault `0600`, directory `0700` |
| Session | Master password stored in OS keyring, 24-hour TTL via session file mtime |

## Development

```bash
go build ./...              # Compile all packages
go test ./...               # Run all tests
go test -cover ./...        # Run tests with coverage
```

## Project Structure

```text
fortbyte/
├── cmd/fort/          # CLI entry point
├── internal/
│   ├── crypto/          # Argon2id key derivation, AES-256-GCM encrypt/decrypt
│   ├── vault/           # Vault CRUD, atomic writes, file locking
│   └── session/         # OS keyring integration, session TTL
└── AGENTS.md            # Project conventions and build commands
```

## Roadmap

- [x] Import/export (.env, JSON)
- [x] Secret move/copy between environments
- [x] Secret search (`fort find`, `--filter` on list)
- [x] Secret show (metadata without value)
- [x] Cobra CLI migration
- [ ] JSON output for list/show/reveal (`--format=json`)
- [ ] Password generator
- [ ] Clipboard integration
- [ ] REST API with OpenAPI spec
- [ ] Docker deployment
- [ ] Multi-vault support

## License

MIT
