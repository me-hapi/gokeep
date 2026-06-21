# gokeep

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
git clone https://github.com/youruser/gokeep.git
cd gokeep
go build -o gokeep ./cmd/gokeep
```

Move the binary to a directory in your `$PATH`:

```bash
sudo mv gokeep /usr/local/bin/
```

## Usage

### Initialize a new vault

```bash
gokeep init
```

Creates `~/.gokeep/vault.enc` and prompts for a master password (min 8 characters).

### Add a secret

```bash
gokeep add <name>
```

Prompts interactively for username, password, URL (optional), and notes (optional).

### Retrieve a secret

```bash
gokeep get <name>
```

### List all secrets

```bash
gokeep list
```

### Remove a secret

```bash
gokeep remove <name>
```

### Lock the session

```bash
gokeep lock
```

Clears the cached master password from the OS keyring.

### Reset (delete everything)

```bash
gokeep reset
```

Irreversibly deletes the vault and session. Requires typing `RESET` to confirm.

## Security

| Component | Detail |
|-----------|--------|
| Key derivation | Argon2id — 64 MB memory, 3 iterations, 4 threads, 256-bit output |
| Encryption | AES-256-GCM with a fresh 12-byte random nonce per operation |
| Vault format | JSON envelope: `{"v": 1, "salt": [...], "payload": [...]}` |
| Vault location | `~/.gokeep/vault.enc` |
| File permissions | Vault `0600`, directory `0700` |
| Session | Master password stored in OS keyring, 24-hour TTL via session file mtime |

## Development

```bash
go build ./...              # Compile all packages
go test ./...               # Run all tests
go test -cover ./...        # Run tests with coverage
```

## Project Structure

```
gokeep/
├── cmd/gokeep/          # CLI entry point
├── internal/
│   ├── crypto/          # Argon2id key derivation, AES-256-GCM encrypt/decrypt
│   ├── vault/           # Vault CRUD, atomic writes, file locking
│   └── session/         # OS keyring integration, session TTL
└── AGENTS.md            # Project conventions and build commands
```

## Roadmap

- [ ] Import/export (CSV, JSON)
- [ ] Secret editing (`gokeep edit`)
- [ ] Password generator
- [ ] Clipboard integration
- [ ] REST API with OpenAPI spec
- [ ] Docker deployment
- [ ] Multi-vault support

## License

MIT
