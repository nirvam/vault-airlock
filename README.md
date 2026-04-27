# Vault-Airlock

Vault-Airlock is a secure, high-performance background daemon written in Rust that unlocks a KeePass (.kdbx) database and provides a controlled REST API over a Unix Domain Socket (UDS) to access vault contents.

Designed as a secure credential relay for isolated agents, it ensures sensitive data is never exposed over the network and is protected in memory.

## Features

- **Secure UDS Communication**: Uses Unix Domain Sockets for local-only, high-performance API access.
- **Client Identification**: Leverages Linux `SO_PEERCRED` to identify the calling process's UID.
- **Memory Safety**: Uses the `secrecy` crate to protect master passwords and entry credentials, ensuring they are zeroed on drop.
- **Audit Hooks**: Pre-hooks for access logging and Post-hooks for notifications (e.g., Feishu/Lark).
- **Systemd Integration**: Runs as a user-level service.

## Installation

### Arch Linux

```bash
cd deploy
makepkg -si
```

### From Source

```bash
make build
sudo make install
```

## Usage

### 1. Start the Daemon

```bash
vault-airlock serve --kdbx ~/vault.kdbx --socket /tmp/vault.sock
```

Or via Systemd:

```bash
systemctl --user enable --now vault-airlock.service
```

### 2. Unlock the Vault

```bash
vault-airlock unlock --socket /tmp/vault.sock
```

### 3. Access Content (Example)

You can use `curl` with the `--unix-socket` flag:

```bash
curl --unix-socket /tmp/vault.sock http://localhost/vault/tree
```

## API Reference

- `GET /health`: Heartbeat check.
- `POST /vault/unlock`: Interactively unlock the vault.
- `POST /vault/lock`: Lock the vault (clears memory).
- `GET /vault/tree`: Get hierarchical structure of the vault.
- `GET /vault/entry/{uuid}`: Get decrypted details of a specific entry.
- `POST /vault/search`: Search entries by title or tags.

## Security Considerations

- **Socket Permissions**: The UDS is created with `0o660` permissions. Ensure the daemon runs with an appropriate `umask`.
- **Memory Cleansing**: While the daemon is locked, all sensitive data is purged from memory. It is recommended to keep the vault locked when not in use.
- **Peer Identity**: The hook system can be used to enforce UID-based access policies.

## License

MIT
