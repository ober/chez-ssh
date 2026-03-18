# chez-ssh

An SSH agent library for Chez Scheme. Implements the SSH agent protocol (draft-miller-ssh-agent) with Ed25519 key support.

Private keys are stored in `mlock`'d C memory and never enter the Scheme heap. Signing happens entirely in C via OpenSSL — only signatures cross the FFI boundary.

## Features

- **SSH agent protocol** — compatible with `ssh`, `git`, `scp`, `rsync`, `ansible`, etc.
- **Ed25519 keys** — parse OpenSSH private key format, load raw seeds
- **Secure key storage** — `mlock()`, `MADV_DONTDUMP`, `explicit_bzero()`
- **Background socket server** — runs in a pthread, sets `SSH_AUTH_SOCK`
- **Zero external dependencies** beyond OpenSSL and pthreads

## Prerequisites

- Chez Scheme 10.x
- OpenSSL libcrypto (`libssl-dev` / `openssl-devel`)
- GCC, pthreads

## Building

```bash
make        # builds chez_ssh_shim.so
make test   # runs test suite (generates temp key, starts agent, checks ssh-add)
```

## Usage

```scheme
(import (chez-ssh))

;; Load an Ed25519 key
(ssh-agent-load-key-file "~/.ssh/id_ed25519")

;; Start the agent (creates Unix socket, sets SSH_AUTH_SOCK)
(ssh-agent-start)

;; Now ssh, git, etc. will use this agent:
;;   ssh user@host         → agent signs the challenge
;;   git push              → agent signs for git's SSH transport

;; List loaded keys
(ssh-agent-list-keys)
;; → ((0 "user@host" "aabbccdd..."))

;; Stop the agent (zeros keys, removes socket)
(ssh-agent-stop)
```

## API

### Key Management

| Function | Description |
|----------|-------------|
| `(ssh-agent-load-key-file path)` | Load Ed25519 key from OpenSSH file. Returns index or `#f`. |
| `(ssh-agent-load-openssh-key bv)` | Load from bytevector (file contents). Returns index or `#f`. |
| `(ssh-agent-load-ed25519-seed seed comment)` | Load from raw 32-byte seed. Returns index or `#f`. |
| `(ssh-agent-key-count)` | Number of loaded keys. |
| `(ssh-agent-key-info idx)` | Returns `(comment . pubkey-hex)` or `#f`. |
| `(ssh-agent-list-keys)` | Returns list of `(index comment pubkey-hex)`. |
| `(ssh-agent-remove-key! idx)` | Remove and zero a key. |
| `(ssh-agent-remove-all-keys!)` | Remove and zero all keys. |

### Agent Lifecycle

| Function | Description |
|----------|-------------|
| `(ssh-agent-start)` | Start agent socket, set `SSH_AUTH_SOCK`. |
| `(ssh-agent-start dir)` | Start with custom socket directory. |
| `(ssh-agent-stop)` | Stop agent, zero keys, remove socket. |
| `(ssh-agent-running?)` | Is the agent running? |
| `(ssh-agent-socket-path)` | Socket path string, or `#f`. |

## Security

- Private key seeds live in `mlock`'d, `MADV_DONTDUMP` memory — never swapped, never in core dumps
- Keys are zeroed with `explicit_bzero()` on removal and agent stop
- Ed25519 signing happens in C via OpenSSL — seeds never cross the FFI boundary
- Socket is `chmod 0600` (owner-only access)
- Socket directory and file are cleaned up on stop
