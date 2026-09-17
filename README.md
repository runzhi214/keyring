# keyring

A cross-platform system keyring library for Go with honest abstractions.

## Design principles

- **Deep module**: simple interface, rich implementation. Normalization work
  belongs in the library, not the caller.
- **Honest union**: platform differences surface as typed errors, not hidden
  behind a leaky facade.
- **Context-aware**: all I/O methods accept `context.Context` — prompts,
  D-Bus calls, and subprocess invocations can be cancelled.
- **Contract-tested**: a shared `RunContractTests` suite verifies every
  backend behaves identically.

## Backends

| Platform | Backend | Persistence | ctx-aware |
|----------|---------|-------------|-----------|
| Linux | Secret Service (D-Bus) | Persistent (survives reboot) | Yes (prompt + 30s timeout) |
| Linux | Kernel keyring (KeyCtl) | Session-only (lost on reboot) | N/A (non-blocking syscalls) |
| macOS | Keychain (`/usr/bin/security`) | Persistent | *planned* |
| Windows | Credential Manager (advapi32) | Persistent | *planned* |
| All | In-memory (`mem`) | Process-only | N/A |

## Linux backend selection

`Open()` on Linux follows this priority:

1. **Secret Service (D-Bus)** — preferred. Requires `DBUS_SESSION_BUS_ADDRESS`
   pointing to a running session bus and `org.freedesktop.secrets` having an
   owner (gnome-keyring, kwallet, etc.). Secrets persist across reboots.
2. **Kernel keyring (KeyCtl)** — fallback. Requires the `keyutils` capability
   (containers may need `--cap-add=keyutils`). Secrets are visible to sibling
   processes in the same session but lost on reboot.
3. **Error** — if neither is available, `Open()` returns `*UnavailableError`.
   The caller decides whether to fall back to `mem.New()`.

The D-Bus connection is a process-level singleton with automatic reconnect.
Locked collections use an **optimistic execution** pattern: operations try
directly and retry with an unlock prompt only if the D-Bus error indicates
the collection is locked. This avoids a `isLocked` round-trip on the common
(unlocked) path.

## Quick start

```go
import (
    "context"
    "log"

    "github.com/runzhi214/keyring"
    "github.com/runzhi214/keyring/mem"
)

b, err := keyring.Open()
if err != nil {
    log.Printf("keyring unavailable: %v — falling back to in-memory", err)
    b = mem.New()
}

// Store
err = b.Set(context.Background(), "myapp", "api-key", keyring.Secret{
    Value: "sk-xxxx",
    Label: "production API key",
})

// Retrieve
secret, err := b.Get(context.Background(), "myapp", "api-key")

// List
keys, err := b.List(context.Background(), "myapp")

// Delete
err = b.Delete(context.Background(), "myapp", "api-key")
```

## License

MIT
