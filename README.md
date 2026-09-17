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

| Platform | Backend | Persistence |
|----------|---------|-------------|
| Linux | Secret Service (D-Bus) | Persistent |
| Linux | Kernel keyring (KeyCtl) | Session-only |
| macOS | Keychain (`/usr/bin/security`) | Persistent |
| Windows | Credential Manager (advapi32) | Persistent |
| All | In-memory (`mem`) | Process-only |

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
