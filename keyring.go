// Package keyring provides a cross-platform system keyring abstraction with
// honest platform semantics.
//
// Design principles:
//   - Deep module: simple interface, rich implementation. Normalization work
//     (error mapping, availability probing, prompt handling) lives in the
//     library, not the caller.
//   - Honest union: platform differences surface as typed errors. Operations
//     unsupported on a backend return ErrUnsupportedOp rather than silently
//     behaving differently.
//   - Context-aware: all I/O methods accept context.Context so prompts,
//     D-Bus calls, and subprocess invocations can be cancelled.
//
// Use Open to get the platform's default backend. When no persistent backend
// is available, callers that tolerate secret loss may fall back to
// mem.New(); callers that must persist should surface the error.
package keyring

import (
	"context"
	"errors"
	"time"
)

// Backend is the storage interface implemented by every platform backend
// and the in-memory fallback.
type Backend interface {
	// Available reports whether the backend is ready for use without
	// performing side effects. It is safe to call at any frequency.
	Available() Availability

	// Get retrieves a secret. Returns *NotFoundError when the key does not
	// exist. Returns *LockedError when the keyring is locked and a prompt
	// is required. Returns *PromptDismissedError when the user dismissed
	// the unlock prompt. The context may cancel a blocking prompt.
	Get(ctx context.Context, service, key string) (Secret, error)

	// Set stores a secret. Returns *TooBigError when the payload exceeds
	// the platform limit. Returns *LockedError or *PromptDismissedError
	// when a prompt is needed and fails. The context may cancel a blocking
	// prompt.
	Set(ctx context.Context, service, key string, s Secret) error

	// Delete removes a secret. It is idempotent: deleting a non-existent
	// key returns nil.
	Delete(ctx context.Context, service, key string) error

	// List returns the keys stored under a service. Returns
	// ErrUnsupportedOp when the backend cannot enumerate keys.
	List(ctx context.Context, service string) ([]string, error)

	// Persistence reports the durability guarantee of the backend.
	Persistence() Persistence
}

// Secret represents a stored credential with optional metadata.
//
// Fields beyond Value are best-effort: backends populate what they can and
// leave the rest as zero values. Callers should not assume any metadata
// field is non-zero unless they stored it themselves.
type Secret struct {
	// Value is the secret payload. Must be non-empty; Set refuses empty
	// values to prevent accidental credential deletion.
	Value string

	// Label is a human-readable description. Supported by Secret Service,
	// macOS Keychain, and the in-memory store. Ignored by keyctl and
	// Windows Credential Manager (stored in UserName field).
	Label string

	// Attributes are searchable key-value pairs. Supported natively by
	// Secret Service. Stored but not searchable on other backends.
	Attributes map[string]string

	// Created is the timestamp when the secret was first stored.
	// Best-effort: zero when the backend does not record it.
	Created time.Time

	// Modified is the timestamp of the last Set call.
	// Best-effort: zero when the backend does not record it.
	Modified time.Time
}

// Availability describes whether a backend is usable and why not.
type Availability struct {
	OK     bool
	Reason UnavailableReason
	Detail string
}

// UnavailableReason categorizes why a backend is unavailable.
type UnavailableReason int

const (
	// ReasonOK means the backend is available.
	ReasonOK UnavailableReason = 0

	// ReasonNoSessionBus: DBUS_SESSION_BUS_ADDRESS is empty or "autolaunch:"
	// (Linux Secret Service).
	ReasonNoSessionBus UnavailableReason = 1

	// ReasonNoSecretService: org.freedesktop.secrets has no owner on the
	// session bus (Linux Secret Service).
	ReasonNoSecretService UnavailableReason = 2

	// ReasonNoKeyutilsCap: the kernel does not support keyrings for this
	// process, e.g. a container lacking the keyutils capability
	// (Linux keyctl).
	ReasonNoKeyutilsCap UnavailableReason = 3

	// ReasonNoKeychain: the macOS security CLI is missing or reports an
	// unexpected error during probing.
	ReasonNoKeychain UnavailableReason = 4

	// ReasonUnsupportedPlatform: the OS has no backend implementation.
	ReasonUnsupportedPlatform UnavailableReason = 5
)

func (r UnavailableReason) String() string {
	switch r {
	case ReasonOK:
		return "ok"
	case ReasonNoSessionBus:
		return "no D-Bus session bus"
	case ReasonNoSecretService:
		return "no Secret Service owner"
	case ReasonNoKeyutilsCap:
		return "no kernel keyring capability"
	case ReasonNoKeychain:
		return "no keychain"
	case ReasonUnsupportedPlatform:
		return "unsupported platform"
	default:
		return "unknown"
	}
}

// Persistence describes the durability guarantee of a backend.
type Persistence int

const (
	// Persistent: secrets survive process restarts and system reboots
	// (macOS Keychain, Windows Credential Manager, Secret Service with
	// gnome-keyring).
	Persistent Persistence = iota

	// SessionOnly: secrets are visible to sibling processes in the same
	// session but do not survive reboot (Linux kernel keyring).
	SessionOnly

	// ProcessOnly: secrets exist only in the current process and are lost
	// on exit (in-memory store).
	ProcessOnly
)

func (p Persistence) String() string {
	switch p {
	case Persistent:
		return "persistent"
	case SessionOnly:
		return "session-only"
	case ProcessOnly:
		return "process-only"
	default:
		return "unknown"
	}
}

// --- Typed errors ---

// NotFoundError is returned by Get when the key does not exist.
type NotFoundError struct {
	Service string
	Key     string
}

func (e *NotFoundError) Error() string {
	return "keyring: secret not found for service " + e.Service + ", key " + e.Key
}

// LockedError is returned when the keyring or collection is locked and
// cannot be unlocked, or the unlock prompt failed.
type LockedError struct {
	Service string
	Detail  string
}

func (e *LockedError) Error() string {
	return "keyring: collection locked for service " + e.Service + ": " + e.Detail
}

// PromptDismissedError is returned when the user dismissed the unlock or
// store prompt.
type PromptDismissedError struct {
	Service string
	Key     string
}

func (e *PromptDismissedError) Error() string {
	return "keyring: prompt dismissed for service " + e.Service + ", key " + e.Key
}

// TooBigError is returned by Set when the payload exceeds the platform
// size limit.
type TooBigError struct {
	Limit   int
	Actual  int
	Platform string
}

func (e *TooBigError) Error() string {
	return "keyring: payload too big for " + e.Platform + " (" + itoa(e.Actual) + " > " + itoa(e.Limit) + " bytes)"
}

// UnavailableError is returned by Open when no persistent backend can be
// initialized.
type UnavailableError struct {
	Reason UnavailableReason
	Detail string
}

func (e *UnavailableError) Error() string {
	return "keyring: backend unavailable: " + e.Reason.String() + " (" + e.Detail + ")"
}

// ErrUnsupportedOp is returned by operations a backend cannot perform
// (e.g. List on a backend without enumeration capability).
var ErrUnsupportedOp = errors.New("keyring: operation not supported on this backend")

// ErrEmptyValue is returned by Set when the secret value is empty.
var ErrEmptyValue = errors.New("keyring: refusing to store an empty value (use Delete to remove)")

// itoa avoids importing strconv just for error formatting.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
