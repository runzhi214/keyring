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
//
// The shared types (Backend, Secret, Availability, etc.) are defined in the
// core sub-package and re-exported here as type aliases. This breaks what
// would otherwise be an import cycle: the top-level package imports platform
// backends, and backends import the types from core.
package keyring

import (
	"github.com/runzhi214/keyring/core"
)

type (
	Backend         = core.Backend
	Secret          = core.Secret
	Availability    = core.Availability
	Persistence     = core.Persistence
	UnavailableReason = core.UnavailableReason
	NotFoundError   = core.NotFoundError
	LockedError     = core.LockedError
	PromptDismissedError = core.PromptDismissedError
	TooBigError     = core.TooBigError
	UnavailableError = core.UnavailableError
)

const (
	ReasonOK                  = core.ReasonOK
	ReasonNoSessionBus        = core.ReasonNoSessionBus
	ReasonNoSecretService     = core.ReasonNoSecretService
	ReasonNoKeyutilsCap       = core.ReasonNoKeyutilsCap
	ReasonNoKeychain          = core.ReasonNoKeychain
	ReasonUnsupportedPlatform = core.ReasonUnsupportedPlatform
)

const (
	Persistent   = core.Persistent
	SessionOnly  = core.SessionOnly
	ProcessOnly  = core.ProcessOnly
)

var (
	ErrUnsupportedOp = core.ErrUnsupportedOp
	ErrEmptyValue    = core.ErrEmptyValue
)
