//go:build linux

package keyctl

import (
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	linkOnce sync.Once
	linkErr  error
)

// ensureLinked links the user keyring into the session keyring so that
// keys added by this process are visible to sibling processes in the same
// session. It also creates the user keyring if it does not yet exist.
//
// This is called lazily on the first Set, not during Available() — probing
// must remain side-effect-free. The sync.Once ensures the link operation
// runs only once per process lifetime.
func ensureLinked() error {
	linkOnce.Do(func() {
		if _, err := unix.KeyctlInt(unix.KEYCTL_LINK,
			unix.KEY_SPEC_USER_KEYRING,
			unix.KEY_SPEC_SESSION_KEYRING, 0, 0); err != nil {
			linkErr = fmt.Errorf("keyctl link user keyring: %w", err)
			return
		}
		if _, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_USER_KEYRING, true); err != nil {
			linkErr = fmt.Errorf("keyctl get user keyring id: %w", err)
			return
		}
	})
	return linkErr
}
