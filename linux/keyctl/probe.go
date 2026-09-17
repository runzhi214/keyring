//go:build linux

package keyctl

import (
	"github.com/runzhi214/keyring/core"
	"golang.org/x/sys/unix"
)

// Available reports whether the kernel user keyring is usable by this
// process. It performs a pure read (create=false) with no side effects:
// it does not link keyrings or create keys. Safe to call at any frequency.
func Available() core.Availability {
	_, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_USER_KEYRING, false)
	if err != nil {
		return core.Availability{
			OK:     false,
			Reason: core.ReasonNoKeyutilsCap,
			Detail: err.Error(),
		}
	}
	return core.Availability{OK: true, Reason: core.ReasonOK}
}
