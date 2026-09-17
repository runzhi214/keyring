//go:build linux

package keyctl

import (
	"context"
	"strings"

	"golang.org/x/sys/unix"
)

// cleanupService removes all keys (including revoked ones) for a service
// from the user keyring. Unlike Delete, which uses KeyctlSearch (and thus
// cannot find revoked keys), this enumerates all keys via KEYCTL_READ and
// unlinks those matching the service prefix.
//
// This is used by test cleanup to prevent revoked keys from accumulating
// across test runs.
func cleanupService(_ context.Context, service string) error {
	infos, err := enumerateKeys()
	if err != nil {
		return err
	}

	prefix := service + ":"
	for _, info := range infos {
		if info.Type != keyType {
			continue
		}
		if !strings.HasPrefix(info.Description, prefix) {
			continue
		}
		_, _ = unix.KeyctlInt(unix.KEYCTL_UNLINK, int(info.ID), unix.KEY_SPEC_USER_KEYRING, 0, 0)
	}
	return nil
}
