//go:build linux

package keyctl

import (
	"context"
	"fmt"

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
	keyringID, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_USER_KEYRING, false)
	if err != nil {
		return fmt.Errorf("keyctl get keyring id: %w", err)
	}
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, keyringID, nil, 0)
	if err != nil {
		return fmt.Errorf("keyctl read (probe): %w", err)
	}
	if n == 0 {
		return nil
	}
	buf := make([]byte, n)
	read, err := unix.KeyctlBuffer(unix.KEYCTL_READ, keyringID, buf, 0)
	if err != nil {
		return fmt.Errorf("keyctl read: %w", err)
	}

	prefix := service + ":"
	for i := 0; i+4 <= read; i += 4 {
		id := int32(buf[i]) | int32(buf[i+1])<<8 | int32(buf[i+2])<<16 | int32(buf[i+3])<<24
		descStr, err := unix.KeyctlString(unix.KEYCTL_DESCRIBE, int(id))
		if err != nil {
			_, _ = unix.KeyctlInt(unix.KEYCTL_UNLINK, int(id), unix.KEY_SPEC_USER_KEYRING, 0, 0)
			continue
		}
		parts := splitDesc(descStr)
		if len(parts) < 5 || parts[0] != keyType {
			continue
		}
		description := parts[4]
		if hasPrefix(description, prefix) {
			_, _ = unix.KeyctlInt(unix.KEYCTL_UNLINK, int(id), unix.KEY_SPEC_USER_KEYRING, 0, 0)
		}
	}
	return nil
}

func splitDesc(s string) []string {
	result := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ';' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}

func hasPrefix(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return s[:len(prefix)] == prefix
}
