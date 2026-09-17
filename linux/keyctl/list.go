//go:build linux

package keyctl

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// List returns the keys stored under a service in the kernel user keyring.
//
// It reads the key ID list from the user keyring via KEYCTL_READ, then
// calls KEYCTL_DESCRIBE on each key ID to get its type and description.
// Keys whose type is "user" and whose description starts with
// "<service>:" are included; the suffix after the colon is returned as
// the key name.
func (b *Backend) List(_ context.Context, service string) ([]string, error) {
	keyringID, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_USER_KEYRING, false)
	if err != nil {
		return nil, fmt.Errorf("keyctl get keyring id: %w", err)
	}

	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, keyringID, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("keyctl read (probe): %w", err)
	}
	if n == 0 {
		return nil, nil
	}

	buf := make([]byte, n)
	read, err := unix.KeyctlBuffer(unix.KEYCTL_READ, keyringID, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("keyctl read: %w", err)
	}

	keyIDs := parseKeyIDs(buf[:read])
	prefix := service + ":"

	var keys []string
	for _, id := range keyIDs {
		descStr, err := unix.KeyctlString(unix.KEYCTL_DESCRIBE, int(id))
		if err != nil {
			if errors.Is(err, unix.ENOKEY) || errors.Is(err, unix.ENOENT) {
				continue
			}
			continue
		}
		// Format: "type;uid;gid;perm;description"
		parts := strings.SplitN(descStr, ";", 5)
		if len(parts) < 5 {
			continue
		}
		if parts[0] != keyType {
			continue
		}
		description := parts[4]
		if !strings.HasPrefix(description, prefix) {
			continue
		}
		keys = append(keys, description[len(prefix):])
	}
	return keys, nil
}

// parseKeyIDs parses a KEYCTL_READ buffer into a slice of key IDs.
// The buffer contains a list of key serial numbers as native-endian
// int32 values.
func parseKeyIDs(buf []byte) []int32 {
	if len(buf) < 4 {
		return nil
	}
	count := len(buf) / 4
	ids := make([]int32, 0, count)
	for i := 0; i+4 <= len(buf); i += 4 {
		id := int32(buf[i]) | int32(buf[i+1])<<8 | int32(buf[i+2])<<16 | int32(buf[i+3])<<24
		ids = append(ids, id)
	}
	return ids
}
