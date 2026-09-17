//go:build linux

package keyctl

import (
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// keyInfo holds the parsed metadata of a single key in the user keyring.
type keyInfo struct {
	ID          int32
	Type        string
	Description string
}

// enumerateKeys reads all keys from the user keyring via KEYCTL_READ,
// then describes each via KEYCTL_DESCRIBE. Keys that have been revoked
// or invalidated between the two calls are silently skipped.
//
// This is the shared implementation used by List and cleanupService.
func enumerateKeys() ([]keyInfo, error) {
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

	ids := parseKeyIDs(buf[:read])
	var infos []keyInfo
	for _, id := range ids {
		descStr, err := unix.KeyctlString(unix.KEYCTL_DESCRIBE, int(id))
		if err != nil {
			continue
		}
		// Format: "type;uid;gid;perm;description"
		parts := strings.SplitN(descStr, ";", 5)
		if len(parts) < 5 {
			continue
		}
		infos = append(infos, keyInfo{
			ID:          id,
			Type:        parts[0],
			Description: parts[4],
		})
	}
	return infos, nil
}

// parseKeyIDs parses a KEYCTL_READ buffer into a slice of key IDs.
// The buffer contains key serial numbers in native byte order.
func parseKeyIDs(buf []byte) []int32 {
	if len(buf) < 4 {
		return nil
	}
	count := len(buf) / 4
	ids := make([]int32, 0, count)
	for i := 0; i+4 <= len(buf); i += 4 {
		ids = append(ids, int32(binary.NativeEndian.Uint32(buf[i:i+4])))
	}
	return ids
}
