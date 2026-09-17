//go:build linux

package keyctl

import (
	"context"
	"strings"
)

// List returns the keys stored under a service in the kernel user keyring.
//
// It enumerates all keys via KEYCTL_READ + KEYCTL_DESCRIBE (see
// enumerateKeys), then filters for type "user" with descriptions
// starting with "<service>:". The suffix after the colon is returned
// as the key name.
func (b *Backend) List(_ context.Context, service string) ([]string, error) {
	infos, err := enumerateKeys()
	if err != nil {
		return nil, err
	}

	prefix := service + ":"
	var keys []string
	for _, info := range infos {
		if info.Type != keyType {
			continue
		}
		if !strings.HasPrefix(info.Description, prefix) {
			continue
		}
		keys = append(keys, info.Description[len(prefix):])
	}
	return keys, nil
}
