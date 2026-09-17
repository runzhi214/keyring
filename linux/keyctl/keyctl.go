//go:build linux

package keyctl

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/runzhi214/keyring/core"
	"golang.org/x/sys/unix"
)

const (
	keyType = "user"
)

// Backend stores secrets in the Linux kernel user keyring under type "user"
// with descriptions "<service>:<key>". Values are base64-encoded to survive
// binary payloads across the kernel keyring API.
//
// Secrets are visible to sibling processes in the same session but do not
// survive reboot — Persistence is SessionOnly.
type Backend struct{}

// New returns a keyctl backend. The returned value is stateless; all state
// lives in the kernel keyring.
func New() *Backend { return &Backend{} }

func desc(service, key string) string {
	return service + ":" + key
}

func b64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func b64Decode(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (b *Backend) Available() core.Availability {
	return Available()
}

func (b *Backend) Get(_ context.Context, service, key string) (core.Secret, error) {
	id, err := unix.KeyctlSearch(unix.KEY_SPEC_USER_KEYRING, keyType, desc(service, key), 0)
	if err != nil {
		if errors.Is(err, unix.ENOKEY) || errors.Is(err, unix.ENOENT) {
			return core.Secret{}, &core.NotFoundError{Service: service, Key: key}
		}
		return core.Secret{}, fmt.Errorf("keyctl search: %w", err)
	}
	// Loop to handle TOCTOU: the key's payload may change between the
	// probe (nil buffer) and the read (allocated buffer). If the second
	// read returns more bytes than the buffer, retry with a larger buffer.
	var val string
	for {
		n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, nil, 0)
		if err != nil {
			return core.Secret{}, fmt.Errorf("keyctl read (probe): %w", err)
		}
		if n == 0 {
			val = ""
			break
		}
		buf := make([]byte, n)
		read, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, buf, 0)
		if err != nil {
			return core.Secret{}, fmt.Errorf("keyctl read: %w", err)
		}
		if read <= n {
			val = string(buf[:read])
			break
		}
		// Payload grew between probe and read; loop will re-probe.
	}
	decoded, err := b64Decode(val)
	if err != nil {
		return core.Secret{}, fmt.Errorf("keyctl decode: %w", err)
	}
	return core.Secret{Value: decoded}, nil
}

func (b *Backend) Set(_ context.Context, service, key string, s core.Secret) error {
	if s.Value == "" {
		return core.ErrEmptyValue
	}
	if err := ensureLinked(); err != nil {
		return err
	}
	d := desc(service, key)
	encoded := b64Encode(s.Value)
	if id, err := unix.KeyctlSearch(unix.KEY_SPEC_USER_KEYRING, keyType, d, 0); err == nil {
		if _, err := unix.KeyctlBuffer(unix.KEYCTL_UPDATE, id, []byte(encoded), 0); err != nil {
			return fmt.Errorf("keyctl update: %w", err)
		}
		return nil
	}
	if _, err := unix.AddKey(keyType, d, []byte(encoded), unix.KEY_SPEC_USER_KEYRING); err != nil {
		return fmt.Errorf("keyctl add: %w", err)
	}
	return nil
}

func (b *Backend) Delete(_ context.Context, service, key string) error {
	id, err := unix.KeyctlSearch(unix.KEY_SPEC_USER_KEYRING, keyType, desc(service, key), 0)
	if err != nil {
		if errors.Is(err, unix.ENOKEY) || errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("keyctl search: %w", err)
	}
	if _, err := unix.KeyctlInt(unix.KEYCTL_UNLINK, id, unix.KEY_SPEC_USER_KEYRING, 0, 0); err != nil {
		return fmt.Errorf("keyctl unlink: %w", err)
	}
	return nil
}

func (b *Backend) Persistence() core.Persistence {
	return core.SessionOnly
}
