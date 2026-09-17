//go:build linux

package secretservice

import (
	"context"
	"errors"
	"fmt"

	dbus "github.com/godbus/dbus/v5"
	"github.com/runzhi214/keyring/core"
)

// Backend implements core.Backend via the Secret Service D-Bus API.
//
// Secrets are stored with "service" and "username" attributes, enabling
// search by either service+key or service alone. Metadata (Label,
// Attributes, Created, Modified) is read from item properties in a
// single GetAll D-Bus call.
//
// The D-Bus connection is a process-level singleton (see Client). New
// returns a lightweight struct; the connection is established lazily on
// first use.
//
// Persistence is Persistent: secrets survive process restarts and system
// reboots when backed by gnome-keyring (which stores encrypted files on
// disk, unlocked at login).
type Backend struct {
	client *Client
}

// New returns a Secret Service backend. The returned value is lightweight;
// the D-Bus connection is established on first use.
func New() *Backend {
	return &Backend{client: sharedClient()}
}

func (b *Backend) Available() core.Availability {
	return Available()
}

// prepare returns a ready collection path for the operation. It ensures
// the D-Bus connection is live and the collection path is resolved.
// It does NOT check or unlock the collection — operations use the
// optimistic pattern (try directly, retry with unlock on locked error).
func (b *Backend) prepare(ctx context.Context) (dbus.ObjectPath, error) {
	if err := b.client.ensureInit(); err != nil {
		return "", err
	}
	collectionPath, err := b.client.resolveCollection()
	if err != nil {
		return "", fmt.Errorf("resolve collection: %w", err)
	}
	return collectionPath, nil
}

func (b *Backend) Get(ctx context.Context, service, key string) (core.Secret, error) {
	collectionPath, err := b.prepare(ctx)
	if err != nil {
		return core.Secret{}, err
	}

	result, err := b.tryGet(ctx, collectionPath, service, key)
	if err == nil {
		return result, nil
	}

	if isLockedError(err) {
		if unlockErr := b.client.ensureUnlocked(ctx, collectionPath, service, key); unlockErr != nil {
			return core.Secret{}, unlockErr
		}
		return b.tryGet(ctx, collectionPath, service, key)
	}

	return core.Secret{}, err
}

func (b *Backend) tryGet(ctx context.Context, collectionPath dbus.ObjectPath, service, key string) (core.Secret, error) {
	var result core.Secret

	err := b.client.withConn(func() error {
		itemPath, err := b.client.searchByServiceAndKey(ctx, collectionPath, service, key)
		if err != nil {
			return err
		}

		secret, err := b.client.getSecret(ctx, itemPath)
		if err != nil {
			return err
		}
		result.Value = string(secret.Value)

		meta, err := b.client.getItemMetadata(itemPath)
		if err != nil {
			return nil
		}
		result.Label = meta.Label
		result.Attributes = meta.Attributes
		result.Created = meta.Created
		result.Modified = meta.Modified
		return nil
	})

	return result, err
}

func (b *Backend) Set(ctx context.Context, service, key string, s core.Secret) error {
	if s.Value == "" {
		return core.ErrEmptyValue
	}

	collectionPath, err := b.prepare(ctx)
	if err != nil {
		return err
	}

	err = b.trySet(ctx, collectionPath, service, key, s)
	if err == nil {
		return nil
	}

	if isLockedError(err) {
		if unlockErr := b.client.ensureUnlocked(ctx, collectionPath, service, key); unlockErr != nil {
			return unlockErr
		}
		return b.trySet(ctx, collectionPath, service, key, s)
	}

	return err
}

func (b *Backend) trySet(ctx context.Context, collectionPath dbus.ObjectPath, service, key string, s core.Secret) error {
	label := s.Label
	if label == "" {
		label = key + " on " + service
	}

	attrs := map[string]string{
		"service":  service,
		"username": key,
	}
	for k, v := range s.Attributes {
		if k != "service" && k != "username" {
			attrs[k] = v
		}
	}

	return b.client.withConn(func() error {
		return b.client.createItem(ctx, collectionPath, label, attrs, s.Value, service, key)
	})
}

func (b *Backend) Delete(ctx context.Context, service, key string) error {
	collectionPath, err := b.prepare(ctx)
	if err != nil {
		return err
	}

	err = b.tryDelete(ctx, collectionPath, service, key)
	if err == nil {
		return nil
	}

	var nfe *core.NotFoundError
	if errors.As(err, &nfe) {
		return nil
	}

	if isLockedError(err) {
		if unlockErr := b.client.ensureUnlocked(ctx, collectionPath, service, key); unlockErr != nil {
			return unlockErr
		}
		return b.tryDelete(ctx, collectionPath, service, key)
	}

	return err
}

func (b *Backend) tryDelete(ctx context.Context, collectionPath dbus.ObjectPath, service, key string) error {
	return b.client.withConn(func() error {
		itemPath, err := b.client.searchByServiceAndKey(ctx, collectionPath, service, key)
		if err != nil {
			return err
		}
		return b.client.deleteItem(ctx, itemPath, service, key)
	})
}

func (b *Backend) List(ctx context.Context, service string) ([]string, error) {
	collectionPath, err := b.prepare(ctx)
	if err != nil {
		return nil, err
	}

	keys, err := b.tryList(ctx, collectionPath, service)
	if err == nil {
		return keys, nil
	}

	if isLockedError(err) {
		if unlockErr := b.client.ensureUnlocked(ctx, collectionPath, service, ""); unlockErr != nil {
			return nil, unlockErr
		}
		return b.tryList(ctx, collectionPath, service)
	}

	return nil, err
}

func (b *Backend) tryList(ctx context.Context, collectionPath dbus.ObjectPath, service string) ([]string, error) {
	var keys []string

	err := b.client.withConn(func() error {
		itemPaths, err := b.client.searchByService(ctx, collectionPath, service)
		if err != nil {
			return err
		}

		for _, itemPath := range itemPaths {
			meta, err := b.client.getItemMetadata(itemPath)
			if err != nil {
				continue
			}
			if meta.Attributes != nil {
				if username, ok := meta.Attributes["username"]; ok {
					keys = append(keys, username)
				}
			}
		}
		return nil
	})

	return keys, err
}

func (b *Backend) Persistence() core.Persistence {
	return core.Persistent
}
