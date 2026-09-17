//go:build linux

package secretservice

import (
	"context"
	"errors"
	"fmt"

	"github.com/runzhi214/keyring/core"
)

// Backend implements core.Backend via the Secret Service D-Bus API.
//
// Secrets are stored with "service" and "username" attributes, enabling
// search by either service+key or service alone. Metadata (Label,
// Attributes, Created, Modified) is read from item properties.
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

func (b *Backend) Get(ctx context.Context, service, key string) (core.Secret, error) {
	if err := b.client.ensureInit(); err != nil {
		return core.Secret{}, err
	}

	collectionPath, err := b.client.resolveCollection()
	if err != nil {
		return core.Secret{}, fmt.Errorf("resolve collection: %w", err)
	}
	if err := b.client.ensureUnlocked(ctx, collectionPath); err != nil {
		return core.Secret{}, err
	}

	itemPath, err := b.client.searchByServiceAndKey(ctx, collectionPath, service, key)
	if err != nil {
		return core.Secret{}, err
	}

	secret, err := b.client.getSecret(ctx, itemPath)
	if err != nil {
		return core.Secret{}, err
	}

	result := core.Secret{Value: string(secret.Value)}

	if label, err := b.client.getItemLabel(itemPath); err == nil {
		result.Label = label
	}
	if attrs, err := b.client.getItemAttributes(itemPath); err == nil {
		result.Attributes = attrs
	}
	if created, err := b.client.getItemCreated(itemPath); err == nil {
		result.Created = created
	}
	if modified, err := b.client.getItemModified(itemPath); err == nil {
		result.Modified = modified
	}

	return result, nil
}

func (b *Backend) Set(ctx context.Context, service, key string, s core.Secret) error {
	if s.Value == "" {
		return core.ErrEmptyValue
	}
	if err := b.client.ensureInit(); err != nil {
		return err
	}

	collectionPath, err := b.client.resolveCollection()
	if err != nil {
		return fmt.Errorf("resolve collection: %w", err)
	}
	if err := b.client.ensureUnlocked(ctx, collectionPath); err != nil {
		return err
	}

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

	return b.client.createItem(ctx, collectionPath, label, attrs, s.Value)
}

func (b *Backend) Delete(ctx context.Context, service, key string) error {
	if err := b.client.ensureInit(); err != nil {
		return err
	}

	collectionPath, err := b.client.resolveCollection()
	if err != nil {
		return fmt.Errorf("resolve collection: %w", err)
	}
	if err := b.client.ensureUnlocked(ctx, collectionPath); err != nil {
		return err
	}

	itemPath, err := b.client.searchByServiceAndKey(ctx, collectionPath, service, key)
	if err != nil {
		var nfe *core.NotFoundError
		if errors.As(err, &nfe) {
			return nil
		}
		return err
	}

	return b.client.deleteItem(ctx, itemPath)
}

func (b *Backend) List(ctx context.Context, service string) ([]string, error) {
	if err := b.client.ensureInit(); err != nil {
		return nil, err
	}

	collectionPath, err := b.client.resolveCollection()
	if err != nil {
		return nil, fmt.Errorf("resolve collection: %w", err)
	}
	if err := b.client.ensureUnlocked(ctx, collectionPath); err != nil {
		return nil, err
	}

	itemPaths, err := b.client.searchByService(ctx, collectionPath, service)
	if err != nil {
		return nil, err
	}

	var keys []string
	for _, itemPath := range itemPaths {
		attrs, err := b.client.getItemAttributes(itemPath)
		if err != nil {
			continue
		}
		if username, ok := attrs["username"]; ok {
			keys = append(keys, username)
		}
	}
	return keys, nil
}

func (b *Backend) Persistence() core.Persistence {
	return core.Persistent
}
