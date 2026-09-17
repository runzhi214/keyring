//go:build linux

package secretservice

import (
	"context"
	"fmt"

	dbus "github.com/godbus/dbus/v5"
)

// resolveCollection returns the default collection path, using a cached
// value when available. The collection path is a D-Bus object path that
// does not change during a process lifetime, so caching is safe.
//
// Resolution order: alias "default" → named "login" → first available
// collection in the Collections property.
func (c *Client) resolveCollection() (dbus.ObjectPath, error) {
	c.mu.RLock()
	if c.collectionPath != "" {
		p := c.collectionPath
		c.mu.RUnlock()
		return p, nil
	}
	c.mu.RUnlock()

	path, err := c.resolveCollectionUncached()
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	c.collectionPath = path
	c.mu.Unlock()

	return path, nil
}

// resolveCollectionUncached queries the D-Bus Collections property and
// selects the best available collection.
func (c *Client) resolveCollectionUncached() (dbus.ObjectPath, error) {
	aliasPath := dbus.ObjectPath(loginAlias)
	prop, err := c.connObject(ssServicePath).GetProperty(ssIface + ".Collections")
	if err != nil {
		return "", fmt.Errorf("read Collections property: %w", err)
	}
	paths, ok := prop.Value().([]dbus.ObjectPath)
	if !ok {
		return "", fmt.Errorf("Collections property is %T, want []dbus.ObjectPath", prop.Value())
	}
	if len(paths) == 0 {
		return "", fmt.Errorf("no collections available")
	}

	for _, p := range paths {
		if p == aliasPath {
			return aliasPath, nil
		}
	}

	loginPath := dbus.ObjectPath(collectionBase + "login")
	for _, p := range paths {
		if p == loginPath {
			return loginPath, nil
		}
	}

	return paths[0], nil
}

// unlock attempts to unlock a collection. If the Secret Service returns
// a prompt path, handlePrompt is called with the provided context.
func (c *Client) unlock(ctx context.Context, collectionPath dbus.ObjectPath, service, key string) error {
	var unlocked []dbus.ObjectPath
	var promptPath dbus.ObjectPath
	if err := c.object.CallWithContext(ctx, ssIface+".Unlock", 0, []dbus.ObjectPath{collectionPath}).Store(&unlocked, &promptPath); err != nil {
		return fmt.Errorf("unlock call: %w", err)
	}
	if err := c.handlePrompt(ctx, promptPath, service, key); err != nil {
		return err
	}
	return nil
}

// ensureUnlocked explicitly checks the Locked property and unlocks if
// needed. This is used as a fallback when an operation fails with a
// locked error (optimistic execution pattern).
func (c *Client) ensureUnlocked(ctx context.Context, collectionPath dbus.ObjectPath, service, key string) error {
	prop, err := c.connObject(collectionPath).GetProperty(collectionIface + ".Locked")
	if err != nil {
		return fmt.Errorf("read Locked property: %w", err)
	}
	locked, ok := prop.Value().(bool)
	if !ok {
		return fmt.Errorf("Locked property is %T, want bool", prop.Value())
	}
	if !locked {
		return nil
	}
	return c.unlock(ctx, collectionPath, service, key)
}
