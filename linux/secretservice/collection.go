//go:build linux

package secretservice

import (
	"context"
	"fmt"

	dbus "github.com/godbus/dbus/v5"
)

// resolveCollection returns the default collection (alias "default",
// typically pointing to "login"). It first tries the alias path, then
// falls back to the named "login" collection.
func (c *Client) resolveCollection() (dbus.ObjectPath, error) {
	aliasPath := dbus.ObjectPath(loginAlias)
	prop, err := c.connObject(ssServicePath).GetProperty(ssIface + ".Collections")
	if err != nil {
		return "", fmt.Errorf("read Collections property: %w", err)
	}
	paths, ok := prop.Value().([]dbus.ObjectPath)
	if !ok {
		return "", fmt.Errorf("Collections property is %T, want []dbus.ObjectPath", prop.Value())
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

	return "", fmt.Errorf("no default or login collection found")
}

// isLocked reports whether a collection is locked.
func (c *Client) isLocked(collectionPath dbus.ObjectPath) (bool, error) {
	prop, err := c.connObject(collectionPath).GetProperty(collectionIface + ".Locked")
	if err != nil {
		return false, fmt.Errorf("read Locked property: %w", err)
	}
	locked, ok := prop.Value().(bool)
	if !ok {
		return false, fmt.Errorf("Locked property is %T, want bool", prop.Value())
	}
	return locked, nil
}

// unlock attempts to unlock a collection. If the Secret Service returns
// a prompt path, handlePrompt is called with the provided context.
func (c *Client) unlock(ctx context.Context, collectionPath dbus.ObjectPath) error {
	var unlocked []dbus.ObjectPath
	var promptPath dbus.ObjectPath
	if err := c.object.CallWithContext(ctx, ssIface+".Unlock", 0, []dbus.ObjectPath{collectionPath}).Store(&unlocked, &promptPath); err != nil {
		return fmt.Errorf("unlock call: %w", err)
	}
	if err := c.handlePrompt(ctx, promptPath); err != nil {
		return err
	}
	return nil
}

// ensureUnlocked checks whether the collection is locked and unlocks it
// if needed, using the provided context for prompt cancellation.
func (c *Client) ensureUnlocked(ctx context.Context, collectionPath dbus.ObjectPath) error {
	locked, err := c.isLocked(collectionPath)
	if err != nil {
		return err
	}
	if !locked {
		return nil
	}
	return c.unlock(ctx, collectionPath)
}
