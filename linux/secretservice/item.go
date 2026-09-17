//go:build linux

package secretservice

import (
	"context"
	"fmt"
	"time"

	dbus "github.com/godbus/dbus/v5"
	"github.com/runzhi214/keyring/core"
)

// searchItems searches for items in a collection matching the given
// attributes. Returns the D-Bus object paths of matching items.
func (c *Client) searchItems(ctx context.Context, collectionPath dbus.ObjectPath, attrs map[string]string) ([]dbus.ObjectPath, error) {
	var results []dbus.ObjectPath
	obj := c.connObject(collectionPath)
	if err := obj.CallWithContext(ctx, collectionIface+".SearchItems", 0, attrs).Store(&results); err != nil {
		return nil, fmt.Errorf("search items: %w", err)
	}
	return results, nil
}

// getSecret retrieves the secret value of an item.
func (c *Client) getSecret(ctx context.Context, itemPath dbus.ObjectPath) (*ssSecret, error) {
	var secret ssSecret
	if err := c.connObject(itemPath).CallWithContext(ctx, itemIface+".GetSecret", 0, c.session).Store(&secret); err != nil {
		return nil, fmt.Errorf("get secret: %w", err)
	}
	return &secret, nil
}

// createItem creates a new item in the collection with the given label,
// attributes, and secret value. When replace is true, any existing item
// with the same attributes is replaced.
func (c *Client) createItem(ctx context.Context, collectionPath dbus.ObjectPath, label string, attrs map[string]string, value string) error {
	secret := ssSecret{
		Session:     c.session,
		Parameters:  []byte{},
		Value:       []byte(value),
		ContentType: "text/plain; charset=utf8",
	}

	properties := map[string]dbus.Variant{
		itemIface + ".Label":      dbus.MakeVariant(label),
		itemIface + ".Attributes": dbus.MakeVariant(attrs),
	}

	var itemPath, promptPath dbus.ObjectPath
	obj := c.connObject(collectionPath)
	if err := obj.CallWithContext(ctx, collectionIface+".CreateItem", 0, properties, secret, true).Store(&itemPath, &promptPath); err != nil {
		return fmt.Errorf("create item: %w", err)
	}
	if err := c.handlePrompt(ctx, promptPath); err != nil {
		return err
	}
	return nil
}

// deleteItem removes an item from its collection.
func (c *Client) deleteItem(ctx context.Context, itemPath dbus.ObjectPath) error {
	var promptPath dbus.ObjectPath
	if err := c.connObject(itemPath).CallWithContext(ctx, itemIface+".Delete", 0).Store(&promptPath); err != nil {
		return fmt.Errorf("delete item: %w", err)
	}
	if err := c.handlePrompt(ctx, promptPath); err != nil {
		return err
	}
	return nil
}

// getItemLabel reads the Label property of an item.
func (c *Client) getItemLabel(itemPath dbus.ObjectPath) (string, error) {
	prop, err := c.connObject(itemPath).GetProperty(itemIface + ".Label")
	if err != nil {
		return "", err
	}
	label, ok := prop.Value().(string)
	if !ok {
		return "", fmt.Errorf("Label is %T, want string", prop.Value())
	}
	return label, nil
}

// getItemAttributes reads the Attributes property of an item.
func (c *Client) getItemAttributes(itemPath dbus.ObjectPath) (map[string]string, error) {
	prop, err := c.connObject(itemPath).GetProperty(itemIface + ".Attributes")
	if err != nil {
		return nil, err
	}
	attrs, ok := prop.Value().(map[string]string)
	if !ok {
		return nil, fmt.Errorf("Attributes is %T, want map[string]string", prop.Value())
	}
	return attrs, nil
}

// getItemCreated reads the Created property (Unix timestamp) of an item.
func (c *Client) getItemCreated(itemPath dbus.ObjectPath) (time.Time, error) {
	prop, err := c.connObject(itemPath).GetProperty(itemIface + ".Created")
	if err != nil {
		return time.Time{}, err
	}
	ts, ok := prop.Value().(uint64)
	if !ok {
		return time.Time{}, fmt.Errorf("Created is %T, want uint64", prop.Value())
	}
	return time.Unix(int64(ts), 0), nil
}

// getItemModified reads the Modified property (Unix timestamp) of an item.
func (c *Client) getItemModified(itemPath dbus.ObjectPath) (time.Time, error) {
	prop, err := c.connObject(itemPath).GetProperty(itemIface + ".Modified")
	if err != nil {
		return time.Time{}, err
	}
	ts, ok := prop.Value().(uint64)
	if !ok {
		return time.Time{}, fmt.Errorf("Modified is %T, want uint64", prop.Value())
	}
	return time.Unix(int64(ts), 0), nil
}

// searchByServiceAndKey searches for a single item matching both the
// service and key (stored as the "service" and "username" attributes).
// Returns NotFoundError when no item is found.
func (c *Client) searchByServiceAndKey(ctx context.Context, collectionPath dbus.ObjectPath, service, key string) (dbus.ObjectPath, error) {
	attrs := map[string]string{
		"service":  service,
		"username": key,
	}
	results, err := c.searchItems(ctx, collectionPath, attrs)
	if err != nil {
		return "", err
	}
	if len(results) == 0 {
		return "", &core.NotFoundError{Service: service, Key: key}
	}
	return results[0], nil
}

// searchByService searches for all items matching a service. Returns
// the item paths and their "username" attribute values (key names).
func (c *Client) searchByService(ctx context.Context, collectionPath dbus.ObjectPath, service string) ([]dbus.ObjectPath, error) {
	attrs := map[string]string{
		"service": service,
	}
	return c.searchItems(ctx, collectionPath, attrs)
}
