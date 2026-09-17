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
func (c *Client) createItem(ctx context.Context, collectionPath dbus.ObjectPath, label string, attrs map[string]string, value string, service, key string) error {
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
	if err := c.handlePrompt(ctx, promptPath, service, key); err != nil {
		return err
	}
	return nil
}

// deleteItem removes an item from its collection.
func (c *Client) deleteItem(ctx context.Context, itemPath dbus.ObjectPath, service, key string) error {
	var promptPath dbus.ObjectPath
	if err := c.connObject(itemPath).CallWithContext(ctx, itemIface+".Delete", 0).Store(&promptPath); err != nil {
		return fmt.Errorf("delete item: %w", err)
	}
	if err := c.handlePrompt(ctx, promptPath, service, key); err != nil {
		return err
	}
	return nil
}

// itemMetadata holds the metadata read from an item's properties.
type itemMetadata struct {
	Label      string
	Attributes map[string]string
	Created    time.Time
	Modified   time.Time
}

// getItemMetadata reads all item properties in a single D-Bus call
// (GetAll) instead of individual GetProperty calls. This reduces the
// number of D-Bus round-trips from 4 to 1 per Get operation.
func (c *Client) getItemMetadata(itemPath dbus.ObjectPath) (*itemMetadata, error) {
	var props map[string]dbus.Variant
	if err := c.connObject(itemPath).Call(
		"org.freedesktop.DBus.Properties.GetAll", 0, itemIface,
	).Store(&props); err != nil {
		return nil, fmt.Errorf("read item properties: %w", err)
	}

	meta := &itemMetadata{}

	if v, ok := props["Label"]; ok {
		if label, ok := v.Value().(string); ok {
			meta.Label = label
		}
	}
	if v, ok := props["Attributes"]; ok {
		if attrs, ok := v.Value().(map[string]string); ok {
			meta.Attributes = attrs
		}
	}
	if v, ok := props["Created"]; ok {
		if ts, ok := v.Value().(uint64); ok {
			meta.Created = time.Unix(int64(ts), 0)
		}
	}
	if v, ok := props["Modified"]; ok {
		if ts, ok := v.Value().(uint64); ok {
			meta.Modified = time.Unix(int64(ts), 0)
		}
	}

	return meta, nil
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
// the item paths.
func (c *Client) searchByService(ctx context.Context, collectionPath dbus.ObjectPath, service string) ([]dbus.ObjectPath, error) {
	attrs := map[string]string{
		"service": service,
	}
	return c.searchItems(ctx, collectionPath, attrs)
}
