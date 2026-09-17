//go:build linux

package secretservice

import (
	"fmt"
	"sync"

	dbus "github.com/godbus/dbus/v5"
)

const (
	ssServiceName   = "org.freedesktop.secrets"
	ssServicePath   = "/org/freedesktop/secrets"
	ssIface         = "org.freedesktop.Secret.Service"
	collectionIface = "org.freedesktop.Secret.Collection"
	itemIface       = "org.freedesktop.Secret.Item"
	sessionIface    = "org.freedesktop.Secret.Session"
	promptIface     = "org.freedesktop.Secret.Prompt"

	loginAlias     = "/org/freedesktop/secrets/aliases/default"
	collectionBase = "/org/freedesktop/secrets/collection/"
)

// ssSecret is the D-Bus struct for org.freedesktop.Secret.Item's secret
// payload, returned by GetSecret and accepted by CreateItem.
type ssSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string `dbus:"content_type"`
}

// Client wraps the D-Bus Secret Service connection. The connection and
// session are established lazily on first use and reused for all
// subsequent operations.
//
// If the connection drops (e.g. the D-Bus daemon restarts), the next
// ensureInit call detects the break and reconnects transparently.
//
// The connection is never closed explicitly; it is released when the
// process exits. This avoids the overhead of reconnecting per call
// (which is what zalando/go-keyring does) and is safe because the
// Secret Service daemon outlives any single client process.
type Client struct {
	mu      sync.Mutex
	conn    *dbus.Conn
	object  dbus.BusObject
	session dbus.ObjectPath
	ready   bool
}

var (
	clientOnce sync.Once
	clientInst *Client
)

// sharedClient returns the process-level Client singleton.
func sharedClient() *Client {
	clientOnce.Do(func() {
		clientInst = &Client{}
	})
	return clientInst
}

// init connects to the D-Bus session bus and opens a Secret Service
// session. Must be called with c.mu held.
func (c *Client) init() error {
	conn, err := dbus.SessionBus()
	if err != nil {
		return fmt.Errorf("connect to session bus: %w", err)
	}
	c.conn = conn
	c.object = conn.Object(ssServiceName, ssServicePath)

	var disregard dbus.Variant
	var sessionPath dbus.ObjectPath
	if err := c.object.Call(ssIface+".OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&disregard, &sessionPath); err != nil {
		conn.Close()
		return fmt.Errorf("open session: %w", err)
	}
	c.session = sessionPath
	c.ready = true
	return nil
}

// ensureInit guarantees that the client is connected and has a session.
// If the connection has dropped, it reconnects transparently.
// Safe to call from any goroutine.
func (c *Client) ensureInit() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ready && c.conn.Connected() {
		return nil
	}
	c.ready = false
	return c.init()
}

// connObject returns a BusObject for the given path on the Secret Service.
func (c *Client) connObject(path dbus.ObjectPath) dbus.BusObject {
	return c.conn.Object(ssServiceName, path)
}

// connObj returns the underlying conn and service object for direct
// access. Must only be called after ensureInit has succeeded.
func (c *Client) busObject() dbus.BusObject {
	return c.object
}
