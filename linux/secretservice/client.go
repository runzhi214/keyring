//go:build linux

package secretservice

import (
	"errors"
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
	promptIface     = "org.freedesktop.Secret.Prompt"

	loginAlias     = "/org/freedesktop/secrets/aliases/default"
	collectionBase = "/org/freedesktop/secrets/collection/"

	// errLocked is the D-Bus error name returned by Secret Service when
	// an item or collection is locked.
	errLockedName = "org.freedesktop.Secret.Error.IsLocked"
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
// The resolved collection path is cached after the first successful
// resolveCollection call — it is a D-Bus object path that does not change
// during a process lifetime. The locked/unlocked state is NOT cached:
// operations use an optimistic approach (try directly, retry with unlock
// on locked error) to stay correct when the keyring is locked or
// re-locked mid-session.
//
// If the D-Bus connection drops (e.g. the daemon restarts), the next
// ensureInit call detects the break, reconnects, and clears the cached
// collection path so it is re-resolved on the new connection.
//
// Concurrency: ensureInit holds a write lock (c.mu); all D-Bus operations
// run under a read lock (c.mu.RLock) obtained by withConn. This ensures
// that a reconnect does not race with in-flight operations.
type Client struct {
	mu             sync.RWMutex
	conn           *dbus.Conn
	object         dbus.BusObject
	session        dbus.ObjectPath
	ready          bool
	collectionPath dbus.ObjectPath
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
// session. Must be called with c.mu held (write lock).
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
	c.collectionPath = ""
	return nil
}

// ensureInit guarantees that the client is connected and has a session.
// If the connection has dropped, it reconnects transparently and clears
// the cached collection path.
// Safe to call from any goroutine.
func (c *Client) ensureInit() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ready && c.conn.Connected() {
		return nil
	}
	c.ready = false
	c.collectionPath = ""
	return c.init()
}

// withConn acquires a read lock and invokes fn with the client's
// connection state. The read lock ensures that no reconnect happens
// during the operation. The caller must have called ensureInit first.
func (c *Client) withConn(fn func() error) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return fn()
}

// connObject returns a BusObject for the given path on the Secret Service.
// Must be called under withConn's read lock or after ensureInit.
func (c *Client) connObject(path dbus.ObjectPath) dbus.BusObject {
	return c.conn.Object(ssServiceName, path)
}

// isLockedError reports whether a D-Bus error indicates a locked item
// or collection.
func isLockedError(err error) bool {
	if err == nil {
		return false
	}
	var dbusErr dbus.Error
	if !errors.As(err, &dbusErr) {
		return false
	}
	return dbusErr.Name == errLockedName
}
