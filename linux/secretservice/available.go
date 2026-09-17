//go:build linux

package secretservice

import (
	"os"

	dbus "github.com/godbus/dbus/v5"
	"github.com/runzhi214/keyring/core"
)

const (
	dbusName        = "org.freedesktop.DBus"
	dbusPath        = "/org/freedesktop/DBus"
	dbusHasOwner    = "org.freedesktop.DBus.NameHasOwner"
	secretService   = "org.freedesktop.secrets"
)

// Available reports whether the Secret Service D-Bus provider is
// registered on the session bus. It guards against the two autolaunch
// triggers in godbus getSessionBusAddress — an empty or "autolaunch:"
// DBUS_SESSION_BUS_ADDRESS — before calling SessionBus, which would
// otherwise spawn dbus-launch + dbus-daemon. conn.Close() does not
// terminate the daemon, leaking an orphan process on every call.
//
// This function is a pure probe: it opens a connection, checks
// NameHasOwner, and closes the connection. It does not create sessions
// or items.
func Available() core.Availability {
	addr := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	if addr == "" || addr == "autolaunch:" {
		return core.Availability{
			OK:     false,
			Reason: core.ReasonNoSessionBus,
			Detail: "DBUS_SESSION_BUS_ADDRESS is empty or autolaunch",
		}
	}
	conn, err := dbus.SessionBus()
	if err != nil {
		return core.Availability{
			OK:     false,
			Reason: core.ReasonNoSessionBus,
			Detail: err.Error(),
		}
	}
	defer conn.Close()

	obj := conn.Object(dbusName, dbusPath)
	var hasOwner bool
	if err := obj.Call(dbusHasOwner, 0, secretService).Store(&hasOwner); err != nil {
		return core.Availability{
			OK:     false,
			Reason: core.ReasonNoSecretService,
			Detail: "NameHasOwner call failed: " + err.Error(),
		}
	}
	if !hasOwner {
		return core.Availability{
			OK:     false,
			Reason: core.ReasonNoSecretService,
			Detail: "org.freedesktop.secrets has no owner on the session bus",
		}
	}
	return core.Availability{OK: true, Reason: core.ReasonOK}
}
