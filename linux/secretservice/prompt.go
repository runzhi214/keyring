//go:build linux

package secretservice

import (
	"context"
	"fmt"
	"time"

	dbus "github.com/godbus/dbus/v5"
	"github.com/runzhi214/keyring/core"
)

// promptTimeout is the maximum time to wait for a user to respond to a
// Secret Service prompt (e.g. keyring unlock dialog).
const promptTimeout = 30 * time.Second

// handlePrompt waits for a Secret Service prompt to complete. If the
// prompt path is "/", no prompt is needed and the function returns nil
// immediately.
//
// The context may cancel a blocking prompt: if ctx is cancelled before
// the prompt completes, the function returns ctx.Err() immediately.
// A promptTimeout guard prevents indefinite blocking when the daemon
// is running but no user is present to dismiss the dialog.
//
// The service and key parameters are used to populate typed errors
// (PromptDismissedError, LockedError) so callers can identify which
// operation triggered the prompt.
//
// This is the critical improvement over zalando/go-keyring, which blocks
// indefinitely on <-promptSignal with no timeout or context awareness.
func (c *Client) handlePrompt(ctx context.Context, promptPath dbus.ObjectPath, service, key string) error {
	if promptPath == "/" {
		return nil
	}

	matchOpts := []dbus.MatchOption{
		dbus.WithMatchObjectPath(promptPath),
		dbus.WithMatchInterface(promptIface),
	}
	if err := c.conn.AddMatchSignal(matchOpts...); err != nil {
		return fmt.Errorf("add prompt signal match: %w", err)
	}
	defer func() {
		_ = c.conn.RemoveMatchSignal(matchOpts...)
	}()

	ch := make(chan *dbus.Signal, 1)
	c.conn.Signal(ch)
	defer c.conn.RemoveSignal(ch)

	if err := c.connObject(promptPath).CallWithContext(ctx, promptIface+".Prompt", 0, "").Err; err != nil {
		return fmt.Errorf("trigger prompt: %w", err)
	}

	timer := time.NewTimer(promptTimeout)
	defer timer.Stop()

	select {
	case sig := <-ch:
		if sig.Name != promptIface+".Completed" {
			return fmt.Errorf("unexpected prompt signal: %s", sig.Name)
		}
		if len(sig.Body) < 2 {
			return fmt.Errorf("prompt signal has %d body items, want 2", len(sig.Body))
		}
		dismissed, ok := sig.Body[0].(bool)
		if !ok {
			return fmt.Errorf("prompt signal body[0] is %T, want bool", sig.Body[0])
		}
		if dismissed {
			return &core.PromptDismissedError{Service: service, Key: key}
		}
		return nil

	case <-ctx.Done():
		return ctx.Err()

	case <-timer.C:
		return &core.LockedError{
			Service: service,
			Detail:  "prompt timed out after " + promptTimeout.String(),
		}
	}
}
