//go:build darwin

package keyring

import "github.com/runzhi214/keyring/core"

func openDefault() (core.Backend, error) {
	return nil, &core.UnavailableError{
		Reason: core.ReasonUnsupportedPlatform,
		Detail: "macOS Keychain backend not yet implemented",
	}
}
