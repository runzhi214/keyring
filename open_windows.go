//go:build windows

package keyring

import "github.com/runzhi214/keyring/core"

func openDefault() (core.Backend, error) {
	return nil, &core.UnavailableError{
		Reason: core.ReasonUnsupportedPlatform,
		Detail: "Windows Credential Manager backend not yet implemented",
	}
}
