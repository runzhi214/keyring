//go:build !linux && !darwin && !windows

package keyring

import "github.com/runzhi214/keyring/core"

func openDefault() (core.Backend, error) {
	return nil, &core.UnavailableError{
		Reason: core.ReasonUnsupportedPlatform,
		Detail: "no keyring backend implemented for this OS",
	}
}
