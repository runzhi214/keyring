//go:build linux

package keyring

import (
	"github.com/runzhi214/keyring/core"
	"github.com/runzhi214/keyring/linux/keyctl"
)

func openDefault() (core.Backend, error) {
	if kt := keyctl.New(); kt.Available().OK {
		return kt, nil
	}
	return nil, &core.UnavailableError{
		Reason: core.ReasonUnsupportedPlatform,
		Detail: "no kernel keyring available on this Linux system",
	}
}
