//go:build linux

package keyring

import (
	"github.com/runzhi214/keyring/core"
	"github.com/runzhi214/keyring/linux/keyctl"
	"github.com/runzhi214/keyring/linux/secretservice"
)

func openDefault() (core.Backend, error) {
	ss := secretservice.New()
	if ss.Available().OK {
		return ss, nil
	}
	if kt := keyctl.New(); kt.Available().OK {
		return kt, nil
	}
	return nil, &core.UnavailableError{
		Reason: core.ReasonUnsupportedPlatform,
		Detail: "no Secret Service or kernel keyring available on this Linux system",
	}
}
