//go:build !linux && !darwin && !windows

package keyring

func openDefault() (Backend, error) {
	return nil, &UnavailableError{
		Reason: ReasonUnsupportedPlatform,
		Detail: "no keyring backend implemented for this OS",
	}
}
