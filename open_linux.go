//go:build linux

package keyring

func openDefault() (Backend, error) {
	return nil, &UnavailableError{
		Reason: ReasonUnsupportedPlatform,
		Detail: "Linux backends not yet implemented",
	}
}
