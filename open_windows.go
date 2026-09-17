//go:build windows

package keyring

func openDefault() (Backend, error) {
	return nil, &UnavailableError{
		Reason: ReasonUnsupportedPlatform,
		Detail: "Windows Credential Manager backend not yet implemented",
	}
}
