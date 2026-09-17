//go:build darwin

package keyring

func openDefault() (Backend, error) {
	return nil, &UnavailableError{
		Reason: ReasonUnsupportedPlatform,
		Detail: "macOS Keychain backend not yet implemented",
	}
}
