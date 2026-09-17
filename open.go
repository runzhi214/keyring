package keyring

// Open returns the platform's default persistent backend.
//
// On Linux it prefers Secret Service (D-Bus), falling back to the kernel
// user keyring (KeyCtl). On macOS it uses the Keychain via
// /usr/bin/security. On Windows it uses the Credential Manager via
// advapi32.
//
// Returns *UnavailableError when no persistent backend can be initialized.
// Callers that tolerate secret loss may fall back to mem.New(); callers
// that must persist should surface the error to the user.
//
// Open does not silently degrade. The decision to use an in-memory
// fallback belongs to the caller, not the library.
func Open() (Backend, error) {
	return openDefault()
}
