//go:build linux

package keyring

import (
	"testing"

	"github.com/runzhi214/keyring/core"
	"github.com/runzhi214/keyring/linux/keyctl"
	"github.com/runzhi214/keyring/linux/secretservice"
)

func TestOpenReturnsBackend(t *testing.T) {
	b, err := Open()
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	if b == nil {
		t.Fatal("Open() returned nil backend")
	}
	avail := b.Available()
	if !avail.OK {
		t.Fatalf("Open() returned unavailable backend: %s (%s)",
			avail.Reason, avail.Detail)
	}
}

func TestOpenPrefersSecretService(t *testing.T) {
	ss := secretservice.New()
	kt := keyctl.New()

	b, err := Open()
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}

	// If Secret Service is available, Open should return it (Persistent).
	// Otherwise it should return keyctl (SessionOnly).
	if ss.Available().OK {
		if b.Persistence() != core.Persistent {
			t.Errorf("Open() Persistence = %v, want Persistent (Secret Service)", b.Persistence())
		}
	} else if kt.Available().OK {
		if b.Persistence() != core.SessionOnly {
			t.Errorf("Open() Persistence = %v, want SessionOnly (keyctl)", b.Persistence())
		}
	}
}

func TestOpenAvailableMatchesBackend(t *testing.T) {
	b, err := Open()
	if err != nil {
		t.Skipf("Open() unavailable: %v", err)
	}
	if !b.Available().OK {
		t.Errorf("Open() backend reports unavailable after Open succeeded")
	}
}
