//go:build linux

package keyctl

import (
	"context"
	"testing"

	"github.com/runzhi214/keyring/contracttest"
	"github.com/runzhi214/keyring/core"
)

func TestContract(t *testing.T) {
	b := New()
	if !b.Available().OK {
		t.Skipf("kernel keyring not available: %s (%s)",
			b.Available().Reason, b.Available().Detail)
	}
	ctx := context.Background()
	t.Cleanup(func() {
		services := []string{
			"keyctl-test-roundtrip", "keyctl-test-notfound",
			"keyctl-test-deleteidem", "keyctl-test-emptyval",
			"keyctl-test-listkeys", "keyctl-test-delfromlist",
			"keyctl-test-update", "keyctl-test-iso-a",
			"keyctl-test-iso-b", "keyctl-test-cross-a",
			"keyctl-test-cross-b", "keyctl-test-concurrent",
			"keyctl-test-cancelled",
		}
		for _, s := range services {
			_ = cleanupService(ctx, s)
		}
	})
	contracttest.RunContractTests(t, b, func() core.Backend { return New() }, "keyctl-test")
}

func TestListFiltersByService(t *testing.T) {
	b := New()
	if !b.Available().OK {
		t.Skipf("kernel keyring not available")
	}
	ctx := context.Background()

	svcA := "keyctl-list-filter-a"
	svcB := "keyctl-list-filter-b"
	t.Cleanup(func() {
		_ = cleanupService(ctx, svcA)
		_ = cleanupService(ctx, svcB)
	})

	_ = b.Set(ctx, svcA, "key-1", core.Secret{Value: "v1"})
	_ = b.Set(ctx, svcA, "key-2", core.Secret{Value: "v2"})
	_ = b.Set(ctx, svcB, "key-3", core.Secret{Value: "v3"})

	keysA, err := b.List(ctx, svcA)
	if err != nil {
		t.Fatalf("List svcA: %v", err)
	}
	if len(keysA) != 2 {
		t.Fatalf("List svcA: got %d keys, want 2", len(keysA))
	}

	keysB, err := b.List(ctx, svcB)
	if err != nil {
		t.Fatalf("List svcB: %v", err)
	}
	if len(keysB) != 1 {
		t.Fatalf("List svcB: got %d keys, want 1", len(keysB))
	}
}

func TestParseKeyIDs(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want []int32
	}{
		{"empty", nil, nil},
		{"one key", []byte{0x01, 0x00, 0x00, 0x00}, []int32{1}},
		{"two keys", []byte{
			0x64, 0x00, 0x00, 0x00,
			0xC8, 0x00, 0x00, 0x00,
		}, []int32{100, 200}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseKeyIDs(tt.buf)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d ids, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("id[%d]: got %d, want %d", i, got[i], tt.want[i])
				}
			}
		})
	}
}
