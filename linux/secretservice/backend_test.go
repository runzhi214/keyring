//go:build linux

package secretservice

import (
	"context"
	"testing"
	"time"

	"github.com/runzhi214/keyring/contracttest"
	"github.com/runzhi214/keyring/core"
)

func TestContract(t *testing.T) {
	b := New()
	if !b.Available().OK {
		t.Skipf("Secret Service not available: %s (%s)",
			b.Available().Reason, b.Available().Detail)
	}
	ctx := context.Background()
	t.Cleanup(func() {
		services := []string{
			"ss-test-roundtrip", "ss-test-notfound",
			"ss-test-deleteidem", "ss-test-emptyval",
			"ss-test-listkeys", "ss-test-delfromlist",
			"ss-test-update", "ss-test-iso-a",
			"ss-test-iso-b", "ss-test-cross-a",
			"ss-test-cross-b", "ss-test-concurrent",
			"ss-test-cancelled",
		}
		for _, s := range services {
			keys, _ := b.List(ctx, s)
			for _, k := range keys {
				_ = b.Delete(ctx, s, k)
			}
		}
	})
	contracttest.RunContractTests(t, b, func() core.Backend { return New() }, "ss-test")
}

func TestMetadataRoundtrip(t *testing.T) {
	b := New()
	if !b.Available().OK {
		t.Skipf("Secret Service not available")
	}
	ctx := context.Background()
	svc := "ss-metadata-test"
	keyName := "meta-key"
	t.Cleanup(func() {
		_ = b.Delete(ctx, svc, keyName)
	})

	want := core.Secret{
		Value:      "metadata-secret",
		Label:      "Test Metadata Label",
		Attributes: map[string]string{"env": "test", "owner": "contracttest"},
	}
	if err := b.Set(ctx, svc, keyName, want); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := b.Get(ctx, svc, keyName)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.Label != want.Label {
		t.Errorf("Label: got %q, want %q", got.Label, want.Label)
	}
	if got.Created.IsZero() {
		t.Error("Created is zero, want non-zero")
	}
	if got.Modified.IsZero() {
		t.Error("Modified is zero, want non-zero")
	}
	if got.Modified.Before(got.Created) {
		t.Errorf("Modified %v before Created %v", got.Modified, got.Created)
	}
	for k, v := range want.Attributes {
		if got.Attributes[k] != v {
			t.Errorf("Attributes[%q]: got %q, want %q", k, got.Attributes[k], v)
		}
	}
}

func TestListFindsMultipleKeys(t *testing.T) {
	b := New()
	if !b.Available().OK {
		t.Skipf("Secret Service not available")
	}
	ctx := context.Background()
	svc := "ss-list-multi-test"
	t.Cleanup(func() {
		keys, _ := b.List(ctx, svc)
		for _, k := range keys {
			_ = b.Delete(ctx, svc, k)
		}
	})

	for i := 0; i < 5; i++ {
		keyName := "key-" + string(rune('A'+i))
		if err := b.Set(ctx, svc, keyName, core.Secret{Value: "val"}); err != nil {
			t.Fatalf("Set %s: %v", keyName, err)
		}
	}

	keys, err := b.List(ctx, svc)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 5 {
		t.Fatalf("List: got %d keys, want 5", len(keys))
	}
}

func TestUpdatePreservesCreated(t *testing.T) {
	b := New()
	if !b.Available().OK {
		t.Skipf("Secret Service not available")
	}
	ctx := context.Background()
	svc := "ss-update-created-test"
	keyName := "up-key"
	t.Cleanup(func() {
		_ = b.Delete(ctx, svc, keyName)
	})

	if err := b.Set(ctx, svc, keyName, core.Secret{Value: "first"}); err != nil {
		t.Fatalf("Set first: %v", err)
	}
	first, err := b.Get(ctx, svc, keyName)
	if err != nil {
		t.Fatalf("Get first: %v", err)
	}
	if first.Created.IsZero() {
		t.Skip("Created not supported by backend, skipping")
	}

	time.Sleep(1100 * time.Millisecond)

	if err := b.Set(ctx, svc, keyName, core.Secret{Value: "second"}); err != nil {
		t.Fatalf("Set second: %v", err)
	}
	second, err := b.Get(ctx, svc, keyName)
	if err != nil {
		t.Fatalf("Get second: %v", err)
	}

	if !second.Created.Equal(first.Created) {
		t.Errorf("Created changed: first=%v second=%v", first.Created, second.Created)
	}
	if !second.Modified.After(first.Modified) {
		t.Errorf("Modified not updated: first=%v second=%v", first.Modified, second.Modified)
	}
}
