// Package contracttest provides a shared contract test suite for all
// keyring.Backend implementations.
//
// Each platform backend and the in-memory store should call RunContractTests
// from their own _test.go file to verify behavioral consistency:
//
//	func TestContract(t *testing.T) {
//	    contracttest.RunContractTests(t, newTestBackend(t), func() keyring.Backend {
//	        return newTestBackend(t)
//	    })
//	}
//
// This package is only imported from test files, so it never appears in
// production binaries.
package contracttest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/runzhi214/keyring"
)

// RunContractTests verifies that a Backend implementation satisfies the
// behavioral contract shared by all backends.
//
// The b parameter is used for single-instance tests. The factory parameter
// creates a fresh instance for tests that need isolation.
func RunContractTests(t *testing.T, b keyring.Backend, factory func() keyring.Backend) {
	t.Helper()

	t.Run("Available", func(t *testing.T) {
		avail := b.Available()
		if !avail.OK {
			t.Fatalf("Available() = false, reason=%s detail=%s; want OK",
				avail.Reason, avail.Detail)
		}
	})

	t.Run("Persistence", func(t *testing.T) {
		p := b.Persistence()
		if p < keyring.Persistent || p > keyring.ProcessOnly {
			t.Fatalf("Persistence() = %d; want a valid Persistence value", p)
		}
	})

	t.Run("SetGetRoundtrip", func(t *testing.T) {
		b := factory()
		ctx := context.Background()
		want := keyring.Secret{
			Value:      "test-secret-value",
			Label:      "test label",
			Attributes: map[string]string{"env": "test"},
		}
		if err := b.Set(ctx, "contract", "roundtrip", want); err != nil {
			t.Fatalf("Set: %v", err)
		}
		got, err := b.Get(ctx, "contract", "roundtrip")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Value != want.Value {
			t.Errorf("Value: got %q, want %q", got.Value, want.Value)
		}
	})

	t.Run("GetNotFound", func(t *testing.T) {
		b := factory()
		ctx := context.Background()
		_, err := b.Get(ctx, "contract", "nonexistent")
		var nfe *keyring.NotFoundError
		if !errors.As(err, &nfe) {
			t.Fatalf("Get non-existent: got %v, want *NotFoundError", err)
		}
		if nfe.Service != "contract" || nfe.Key != "nonexistent" {
			t.Errorf("NotFoundError fields: service=%q key=%q, want contract/nonexistent",
				nfe.Service, nfe.Key)
		}
	})

	t.Run("DeleteIdempotent", func(t *testing.T) {
		b := factory()
		ctx := context.Background()
		if err := b.Delete(ctx, "contract", "never-existed"); err != nil {
			t.Fatalf("Delete non-existent: got %v, want nil", err)
		}
	})

	t.Run("SetEmptyValueRejected", func(t *testing.T) {
		b := factory()
		ctx := context.Background()
		err := b.Set(ctx, "contract", "empty", keyring.Secret{Value: ""})
		if !errors.Is(err, keyring.ErrEmptyValue) {
			t.Fatalf("Set empty value: got %v, want ErrEmptyValue", err)
		}
	})

	t.Run("ListReflectsStoredKeys", func(t *testing.T) {
		b := factory()
		ctx := context.Background()
		_ = b.Set(ctx, "contract", "key-a", keyring.Secret{Value: "a"})
		_ = b.Set(ctx, "contract", "key-b", keyring.Secret{Value: "b"})
		_ = b.Set(ctx, "contract", "key-c", keyring.Secret{Value: "c"})

		keys, err := b.List(ctx, "contract")
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(keys) != 3 {
			t.Fatalf("List: got %d keys, want 3", len(keys))
		}
		want := map[string]bool{"key-a": true, "key-b": true, "key-c": true}
		for _, k := range keys {
			if !want[k] {
				t.Errorf("List: unexpected key %q", k)
			}
		}
	})

	t.Run("ListEmptyService", func(t *testing.T) {
		b := factory()
		ctx := context.Background()
		keys, err := b.List(ctx, "no-such-service")
		if err != nil {
			t.Fatalf("List on non-existent service: got %v, want nil", err)
		}
		if len(keys) != 0 {
			t.Fatalf("List on non-existent service: got %d keys, want 0", len(keys))
		}
	})

	t.Run("DeleteRemovesFromList", func(t *testing.T) {
		b := factory()
		ctx := context.Background()
		_ = b.Set(ctx, "contract", "to-delete", keyring.Secret{Value: "x"})
		_ = b.Set(ctx, "contract", "to-keep", keyring.Secret{Value: "y"})

		if err := b.Delete(ctx, "contract", "to-delete"); err != nil {
			t.Fatalf("Delete: %v", err)
		}

		keys, _ := b.List(ctx, "contract")
		for _, k := range keys {
			if k == "to-delete" {
				t.Error("List still contains deleted key 'to-delete'")
			}
		}
	})

	t.Run("SetUpdatesExisting", func(t *testing.T) {
		b := factory()
		ctx := context.Background()
		first := keyring.Secret{Value: "first"}
		if err := b.Set(ctx, "contract", "update", first); err != nil {
			t.Fatalf("Set first: %v", err)
		}
		time.Sleep(1 * time.Millisecond)
		second := keyring.Secret{Value: "second"}
		if err := b.Set(ctx, "contract", "update", second); err != nil {
			t.Fatalf("Set second: %v", err)
		}
		got, err := b.Get(ctx, "contract", "update")
		if err != nil {
			t.Fatalf("Get after update: %v", err)
		}
		if got.Value != "second" {
			t.Errorf("Value after update: got %q, want %q", got.Value, "second")
		}
	})

	t.Run("ServicesAreIsolated", func(t *testing.T) {
		b := factory()
		ctx := context.Background()
		_ = b.Set(ctx, "svc-a", "shared-key", keyring.Secret{Value: "from-a"})
		_ = b.Set(ctx, "svc-b", "shared-key", keyring.Secret{Value: "from-b"})

		gotA, _ := b.Get(ctx, "svc-a", "shared-key")
		gotB, _ := b.Get(ctx, "svc-b", "shared-key")
		if gotA.Value != "from-a" {
			t.Errorf("svc-a: got %q, want %q", gotA.Value, "from-a")
		}
		if gotB.Value != "from-b" {
			t.Errorf("svc-b: got %q, want %q", gotB.Value, "from-b")
		}
	})

	t.Run("DeleteDoesNotCrossServices", func(t *testing.T) {
		b := factory()
		ctx := context.Background()
		_ = b.Set(ctx, "svc-a", "key", keyring.Secret{Value: "a"})
		_ = b.Set(ctx, "svc-b", "key", keyring.Secret{Value: "b"})

		_ = b.Delete(ctx, "svc-a", "key")
		gotB, err := b.Get(ctx, "svc-b", "key")
		if err != nil {
			t.Fatalf("Get svc-b after deleting svc-a: %v", err)
		}
		if gotB.Value != "b" {
			t.Errorf("svc-b value: got %q, want %q", gotB.Value, "b")
		}
	})

	t.Run("ConcurrentAccess", func(t *testing.T) {
		b := factory()
		ctx := context.Background()
		const goroutines = 20
		const iterations = 50

		var wg sync.WaitGroup
		wg.Add(goroutines * 2)

		for i := 0; i < goroutines; i++ {
			go func() {
				defer wg.Done()
				for j := 0; j < iterations; j++ {
					_ = b.Set(ctx, "concurrent", "key", keyring.Secret{
						Value: "concurrent-value",
					})
				}
			}()
		}
		for i := 0; i < goroutines; i++ {
			go func() {
				defer wg.Done()
				for j := 0; j < iterations; j++ {
					_, _ = b.Get(ctx, "concurrent", "key")
				}
			}()
		}
		wg.Wait()
	})

	t.Run("CtxCancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := b.Set(ctx, "contract", "cancelled", keyring.Secret{Value: "x"})
		if !errors.Is(err, context.Canceled) {
			t.Logf("Set with cancelled ctx: got %v (backends may ignore ctx for non-blocking ops)", err)
		}
	})
}
