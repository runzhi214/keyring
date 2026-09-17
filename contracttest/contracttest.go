// Package contracttest provides a shared contract test suite for all
// core.Backend implementations.
//
// Each platform backend and the in-memory store should call RunContractTests
// from their own _test.go file to verify behavioral consistency:
//
//	func TestContract(t *testing.T) {
//	    contracttest.RunContractTests(t, newTestBackend(t), func() core.Backend {
//	        return newTestBackend(t)
//	    }, "keyctl-test")
//	}
//
// The servicePrefix parameter namespaces all service names used in the test
// suite, preventing collisions when multiple backends share the same
// underlying storage (e.g. keyctl and Secret Service both writing to the
// same kernel keyring or D-Bus service during parallel test runs).
//
// This package is only imported from test files, so it never appears in
// production binaries.
package contracttest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/runzhi214/keyring/core"
)

// svc builds a service name from the prefix and a suffix.
func svc(prefix, suffix string) string {
	return prefix + "-" + suffix
}

// RunContractTests verifies that a Backend implementation satisfies the
// behavioral contract shared by all backends.
//
// The b parameter is used for single-instance tests. The factory parameter
// creates a fresh instance for tests that need isolation. The servicePrefix
// parameter namespaces all service names to avoid collisions when multiple
// backends share the same underlying storage.
func RunContractTests(t *testing.T, b core.Backend, factory func() core.Backend, servicePrefix string) {
	t.Helper()

	// Collect all service names used so we can clean up after the suite.
	var services []string
	var cleanupMu sync.Mutex
	registerService := func(name string) string {
		cleanupMu.Lock()
		services = append(services, name)
		cleanupMu.Unlock()
		return name
	}

	t.Cleanup(func() {
		ctx := context.Background()
		for _, s := range services {
			keys, _ := b.List(ctx, s)
			for _, k := range keys {
				_ = b.Delete(ctx, s, k)
			}
		}
	})

	t.Run("Available", func(t *testing.T) {
		avail := b.Available()
		if !avail.OK {
			t.Fatalf("Available() = false, reason=%s detail=%s; want OK",
				avail.Reason, avail.Detail)
		}
	})

	t.Run("Persistence", func(t *testing.T) {
		p := b.Persistence()
		if p < core.Persistent || p > core.ProcessOnly {
			t.Fatalf("Persistence() = %d; want a valid Persistence value", p)
		}
	})

	t.Run("SetGetRoundtrip", func(t *testing.T) {
		b := factory()
		ctx := context.Background()
		s := registerService(svc(servicePrefix, "roundtrip"))
		want := core.Secret{
			Value:      "test-secret-value",
			Label:      "test label",
			Attributes: map[string]string{"env": "test"},
		}
		if err := b.Set(ctx, s, "rt-key", want); err != nil {
			t.Fatalf("Set: %v", err)
		}
		got, err := b.Get(ctx, s, "rt-key")
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
		s := registerService(svc(servicePrefix, "notfound"))
		_, err := b.Get(ctx, s, "nonexistent")
		var nfe *core.NotFoundError
		if !errors.As(err, &nfe) {
			t.Fatalf("Get non-existent: got %v, want *NotFoundError", err)
		}
		if nfe.Service != s || nfe.Key != "nonexistent" {
			t.Errorf("NotFoundError fields: service=%q key=%q, want %q/nonexistent",
				nfe.Service, nfe.Key, s)
		}
	})

	t.Run("DeleteIdempotent", func(t *testing.T) {
		b := factory()
		ctx := context.Background()
		s := registerService(svc(servicePrefix, "deleteidem"))
		if err := b.Delete(ctx, s, "never-existed"); err != nil {
			t.Fatalf("Delete non-existent: got %v, want nil", err)
		}
	})

	t.Run("SetEmptyValueRejected", func(t *testing.T) {
		b := factory()
		ctx := context.Background()
		s := registerService(svc(servicePrefix, "emptyval"))
		err := b.Set(ctx, s, "empty", core.Secret{Value: ""})
		if !errors.Is(err, core.ErrEmptyValue) {
			t.Fatalf("Set empty value: got %v, want ErrEmptyValue", err)
		}
	})

	t.Run("ListReflectsStoredKeys", func(t *testing.T) {
		b := factory()
		ctx := context.Background()
		s := registerService(svc(servicePrefix, "listkeys"))
		_ = b.Set(ctx, s, "key-a", core.Secret{Value: "a"})
		_ = b.Set(ctx, s, "key-b", core.Secret{Value: "b"})
		_ = b.Set(ctx, s, "key-c", core.Secret{Value: "c"})

		keys, err := b.List(ctx, s)
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
		s := svc(servicePrefix, "nosuchservice") + fmt.Sprintf("-%d", time.Now().UnixNano())
		keys, err := b.List(ctx, s)
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
		s := registerService(svc(servicePrefix, "delfromlist"))
		_ = b.Set(ctx, s, "to-delete", core.Secret{Value: "x"})
		_ = b.Set(ctx, s, "to-keep", core.Secret{Value: "y"})

		if err := b.Delete(ctx, s, "to-delete"); err != nil {
			t.Fatalf("Delete: %v", err)
		}

		keys, _ := b.List(ctx, s)
		for _, k := range keys {
			if k == "to-delete" {
				t.Error("List still contains deleted key 'to-delete'")
			}
		}
	})

	t.Run("SetUpdatesExisting", func(t *testing.T) {
		b := factory()
		ctx := context.Background()
		s := registerService(svc(servicePrefix, "update"))
		first := core.Secret{Value: "first"}
		if err := b.Set(ctx, s, "up-key", first); err != nil {
			t.Fatalf("Set first: %v", err)
		}
		time.Sleep(1 * time.Millisecond)
		second := core.Secret{Value: "second"}
		if err := b.Set(ctx, s, "up-key", second); err != nil {
			t.Fatalf("Set second: %v", err)
		}
		got, err := b.Get(ctx, s, "up-key")
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
		sA := registerService(svc(servicePrefix, "iso-a"))
		sB := registerService(svc(servicePrefix, "iso-b"))
		_ = b.Set(ctx, sA, "shared-key", core.Secret{Value: "from-a"})
		_ = b.Set(ctx, sB, "shared-key", core.Secret{Value: "from-b"})

		gotA, _ := b.Get(ctx, sA, "shared-key")
		gotB, _ := b.Get(ctx, sB, "shared-key")
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
		sA := registerService(svc(servicePrefix, "cross-a"))
		sB := registerService(svc(servicePrefix, "cross-b"))
		_ = b.Set(ctx, sA, "key", core.Secret{Value: "a"})
		_ = b.Set(ctx, sB, "key", core.Secret{Value: "b"})

		_ = b.Delete(ctx, sA, "key")
		gotB, err := b.Get(ctx, sB, "key")
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
		s := registerService(svc(servicePrefix, "concurrent"))
		const goroutines = 20
		const iterations = 50

		var wg sync.WaitGroup
		wg.Add(goroutines * 2)

		for i := 0; i < goroutines; i++ {
			go func() {
				defer wg.Done()
				for j := 0; j < iterations; j++ {
					_ = b.Set(ctx, s, "key", core.Secret{
						Value: "concurrent-value",
					})
				}
			}()
		}
		for i := 0; i < goroutines; i++ {
			go func() {
				defer wg.Done()
				for j := 0; j < iterations; j++ {
					_, _ = b.Get(ctx, s, "key")
				}
			}()
		}
		wg.Wait()
	})

	t.Run("CtxCancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		s := registerService(svc(servicePrefix, "cancelled"))
		err := b.Set(ctx, s, "cancelled-key", core.Secret{Value: "x"})
		if !errors.Is(err, context.Canceled) {
			t.Logf("Set with cancelled ctx: got %v (backends may ignore ctx for non-blocking ops)", err)
		}
	})
}
