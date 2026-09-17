// Package mem provides an in-memory keyring backend for testing and as a
// last-resort fallback when no persistent backend is available.
//
// Secrets do NOT persist across process restarts. Use mem.New to create
// an instance.
package mem

import (
	"context"
	"sync"
	"time"

	"github.com/runzhi214/keyring/core"
)

// Store is an in-memory keyring. It is safe for concurrent use.
type Store struct {
	mu   sync.RWMutex
	data map[string]map[string]core.Secret // service → key → secret
}

// New creates an in-memory keyring.
func New() *Store {
	return &Store{data: make(map[string]map[string]core.Secret)}
}

func (s *Store) Available() core.Availability {
	return core.Availability{OK: true, Reason: core.ReasonOK}
}

func (s *Store) Get(_ context.Context, service, key string) (core.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	svc, ok := s.data[service]
	if !ok {
		return core.Secret{}, &core.NotFoundError{Service: service, Key: key}
	}
	secret, ok := svc[key]
	if !ok {
		return core.Secret{}, &core.NotFoundError{Service: service, Key: key}
	}
	return secret, nil
}

func (s *Store) Set(_ context.Context, service, key string, secret core.Secret) error {
	if secret.Value == "" {
		return core.ErrEmptyValue
	}

	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	svc, ok := s.data[service]
	if !ok {
		svc = make(map[string]core.Secret)
		s.data[service] = svc
	}

	if existing, ok := svc[key]; ok {
		secret.Created = existing.Created
	} else {
		secret.Created = now
	}
	secret.Modified = now

	svc[key] = secret
	return nil
}

func (s *Store) Delete(_ context.Context, service, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	svc, ok := s.data[service]
	if !ok {
		return nil
	}
	delete(svc, key)
	if len(svc) == 0 {
		delete(s.data, service)
	}
	return nil
}

func (s *Store) List(_ context.Context, service string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	svc, ok := s.data[service]
	if !ok {
		return nil, nil
	}

	keys := make([]string, 0, len(svc))
	for k := range svc {
		keys = append(keys, k)
	}
	return keys, nil
}

func (s *Store) Persistence() core.Persistence {
	return core.ProcessOnly
}
