package geoscore

import (
	"context"
	"errors"
	"sync"
)

// Store is where the score map lives. The plugin only reads it; a separate
// writer (a CronJob polling latency, carbon intensity, cost or health) keeps
// it current. Same seam as probe's Store: the plugin and the writer share a
// key space and nothing else.
type Store interface {
	// Get returns one value per key, in order, nil where a key does not
	// exist. It must honour ctx: the plugin bounds every read.
	Get(ctx context.Context, keys []string) ([][]byte, error)
	// Close releases the store's resources.
	Close() error
}

// MemStore is an in-process Store, for tests and for a Corefile that wants
// the plugin's behaviour without a writer (`store memory`: nothing can write
// to it from outside, so every answer is the fallback).
type MemStore struct {
	err error
	m   map[string][]byte
	mu  sync.RWMutex
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore { return &MemStore{m: map[string][]byte{}} }

// Set stores a copy of v at key.
func (s *MemStore) Set(key string, v []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = append([]byte(nil), v...)
}

// Delete removes key.
func (s *MemStore) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
}

// Fail makes every Get return err until Fail(nil): a store outage, for tests.
func (s *MemStore) Fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

// Get implements Store.
func (s *MemStore) Get(ctx context.Context, keys []string) ([][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err //nolint:wrapcheck // the context's own error, as a real store would return it
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.err != nil {
		return nil, s.err
	}
	out := make([][]byte, len(keys))
	for i, k := range keys {
		if v, ok := s.m[k]; ok {
			out[i] = append([]byte(nil), v...)
		}
	}
	return out, nil
}

// Close implements Store.
func (*MemStore) Close() error { return nil }

var errStoreClosed = errors.New("geoscore: store closed")
