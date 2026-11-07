package geoscore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/valkey-io/valkey-go"
)

// ValkeyStore is a Store backed by Valkey: one MGET per refresh for all of a
// name's endpoint keys. Modelled on probe's ValkeyStore (probe/valkey.go).
type ValkeyStore struct {
	client valkey.Client
}

// ValkeyConfig is what the Corefile supplies.
type ValkeyConfig struct {
	// CAFile, when set, enables TLS and verifies the server certificate
	// against this bundle. The Corefile path requires it (see setup): the
	// scores decide where clients are sent, so they must not be readable
	// or forgeable on the path. As in probe, there is no "skip
	// verification" option.
	CAFile string
	// Addrs are host:port endpoints.
	Addrs []string
}

var errNoValkeyAddrs = errors.New("geoscore: no valkey addresses configured")

// NewValkeyStore connects and returns a Store. It fails rather than degrading:
// a misconfigured store must stop the server from starting, not quietly turn
// every answer into the fallback.
func NewValkeyStore(cfg ValkeyConfig) (*ValkeyStore, error) {
	if len(cfg.Addrs) == 0 {
		return nil, errNoValkeyAddrs
	}
	opt := valkey.ClientOption{
		InitAddress: cfg.Addrs,
		// The plugin keeps its own snapshot and re-reads on its refresh
		// interval; server-assisted client caching would add invalidation
		// traffic for no gain.
		DisableCache: true,
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("geoscore: reading valkey CA %s: %w", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("geoscore: valkey CA %s contains no usable certificate", cfg.CAFile)
		}
		opt.TLSConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	client, err := valkey.NewClient(opt)
	if err != nil {
		return nil, fmt.Errorf("geoscore: connecting to valkey %v: %w", cfg.Addrs, err)
	}
	return &ValkeyStore{client: client}, nil
}

// Get implements Store with a single MGET.
func (s *ValkeyStore) Get(ctx context.Context, keys []string) ([][]byte, error) {
	if s.client == nil {
		return nil, errStoreClosed
	}
	c := s.client
	msgs, err := c.Do(ctx, c.B().Mget().Key(keys...).Build()).ToArray()
	if err != nil {
		return nil, fmt.Errorf("geoscore: valkey MGET: %w", err)
	}
	if len(msgs) != len(keys) {
		return nil, fmt.Errorf("geoscore: valkey MGET returned %d values for %d keys", len(msgs), len(keys))
	}
	out := make([][]byte, len(keys))
	for i := range msgs {
		if msgs[i].IsNil() {
			continue
		}
		b, err := msgs[i].AsBytes()
		if err != nil {
			return nil, fmt.Errorf("geoscore: valkey value for %s: %w", keys[i], err)
		}
		out[i] = b
	}
	return out, nil
}

// Close implements Store.
func (s *ValkeyStore) Close() error {
	if s.client != nil {
		s.client.Close()
	}
	return nil
}
