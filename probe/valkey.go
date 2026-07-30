package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/valkey-io/valkey-go"
)

// Why a shared store exists
//
// MemStore is per-process, and the two halves of this system are different
// processes: this plugin writes observations, a separate web tier reads them
// back by token. Even within the DNS tier a second replica breaks the
// in-process store, because a visitor's queries and their report request would
// have to land on the same pod by luck.
//
// Valkey is the seam. It is also the ONLY thing the two programs share — no
// linked code, no shared library, just a key space — which is what keeps the
// MIT plugin and the AGPL web tier at arm's length from each other.
//
// Data model, one token per visit:
//
//	probe:seen:<token>  counter, INCR per query   — authoritative query count
//	probe:obs:<token>   list of JSON observations — detail, capped
//
// The count is a separate key from the list on purpose: the list is capped so a
// resolver hammering one name cannot grow it without limit, but the count must
// stay truthful past that cap, because "we saw this 200 times" is itself the
// interesting finding.

// ValkeyStore is a Store backed by Valkey.
type ValkeyStore struct {
	client valkey.Client
	// ttl bounds how long a token stays readable. Applied to both keys on every
	// write, keyed on the write rather than on first-seen — see Record.
	ttl time.Duration
	// timeout bounds how long a single store round-trip may delay a DNS answer.
	timeout time.Duration
	// maxPerToken caps retained detail per token.
	maxPerToken int
}

// defaultValkeyTimeout keeps a slow or wedged store from turning into slow DNS.
// Every probe query does one round-trip, so this is added latency on the
// serving path — deliberately tight, and exceeding it degrades the measurement
// rather than failing the query.
const defaultValkeyTimeout = 100 * time.Millisecond

// ValkeyConfig is what the Corefile supplies.
type ValkeyConfig struct {
	// Addrs are host:port endpoints.
	Addrs []string
	// CAFile, when set, enables TLS and verifies the server certificate against
	// this bundle. The fleet's Valkey presents a step-ca-issued certificate, so
	// this should normally be the step-ca root.
	CAFile string
	// TTL, Timeout and MaxPerToken mirror MemStore's bounds.
	TTL         time.Duration
	Timeout     time.Duration
	MaxPerToken int
}

// NewValkeyStore connects and returns a Store.
//
// It fails rather than degrading silently: falling back to an in-process store
// would leave the zone answering perfectly while recording observations nobody
// can read, which is the worst outcome — the measurement looks healthy and
// isn't. This plugin runs in its own Deployment, separate from LAN DNS, so a
// hard failure here costs the lab zone and nothing else.
func NewValkeyStore(cfg ValkeyConfig) (*ValkeyStore, error) {
	if len(cfg.Addrs) == 0 {
		return nil, fmt.Errorf("no valkey addresses configured")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = defaultStoreTTL
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultValkeyTimeout
	}
	if cfg.MaxPerToken <= 0 {
		cfg.MaxPerToken = defaultMaxPerToken
	}

	opt := valkey.ClientOption{
		InitAddress: cfg.Addrs,
		// Client-side caching tracks keys the server invalidates. These keys are
		// written far more often than read and expire in minutes, so caching
		// would cost invalidation traffic for no hit rate.
		DisableCache: true,
	}

	// There is deliberately no "skip verification" option. The fleet's Valkey
	// presents a step-ca-issued certificate, so verification can always be
	// satisfied by pointing CAFile at the step-ca root — an escape hatch would
	// only ever be used to paper over a misconfigured CA path, and this store
	// carries observations about other people's networks across a network that
	// has no Valkey authentication of its own.
	//
	// Plaintext (no CAFile) remains reachable through this constructor for a
	// local test server; the Corefile path requires TLS, see setup.
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading valkey CA %s: %w", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("valkey CA %s contains no usable certificate", cfg.CAFile)
		}
		opt.TLSConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}

	client, err := valkey.NewClient(opt)
	if err != nil {
		return nil, fmt.Errorf("connecting to valkey %v: %w", cfg.Addrs, err)
	}

	return &ValkeyStore{
		client:      client,
		ttl:         cfg.TTL,
		timeout:     cfg.Timeout,
		maxPerToken: cfg.MaxPerToken,
	}, nil
}

// Close releases the connection pool.
func (s *ValkeyStore) Close() { s.client.Close() }

func seenKey(token string) string { return "probe:seen:" + token }
func obsKey(token string) string  { return "probe:obs:" + token }

// Record implements Store.
//
// The counter is incremented first and its value becomes Seen, so the count is
// correct even when the detail list is already at its cap and even across
// replicas. Both keys get their expiry refreshed on every write: unlike
// MemStore (which expires on first-seen so a token cannot be kept alive by
// continued querying) a shared store has no cheap way to know first-seen
// without an extra round-trip, and the cap on retained detail already bounds
// what continued querying can achieve.
func (s *ValkeyStore) Record(obs Observation) (Observation, error) {
	if obs.At.IsZero() {
		obs.At = time.Now().UTC()
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	c := s.client
	ttl := int64(s.ttl.Seconds())

	n, err := c.Do(ctx, c.B().Incr().Key(seenKey(obs.Token)).Build()).AsInt64()
	if err != nil {
		// Seen stays 0, which the in-band readout renders honestly rather than
		// inventing a count.
		return obs, fmt.Errorf("valkey INCR: %w", err)
	}
	obs.Seen = int(n)

	// Fire-and-check the remaining writes together; a partial failure here
	// costs detail, not the answer.
	cmds := []valkey.Completed{
		c.B().Expire().Key(seenKey(obs.Token)).Seconds(ttl).Build(),
	}
	if obs.Seen <= s.maxPerToken {
		payload, err := json.Marshal(obs)
		if err != nil {
			return obs, fmt.Errorf("marshalling observation: %w", err)
		}
		cmds = append(cmds,
			c.B().Rpush().Key(obsKey(obs.Token)).Element(string(payload)).Build(),
			c.B().Expire().Key(obsKey(obs.Token)).Seconds(ttl).Build(),
		)
	}
	for _, res := range c.DoMulti(ctx, cmds...) {
		if err := res.Error(); err != nil {
			return obs, fmt.Errorf("valkey write: %w", err)
		}
	}
	return obs, nil
}

// Lookup implements Store. Read path only — the web tier is the usual caller,
// but keeping it here means the plugin's own tests exercise the same encoding
// the web tier will decode.
func (s *ValkeyStore) Lookup(token string) ([]Observation, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	c := s.client
	vals, err := c.Do(ctx, c.B().Lrange().Key(obsKey(token)).Start(0).Stop(-1).Build()).AsStrSlice()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("valkey LRANGE: %w", err)
	}

	out := make([]Observation, 0, len(vals))
	for _, v := range vals {
		var obs Observation
		if err := json.Unmarshal([]byte(v), &obs); err != nil {
			// One corrupt entry must not hide the rest: this data is diagnostic,
			// and a partial report beats no report.
			log.Warningf("skipping unparseable observation for token %s: %v", token, err)
			continue
		}
		out = append(out, obs)
	}
	return out, nil
}

// SeenCount returns the authoritative query count for a token, which can exceed
// the number of retained observations once the per-token cap is hit.
func (s *ValkeyStore) SeenCount(token string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	c := s.client
	n, err := c.Do(ctx, c.B().Get().Key(seenKey(token)).Build()).AsInt64()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("valkey GET: %w", err)
	}
	return int(n), nil
}
