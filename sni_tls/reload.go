package snitls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"os"
	"sync"
	"sync/atomic"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
)

var log = clog.NewWithPlugin("sni_tls")

// reloadInterval is fixed rather than Corefile-configurable: cert renewal
// runs on an hour-to-day cadence, so polling every 30s catches rotation
// promptly for negligible cost, and the tradeoff doesn't vary enough
// per-deployment to justify the syntax.
const reloadInterval = 30 * time.Second

// liveStore holds the active certStore behind an atomic.Pointer so
// GetCertificate never blocks on, or races with, a reload swap.
//
// It exists because coredns/plugin/reload can't do this for us: it hashes
// the parsed Corefile, not the cert files a directive names, so a cert
// rotated at the same path (the k8s Secret symlink-swap pattern) never
// changes that hash and reload never restarts the server. Rotation has to be
// polled in-process instead.
//
// The reloadMu field serialises reloadOnce. The current and digest fields
// are two separate stores, so two concurrent reloads can interleave them and
// leave an older certificate installed beside a newer digest; since the
// digest then matches the files on disk, no later poll ever replaces it. One
// poll loop per liveStore is what OnStartup aims for, but caddy can call it
// twice (see OnStartup), and the outgoing loop may still be mid-reload when
// its replacement starts. See verification/tla/SniTlsReload.tla, which
// checks both the failure and this fix.
type liveStore struct {
	current atomic.Pointer[certStore]
	digest  atomic.Pointer[[32]byte]
	// The owner field is the caddy instance this store was set up for (its
	// server-type context), compared by identity; see pollers.
	owner    any
	running  *pollerHandle
	pairs    [][2]string
	reloadMu sync.Mutex
	strict   bool
}

// pollerHandle is one running poll loop, and the instance that started it.
type pollerHandle struct {
	owner  any
	cancel context.CancelFunc
}

// pollers holds every poll loop this process has started and not yet
// stopped. Caddy can drop an instance without calling any of its shutdown
// hooks: when a reload fails after the new instance's OnStartup already ran
// (a later plugin's OnStartup errors, or a listener cannot bind), the new
// instance is discarded and the old one gets OnRestartFailed. Its poller
// would otherwise run until the process exits.
//
// So every OnStartup first stops the pollers of every OTHER instance. At
// most one caddy instance is live, so that is always safe: on a successful
// reload the old instance's pollers were already stopped by its OnRestart,
// and on a failed one this reclaims the discarded instance's. Pollers of the
// same instance (several server blocks) are left alone. See
// verification/tla/PluginLifecycle.tla.
var (
	pollersMu sync.Mutex
	pollers   = map[*pollerHandle]struct{}{}
)

// newLiveStore wraps an already-loaded certStore for polling; setup() still
// fails loudly on the initial buildCertStore error before reaching this.
func newLiveStore(pairs [][2]string, strict bool, initial *certStore, initialDigest [32]byte) *liveStore {
	l := &liveStore{pairs: pairs, strict: strict}
	l.current.Store(initial)
	l.digest.Store(&initialDigest)
	return l
}

// GetCertificate implements tls.Config.GetCertificate against whichever
// certStore is currently active.
func (l *liveStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return l.current.Load().GetCertificate(hello)
}

// OnStartup starts the poll loop. Doubles as setup.go's OnRestartFailed: if
// an unrelated Corefile change fails to restart the server, this resumes
// polling on the still-live old instance, matching radnr's lifecycle
// convention.
//
// This store's own loop may already be running too. When another plugin's
// OnRestart fails, caddy runs every plugin's OnRestartFailed, including
// those whose OnRestart (our OnShutdown) never ran; keeping that loop would
// leave two loops writing one store.
func (l *liveStore) OnStartup() error {
	ctx, cancel := context.WithCancel(context.Background())
	l.adopt(cancel)
	go l.run(ctx)
	return nil
}

// OnShutdown stops the poll loop; wired to both OnRestart (server tearing
// down for a Corefile-driven restart) and OnFinalShutdown (process exit).
func (l *liveStore) OnShutdown() error {
	pollersMu.Lock()
	defer pollersMu.Unlock()
	if l.running != nil {
		l.running.cancel()
		delete(pollers, l.running)
		l.running = nil
	}
	return nil
}

// adopt registers cancel as l's running loop, stopping l's previous loop and
// every loop some other caddy instance left running.
func (l *liveStore) adopt(cancel context.CancelFunc) {
	pollersMu.Lock()
	defer pollersMu.Unlock()
	for h := range pollers {
		if h == l.running || h.owner != l.owner {
			h.cancel()
			delete(pollers, h)
		}
	}
	l.running = &pollerHandle{owner: l.owner, cancel: cancel}
	pollers[l.running] = struct{}{}
}

// run polls reloadInterval until ctx is canceled.
func (l *liveStore) run(ctx context.Context) {
	ticker := time.NewTicker(reloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.reloadOnce()
		case <-ctx.Done():
			return
		}
	}
}

// reloadOnce rebuilds and swaps in the certStore only if the configured
// files' digest changed since the last successful load. A rebuild failure
// (e.g. caught mid-rotation) is logged and the previous store kept — a
// transient reload error must never blank an already-running TLS listener.
func (l *liveStore) reloadOnce() {
	l.reloadMu.Lock()
	defer l.reloadMu.Unlock()

	newDigest := digestPairs(l.pairs)
	if newDigest == *l.digest.Load() {
		return
	}
	store, err := buildCertStore(l.pairs, l.strict)
	if err != nil {
		log.Warningf("cert reload skipped, keeping previous store: %v", err)
		return
	}
	l.current.Store(store)
	l.digest.Store(&newDigest)
	log.Infof("reloaded %d configured cert/key pair(s) from disk", len(l.pairs))
}

// digestPairs hashes every configured cert/key file's raw bytes, in order. A
// missing file hashes a fixed sentinel instead of erroring, so a
// still-missing file and a newly-missing one produce the same stable
// digest — mirrors buildCertStore's own tolerance of missing files.
func digestPairs(pairs [][2]string) [32]byte {
	h := sha256.New()
	for _, p := range pairs {
		for _, path := range p {
			b, err := os.ReadFile(path) //nolint:gosec // G304: path is a Corefile-configured cert/key path (operator-trusted at startup), not runtime attacker input — same trust model as coredns's own tls plugin.
			if err != nil {
				h.Write([]byte("sni_tls:missing:" + path))
				continue
			}
			h.Write(b)
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
