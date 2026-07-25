package sni_tls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"os"
	"sync/atomic"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
)

var log = clog.NewWithPlugin("sni_tls")

// reloadInterval is how often liveStore re-hashes the configured cert/key
// files to check for rotation. Fixed rather than Corefile-configurable: cert
// renewal (step-ca/cert-manager, hour-to-day cadence) is picked up promptly
// at this interval, and hashing a couple of small PEM files every 30s is
// noise-level CPU cost, so the tradeoff doesn't vary enough per-deployment to
// justify the syntax.
const reloadInterval = 30 * time.Second

// liveStore holds the currently active certStore behind an atomic pointer so
// GetCertificate reads never block on, or race with, a reload swapping it
// out.
//
// Piggybacking on the existing `reload` plugin (docs/sni-tls-plugin.md's
// original plan) was ruled out on inspection of coredns/plugin/reload's
// source: it SHA512-hashes the *parsed Corefile*, not the cert files it
// references, so a cert rotated at the same on-disk path — the k8s
// Secret-volume symlink-swap pattern this plugin's fallback-cert doc already
// assumes, see [[project_cert_reload_incident]] for the general shape used
// elsewhere in the fleet — never changes that hash, and `reload` never
// restarts the server. Cert rotation must be polled independently, in-process.
type liveStore struct {
	pairs   [][2]string
	current atomic.Pointer[certStore]
	digest  atomic.Pointer[[32]byte]
	cancel  context.CancelFunc
}

// newLiveStore wraps an already-built initial certStore for polling. Callers
// must have loaded it via buildCertStore first (setup() still fails loudly on
// an initial load error, same as before this plugin gained reload support).
func newLiveStore(pairs [][2]string, initial *certStore, initialDigest [32]byte) *liveStore {
	l := &liveStore{pairs: pairs}
	l.current.Store(initial)
	l.digest.Store(&initialDigest)
	return l
}

// GetCertificate implements the tls.Config.GetCertificate callback against
// whichever certStore is currently active.
func (l *liveStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return l.current.Load().GetCertificate(hello)
}

// OnStartup starts the background poll loop. Also wired to
// caddy.Controller's OnRestartFailed in setup.go: if an unrelated Corefile
// change triggers the `reload` plugin and the new config fails to come up,
// this resumes polling on the still-live old instance, mirroring the radnr
// plugin's OnStartup/OnShutdown/OnRestartFailed lifecycle convention in this
// repo.
func (l *liveStore) OnStartup() error {
	ctx, cancel := context.WithCancel(context.Background())
	l.cancel = cancel
	go l.run(ctx)
	return nil
}

// OnShutdown stops the poll loop. Wired to both OnRestart (this server
// instance is about to be torn down for a Corefile-driven restart) and
// OnFinalShutdown (process exit).
func (l *liveStore) OnShutdown() error {
	if l.cancel != nil {
		l.cancel()
		l.cancel = nil
	}
	return nil
}

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

// reloadOnce re-hashes the configured cert/key files and, only if something
// changed since the last successful (re)load, rebuilds the certStore and
// atomically swaps it in. A rebuild failure (e.g. reading mid-rotation, one
// file replaced but not the other yet) is logged and the previously active
// store is left in place — a transient reload error must never take down an
// already-running TLS listener.
func (l *liveStore) reloadOnce() {
	newDigest := digestPairs(l.pairs)
	if newDigest == *l.digest.Load() {
		return
	}
	store, err := buildCertStore(l.pairs)
	if err != nil {
		log.Warningf("cert reload skipped, keeping previous store: %v", err)
		return
	}
	l.current.Store(store)
	l.digest.Store(&newDigest)
	log.Infof("reloaded %d configured cert/key pair(s) from disk", len(l.pairs))
}

// digestPairs hashes the raw bytes of every configured cert/key file, in
// order. A missing file contributes a fixed sentinel instead of erroring, so
// "still missing" and "just went missing" both produce a stable, comparable
// digest instead of digestPairs itself failing — mirrors buildCertStore's own
// tolerance of missing files (see its doc comment).
func digestPairs(pairs [][2]string) [32]byte {
	h := sha256.New()
	for _, p := range pairs {
		for _, path := range p {
			b, err := os.ReadFile(path)
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
