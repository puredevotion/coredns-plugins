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
type liveStore struct {
	pairs   [][2]string
	current atomic.Pointer[certStore]
	digest  atomic.Pointer[[32]byte]
	cancel  context.CancelFunc
}

// newLiveStore wraps an already-loaded certStore for polling; setup() still
// fails loudly on the initial buildCertStore error before reaching this.
func newLiveStore(pairs [][2]string, initial *certStore, initialDigest [32]byte) *liveStore {
	l := &liveStore{pairs: pairs}
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
func (l *liveStore) OnStartup() error {
	ctx, cancel := context.WithCancel(context.Background())
	l.cancel = cancel
	go l.run(ctx)
	return nil
}

// OnShutdown stops the poll loop; wired to both OnRestart (server tearing
// down for a Corefile-driven restart) and OnFinalShutdown (process exit).
func (l *liveStore) OnShutdown() error {
	if l.cancel != nil {
		l.cancel()
		l.cancel = nil
	}
	return nil
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

// digestPairs hashes every configured cert/key file's raw bytes, in order. A
// missing file hashes a fixed sentinel instead of erroring, so a
// still-missing file and a newly-missing one produce the same stable
// digest — mirrors buildCertStore's own tolerance of missing files.
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
