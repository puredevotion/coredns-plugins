package sni_tls

import (
	"crypto/tls"
	"os"
	"testing"
)

// --- digestPairs: change detection -------------------------------------------

func TestDigestPairs_StableWhenUnchanged(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", "dns.example.com")
	pairs := [][2]string{{certPath, keyPath}}

	if digestPairs(pairs) != digestPairs(pairs) {
		t.Fatal("digest must be stable across calls when files are unchanged")
	}
}

func TestDigestPairs_ChangesOnRotation(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", "dns.example.com")
	pairs := [][2]string{{certPath, keyPath}}

	before := digestPairs(pairs)

	rotatedCertPath, rotatedKeyPath := writeTestCert(t, "rotated", "dns.example.com")
	certBytes, err := os.ReadFile(rotatedCertPath)
	if err != nil {
		t.Fatalf("read rotated cert: %v", err)
	}
	keyBytes, err := os.ReadFile(rotatedKeyPath)
	if err != nil {
		t.Fatalf("read rotated key: %v", err)
	}
	if err := os.WriteFile(certPath, certBytes, 0o600); err != nil {
		t.Fatalf("overwrite cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyBytes, 0o600); err != nil {
		t.Fatalf("overwrite key: %v", err)
	}

	if digestPairs(pairs) == before {
		t.Fatal("digest must change after cert/key file content is rotated at the same path")
	}
}

func TestDigestPairs_MissingFileIsStableSentinel(t *testing.T) {
	pairs := [][2]string{{"/nonexistent/cert.pem", "/nonexistent/key.pem"}}
	if digestPairs(pairs) != digestPairs(pairs) {
		t.Fatal("missing-file digest must be stable, not vary per call")
	}
}

// --- liveStore.reloadOnce: swap-on-change, keep-old-on-error -----------------

// TestLiveStore_ReloadOnce_SwapsOnRotation is the core hot-reload behavior: a
// cert rotated at the same path must be picked up on the next poll, no
// CoreDNS restart needed.
func TestLiveStore_ReloadOnce_SwapsOnRotation(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", "dns.example.com")

	store, err := buildCertStore([][2]string{{certPath, keyPath}})
	if err != nil {
		t.Fatalf("buildCertStore: %v", err)
	}
	pairs := [][2]string{{certPath, keyPath}}
	live := newLiveStore(pairs, store, digestPairs(pairs))

	before, err := live.GetCertificate(&tls.ClientHelloInfo{ServerName: "dns.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate before rotation: %v", err)
	}

	rotatedCertPath, rotatedKeyPath := writeTestCert(t, "rotated", "dns.example.com")
	overwrite(t, certPath, rotatedCertPath)
	overwrite(t, keyPath, rotatedKeyPath)

	live.reloadOnce()

	after, err := live.GetCertificate(&tls.ClientHelloInfo{ServerName: "dns.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate after rotation: %v", err)
	}
	if after == before {
		t.Fatal("reloadOnce did not swap in the rotated cert")
	}
}

// TestLiveStore_ReloadOnce_NoopWhenUnchanged: an unchanged poll tick must not
// rebuild/swap — steady-state should be cheap and quiet.
func TestLiveStore_ReloadOnce_NoopWhenUnchanged(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", "dns.example.com")
	store, err := buildCertStore([][2]string{{certPath, keyPath}})
	if err != nil {
		t.Fatalf("buildCertStore: %v", err)
	}
	pairs := [][2]string{{certPath, keyPath}}
	live := newLiveStore(pairs, store, digestPairs(pairs))

	before := live.current.Load()
	live.reloadOnce()
	after := live.current.Load()

	if before != after {
		t.Fatal("reloadOnce must not swap the store when nothing on disk changed")
	}
}

// TestLiveStore_ReloadOnce_KeepsOldStoreOnLoadFailure covers a rotation
// caught mid-write (digest changed, but the new file is unloadable): the
// listener must keep serving the last-good cert, not lose it.
func TestLiveStore_ReloadOnce_KeepsOldStoreOnLoadFailure(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", "dns.example.com")
	store, err := buildCertStore([][2]string{{certPath, keyPath}})
	if err != nil {
		t.Fatalf("buildCertStore: %v", err)
	}
	pairs := [][2]string{{certPath, keyPath}}
	live := newLiveStore(pairs, store, digestPairs(pairs))

	before := live.current.Load()

	if err := os.WriteFile(certPath, []byte("not a valid cert"), 0o600); err != nil {
		t.Fatalf("corrupt cert file: %v", err)
	}

	live.reloadOnce()

	if live.current.Load() != before {
		t.Fatal("reloadOnce must keep the previous store when the rebuild fails")
	}

	got, err := live.GetCertificate(&tls.ClientHelloInfo{ServerName: "dns.example.com"})
	if err != nil || got == nil {
		t.Fatalf("plugin must keep serving the last-good cert after a failed reload: got=%v err=%v", got, err)
	}
}

// --- liveStore lifecycle: OnStartup/OnShutdown are safe to call repeatedly --

// TestLiveStore_Lifecycle_StartStopRestart mirrors the
// OnStartup->OnRestart->OnRestartFailed sequence a Corefile reload can
// produce; must not deadlock, panic, or leak the poll goroutine.
func TestLiveStore_Lifecycle_StartStopRestart(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", "dns.example.com")
	store, err := buildCertStore([][2]string{{certPath, keyPath}})
	if err != nil {
		t.Fatalf("buildCertStore: %v", err)
	}
	pairs := [][2]string{{certPath, keyPath}}
	live := newLiveStore(pairs, store, digestPairs(pairs))

	if err := live.OnStartup(); err != nil {
		t.Fatalf("OnStartup: %v", err)
	}
	if err := live.OnShutdown(); err != nil {
		t.Fatalf("OnShutdown (restart): %v", err)
	}
	if err := live.OnStartup(); err != nil { // OnRestartFailed path
		t.Fatalf("OnStartup (restart-failed resume): %v", err)
	}
	if err := live.OnShutdown(); err != nil { // OnFinalShutdown
		t.Fatalf("OnShutdown (final): %v", err)
	}
}

func overwrite(t *testing.T, dst, srcContentFrom string) {
	t.Helper()
	b, err := os.ReadFile(srcContentFrom)
	if err != nil {
		t.Fatalf("read %s: %v", srcContentFrom, err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}
