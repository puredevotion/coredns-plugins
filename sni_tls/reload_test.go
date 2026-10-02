package snitls

import (
	"crypto/tls"
	"os"
	"runtime"
	"testing"
	"time"
)

// --- digestPairs: change detection -------------------------------------------.

func TestDigestPairs_StableWhenUnchanged(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", testSNIPrimary)
	pairs := [][2]string{{certPath, keyPath}}

	a, b := digestPairs(pairs), digestPairs(pairs)
	if a != b {
		t.Fatal("digest must be stable across calls when files are unchanged")
	}
}

func TestDigestPairs_ChangesOnRotation(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", testSNIPrimary)
	pairs := [][2]string{{certPath, keyPath}}

	before := digestPairs(pairs)

	rotatedCertPath, rotatedKeyPath := writeTestCert(t, "rotated", testSNIPrimary)
	//nolint:gosec // G304/G703: all four paths are t.TempDir() fixtures from writeTestCert, not external input.
	certBytes, err := os.ReadFile(rotatedCertPath)
	if err != nil {
		t.Fatalf("read rotated cert: %v", err)
	}
	keyBytes, err := os.ReadFile(rotatedKeyPath) //nolint:gosec // G304/G703: see above
	if err != nil {
		t.Fatalf("read rotated key: %v", err)
	}
	if err := os.WriteFile(certPath, certBytes, 0o600); err != nil { //nolint:gosec // G304/G703: see above
		t.Fatalf("overwrite cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyBytes, 0o600); err != nil { //nolint:gosec // G304/G703: see above
		t.Fatalf("overwrite key: %v", err)
	}

	if digestPairs(pairs) == before {
		t.Fatal("digest must change after cert/key file content is rotated at the same path")
	}
}

func TestDigestPairs_MissingFileIsStableSentinel(t *testing.T) {
	pairs := [][2]string{{"/nonexistent/cert.pem", "/nonexistent/key.pem"}}
	a, b := digestPairs(pairs), digestPairs(pairs)
	if a != b {
		t.Fatal("missing-file digest must be stable, not vary per call")
	}
}

// --- liveStore.reloadOnce: swap-on-change, keep-old-on-error -----------------.

// TestLiveStore_ReloadOnce_SwapsOnRotation is the core hot-reload behaviour: a
// cert rotated at the same path must be picked up on the next poll, no
// CoreDNS restart needed.
func TestLiveStore_ReloadOnce_SwapsOnRotation(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", testSNIPrimary)

	store, err := buildCertStore([][2]string{{certPath, keyPath}}, false)
	if err != nil {
		t.Fatalf("buildCertStore: %v", err)
	}
	pairs := [][2]string{{certPath, keyPath}}
	live := newLiveStore(pairs, false, store, digestPairs(pairs))

	before, err := live.GetCertificate(&tls.ClientHelloInfo{ServerName: testSNIPrimary})
	if err != nil {
		t.Fatalf("GetCertificate before rotation: %v", err)
	}

	rotatedCertPath, rotatedKeyPath := writeTestCert(t, "rotated", testSNIPrimary)
	overwrite(t, certPath, rotatedCertPath)
	overwrite(t, keyPath, rotatedKeyPath)

	live.reloadOnce()

	after, err := live.GetCertificate(&tls.ClientHelloInfo{ServerName: testSNIPrimary})
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
	certPath, keyPath := writeTestCert(t, "primary", testSNIPrimary)
	store, err := buildCertStore([][2]string{{certPath, keyPath}}, false)
	if err != nil {
		t.Fatalf("buildCertStore: %v", err)
	}
	pairs := [][2]string{{certPath, keyPath}}
	live := newLiveStore(pairs, false, store, digestPairs(pairs))

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
	certPath, keyPath := writeTestCert(t, "primary", testSNIPrimary)
	store, err := buildCertStore([][2]string{{certPath, keyPath}}, false)
	if err != nil {
		t.Fatalf("buildCertStore: %v", err)
	}
	pairs := [][2]string{{certPath, keyPath}}
	live := newLiveStore(pairs, false, store, digestPairs(pairs))

	before := live.current.Load()

	if writeErr := os.WriteFile(certPath, []byte("not a valid cert"), 0o600); writeErr != nil {
		t.Fatalf("corrupt cert file: %v", writeErr)
	}

	live.reloadOnce()

	if live.current.Load() != before {
		t.Fatal("reloadOnce must keep the previous store when the rebuild fails")
	}

	got, err := live.GetCertificate(&tls.ClientHelloInfo{ServerName: testSNIPrimary})
	if err != nil || got == nil {
		t.Fatalf("plugin must keep serving the last-good cert after a failed reload: got=%v err=%v", got, err)
	}
}

// --- liveStore lifecycle: OnStartup/OnShutdown are safe to call repeatedly --.

// TestLiveStore_Lifecycle_StartStopRestart mirrors the
// OnStartup->OnRestart->OnRestartFailed sequence a Corefile reload can
// produce; must not deadlock, panic, or leak the poll goroutine.
func TestLiveStore_Lifecycle_StartStopRestart(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", testSNIPrimary)
	store, err := buildCertStore([][2]string{{certPath, keyPath}}, false)
	if err != nil {
		t.Fatalf("buildCertStore: %v", err)
	}
	pairs := [][2]string{{certPath, keyPath}}
	live := newLiveStore(pairs, false, store, digestPairs(pairs))

	if err := live.OnStartup(); err != nil {
		t.Fatalf("OnStartup: %v", err)
	}
	if err := live.OnShutdown(); err != nil {
		t.Fatalf("OnShutdown (restart): %v", err)
	}
	if err := live.OnStartup(); err != nil { // OnRestartFailed path.
		t.Fatalf("OnStartup (restart-failed resume): %v", err)
	}
	if err := live.OnShutdown(); err != nil { // OnFinalShutdown.
		t.Fatalf("OnShutdown (final): %v", err)
	}
}

// TestLiveStore_Lifecycle_RestartFailedWithoutRestart is the sequence caddy
// produces when a plugin registered before sni_tls fails its OnRestart: our
// OnRestart never runs, but OnRestartFailed (OnStartup) still does. The
// first poll loop must not be orphaned — after the final shutdown, no poll
// goroutine may be left running.
func TestLiveStore_Lifecycle_RestartFailedWithoutRestart(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", testSNIPrimary)
	store, err := buildCertStore([][2]string{{certPath, keyPath}}, false)
	if err != nil {
		t.Fatalf("buildCertStore: %v", err)
	}
	pairs := [][2]string{{certPath, keyPath}}
	live := newLiveStore(pairs, false, store, digestPairs(pairs))

	baseline := runtime.NumGoroutine()
	if err := live.OnStartup(); err != nil {
		t.Fatalf("OnStartup: %v", err)
	}
	if err := live.OnStartup(); err != nil { // OnRestartFailed, no OnRestart before it.
		t.Fatalf("OnStartup (restart-failed): %v", err)
	}
	if err := live.OnShutdown(); err != nil { // OnFinalShutdown.
		t.Fatalf("OnShutdown (final): %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > baseline {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutine(s) still running after final shutdown; a poll loop was orphaned",
				runtime.NumGoroutine()-baseline)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestLiveStore_Lifecycle_ReclaimsDroppedInstance is a reload that fails
// after the new instance's OnStartup already ran: caddy discards the new
// instance without calling its shutdown hooks, then runs the old one's
// OnRestartFailed. That must stop the discarded instance's poller.
func TestLiveStore_Lifecycle_ReclaimsDroppedInstance(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", testSNIPrimary)
	pairs := [][2]string{{certPath, keyPath}}
	store, err := buildCertStore(pairs, false)
	if err != nil {
		t.Fatalf("buildCertStore: %v", err)
	}
	oldInst := newLiveStore(pairs, false, store, digestPairs(pairs))
	oldInst.owner = new(int)
	newInst := newLiveStore(pairs, false, store, digestPairs(pairs))
	newInst.owner = new(int)

	baseline := runtime.NumGoroutine()
	mustNil(t, oldInst.OnStartup())  // First startup.
	mustNil(t, oldInst.OnShutdown()) // Old instance's OnRestart.
	mustNil(t, newInst.OnStartup())  // New instance's OnStartup, then the reload fails.
	mustNil(t, oldInst.OnStartup())  // Old instance's OnRestartFailed.
	mustNil(t, oldInst.OnShutdown()) // OnFinalShutdown; newInst gets none.

	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > baseline {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutine(s) still running after final shutdown; the dropped instance's poller survived",
				runtime.NumGoroutine()-baseline)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func mustNil(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// overwrite copies srcContentFrom's bytes onto dst. Test-only helper: both
// paths are always t.TempDir() fixtures from the caller, never external
// input.
func overwrite(t *testing.T, dst, srcContentFrom string) {
	t.Helper()
	b, err := os.ReadFile(srcContentFrom) //nolint:gosec // G304/G703: see doc comment
	if err != nil {
		t.Fatalf("read %s: %v", srcContentFrom, err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil { //nolint:gosec // G304/G703: see doc comment
		t.Fatalf("write %s: %v", dst, err)
	}
}
