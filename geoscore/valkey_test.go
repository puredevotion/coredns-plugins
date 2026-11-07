package geoscore

import (
	"os"
	"testing"
	"time"
)

// Integration test against a real Valkey, skipped unless GEOSCORE_VALKEY_ADDR
// is set, as probe's are with PROBE_VALKEY_ADDR:
//
//	valkey-server --port 6399 &
//	GEOSCORE_VALKEY_ADDR=127.0.0.1:6399 go test ./...
func TestValkeyStoreRoundTrip(t *testing.T) {
	addr := os.Getenv("GEOSCORE_VALKEY_ADDR")
	if addr == "" {
		t.Skip("GEOSCORE_VALKEY_ADDR not set; skipping Valkey integration test")
	}
	s, err := NewValkeyStore(ValkeyConfig{Addrs: []string{addr}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cerr := s.Close(); cerr != nil {
			t.Error(cerr)
		}
	})
	key := "geoscore-test:" + time.Now().Format(time.RFC3339Nano)
	e := Entry{Score: 0.5, Healthy: true, Updated: time.Now().Unix()}
	b, err := e.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	c := s.client
	if serr := c.Do(t.Context(), c.B().Set().Key(key).Value(string(b)).Ex(time.Minute).Build()).Error(); serr != nil {
		t.Fatal(serr)
	}
	vals, err := s.Get(t.Context(), []string{key, key + ":absent"})
	if err != nil {
		t.Fatal(err)
	}
	if vals[1] != nil {
		t.Fatalf("absent key returned %q", vals[1])
	}
	got, err := ParseEntry(vals[0])
	if err != nil || got != e {
		t.Fatalf("read back %+v, %v", got, err)
	}
}
