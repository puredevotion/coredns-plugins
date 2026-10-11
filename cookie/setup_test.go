package cookie

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"
)

func parseInput(t *testing.T, input string) (config, time.Time, error) {
	t.Helper()
	return parse(caddy.NewTestController("dns", input))
}

func TestParseValid(t *testing.T) {
	cfg, _, err := parseInput(t, "cookie {\n secret "+secretA+"\n verify_secret "+secretB+"\n mode enforce\n}")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.mode != modeEnforce || cfg.secret != key16(t, secretA) || len(cfg.verifyOnly) != 1 || cfg.verifyOnly[0] != key16(t, secretB) {
		t.Errorf("parsed wrong: %+v", cfg)
	}

	// Defaults: permissive, and a random secret when none is given.
	cfg, _, err = parseInput(t, "cookie")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.mode != modePermissive {
		t.Errorf("default mode = %v, want permissive", cfg.mode)
	}
	if cfg.secret == ([16]byte{}) {
		t.Error("no secret configured should yield a random one, got zero")
	}
	cfg2, _, err := parseInput(t, "cookie")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.secret == cfg2.secret {
		t.Error("two plugin instances without a secret drew the same one")
	}
}

func TestParseSecretFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte(secretA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mtime := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	cfg, since, err := parseInput(t, "cookie {\n secret_file "+path+"\n}")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.secret != key16(t, secretA) {
		t.Error("secret_file not read")
	}
	if !since.Equal(mtime) {
		t.Errorf("secret age counts from %v, want the file's mtime %v", since, mtime)
	}
}

func TestParseErrors(t *testing.T) {
	dir := t.TempDir()
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(short, []byte("abcd"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, input, want string
	}{
		{"argument", "cookie extra", ""},
		{"unknown property", "cookie {\n frobnicate 1\n}", "unknown property"},
		{"short secret", "cookie {\n secret abcd\n}", "32 hex digits"},
		{"non-hex secret", "cookie {\n secret " + strings.Repeat("zz", 16) + "\n}", "not hexadecimal"},
		{"bad mode", "cookie {\n mode strict\n}", "permissive or enforce"},
		{"duplicate secret", "cookie {\n secret " + secretA + "\n secret " + secretB + "\n}", "duplicate"},
		{"duplicate mode", "cookie {\n mode enforce\n mode permissive\n}", "duplicate"},
		{"secret and file", "cookie {\n secret " + secretA + "\n secret_file " + short + "\n}", "alternatives"},
		{"missing file", "cookie {\n secret_file " + filepath.Join(dir, "nope") + "\n}", "secret_file"},
		{"short file", "cookie {\n secret_file " + short + "\n}", "32 hex digits"},
		{"verify without secret", "cookie {\n verify_secret " + secretA + "\n}", "without a secret"},
		{"same secret twice", "cookie {\n secret " + secretA + "\n verify_secret " + secretA + "\n}", "more than once"},
		{"missing value", "cookie {\n mode\n}", ""},
		{"too many verify", "cookie {\n secret " + secretA + "\n" + strings.Repeat(" verify_secret "+secretB+"\n", 1) +
			" verify_secret 00000000000000000000000000000001\n verify_secret 00000000000000000000000000000002\n verify_secret 00000000000000000000000000000003\n verify_secret 00000000000000000000000000000004\n}", "at most"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseInput(t, tc.input)
			if err == nil {
				t.Fatal("accepted")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			// A secret must never be echoed into an error.
			for _, s := range []string{secretA, secretB} {
				if strings.Contains(err.Error(), s) {
					t.Errorf("error leaks the secret: %q", err)
				}
			}
		})
	}
}
