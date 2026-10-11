package cookie

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

var log = clog.NewWithPlugin(pluginName)

// maxVerifyOnly bounds the verify_secret list. RFC 9018 §5 needs one at a time;
// a longer list is a rollout that was never finished.
const maxVerifyOnly = 4

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	cfg, since, err := parse(c)
	if err != nil {
		return plugin.Error(pluginName, err) //nolint:wrapcheck // plugin.Error is coredns's own setup-error convention
	}
	secretSince.Store(since.Unix())

	h := newCookie(cfg)
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		h.Next = next
		return h
	})
	return nil
}

// block is what one Corefile block has said so far.
type block struct {
	file       string
	cfg        config
	haveSecret bool
}

// property applies one `name value` line.
func (b *block) property(name, value string) error {
	switch name {
	case "secret":
		k, err := parseSecret(value)
		if err != nil {
			return fmt.Errorf("secret: %w", err)
		}
		b.cfg.secret, b.haveSecret = k, true
	case "secret_file":
		b.file = value
	case "verify_secret":
		k, err := parseSecret(value)
		if err != nil {
			return fmt.Errorf("verify_secret: %w", err)
		}
		if len(b.cfg.verifyOnly) == maxVerifyOnly {
			return fmt.Errorf("at most %d verify_secret entries", maxVerifyOnly)
		}
		b.cfg.verifyOnly = append(b.cfg.verifyOnly, k)
	case "mode":
		switch value {
		case "permissive":
			b.cfg.mode = modePermissive
		case "enforce":
			b.cfg.mode = modeEnforce
		default:
			return fmt.Errorf("mode %q: want permissive or enforce", value)
		}
	default:
		return fmt.Errorf("unknown property %q", name)
	}
	return nil
}

// finish settles the generating secret: from secret_file, from `secret`, or a
// random one, and refuses a secret listed twice. It returns the secret's
// installation time for the secret_age_seconds gauge.
func (b *block) finish() (time.Time, error) {
	since := time.Now()
	if b.haveSecret && b.file != "" {
		return since, errors.New("secret and secret_file are alternatives, not both")
	}
	switch {
	case b.file != "":
		k, mtime, err := readSecretFile(b.file)
		if err != nil {
			return since, err
		}
		b.cfg.secret, since = k, mtime
	case !b.haveSecret:
		if len(b.cfg.verifyOnly) != 0 {
			return since, errors.New("verify_secret without a secret: name the generating secret explicitly")
		}
		if _, err := rand.Read(b.cfg.secret[:]); err != nil {
			return since, fmt.Errorf("generating a secret: %w", err)
		}
		log.Warning("no secret configured: using a random one, which is correct for a single server and wrong for an anycast set (RFC 9018 section 4: the Server Secret MUST be configurable)")
	}

	// A secret listed twice is a rollout step done twice, not a feature.
	all := append([][16]byte{b.cfg.secret}, b.cfg.verifyOnly...)
	for i := range all {
		for j := i + 1; j < len(all); j++ {
			if all[i] == all[j] {
				return since, errors.New("the same secret is listed more than once")
			}
		}
	}
	return since, nil
}

// parse reads the Corefile block. It returns the secret's installation time,
// for the secret_age_seconds gauge: the file's mtime for secret_file, now
// otherwise.
func parse(c *caddy.Controller) (config, time.Time, error) {
	var b block
	seen := map[string]bool{}

	if !c.Next() {
		return b.cfg, time.Now(), c.ArgErr()
	}
	if len(c.RemainingArgs()) != 0 {
		return b.cfg, time.Now(), c.ArgErr()
	}
	for c.NextBlock() {
		name := c.Val()
		// The verify_secret property may repeat (RFC 9018 §5 needs one at a time, but a
		// list reads naturally); every other property is single.
		if seen[name] && name != "verify_secret" {
			return b.cfg, time.Now(), fmt.Errorf("duplicate %s", name)
		}
		seen[name] = true

		args := c.RemainingArgs()
		if len(args) != 1 {
			return b.cfg, time.Now(), c.ArgErr()
		}
		if err := b.property(name, args[0]); err != nil {
			return b.cfg, time.Now(), err
		}
	}
	if c.Next() {
		return b.cfg, time.Now(), errors.New("the cookie plugin may be given once per server block")
	}

	since, err := b.finish()
	return b.cfg, since, err
}

// parseSecret reads 32 hex digits: the 16-byte SipHash key.
func parseSecret(s string) ([16]byte, error) {
	var k [16]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return k, errors.New("not hexadecimal") //nolint:err113 // never echo secret material into an error
	}
	if len(b) != len(k) {
		return k, fmt.Errorf("want 32 hex digits (16 bytes), got %d bytes", len(b))
	}
	copy(k[:], b)
	return k, nil
}

func readSecretFile(path string) ([16]byte, time.Time, error) {
	var zero [16]byte
	st, err := os.Stat(path)
	if err != nil {
		return zero, time.Time{}, fmt.Errorf("secret_file: %w", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		log.Warningf("secret_file %s is readable by group or others (mode %o)", path, st.Mode().Perm())
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the operator names this file in the Corefile
	if err != nil {
		return zero, time.Time{}, fmt.Errorf("secret_file: %w", err)
	}
	k, err := parseSecret(strings.TrimSpace(string(raw)))
	if err != nil {
		return zero, time.Time{}, fmt.Errorf("secret_file %s: %w", path, err)
	}
	return k, st.ModTime(), nil
}
