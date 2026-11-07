package zoneversion

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	propIterations = 5000
	propSeed       = 9660
)

func randLabel(r *rand.Rand) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
	b := make([]byte, 1+r.Intn(12))
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

func randName(r *rand.Rand, labels int) string {
	parts := make([]string, labels)
	for i := range parts {
		parts[i] = randLabel(r)
	}
	return strings.Join(parts, ".") + "."
}

// NewVersion, Encode and Decode agree: every valid version round-trips, and
// its label count is the zone's, at most QNAME's.
func TestProperty_VersionRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(propSeed)) //nolint:gosec // G404: deterministic test generator.
	for range propIterations {
		zone := randName(r, 1+r.Intn(6))
		qname := zone
		if r.Intn(4) != 0 {
			qname = randName(r, r.Intn(4)) + zone
			qname = strings.TrimPrefix(qname, ".")
		}
		if r.Intn(10) == 0 {
			qname = randName(r, 1+r.Intn(6)) // Usually not below zone.
		}
		serial := r.Uint32()
		v, err := NewVersion(zone, qname, serial)
		below := dns.IsSubDomain(zone, qname)
		if (err == nil) != below {
			t.Fatalf("NewVersion(%q, %q): err %v, but IsSubDomain %v", zone, qname, err, below)
		}
		if err != nil {
			continue
		}
		enc := v.Encode()
		back, err := Decode(enc[:])
		if err != nil || back != v || back.Serial() != serial || int(back.LabelCount()) != dns.CountLabel(zone) {
			t.Fatalf("round trip %q/%q/%d: %+v, %v", zone, qname, serial, back, err)
		}
	}
}

// classify against the specification it implements (ZoneVersion.lean
// classify_version_iff): askVersion iff exactly one ZONEVERSION option and it
// is empty; askNone iff none.
func TestProperty_Classify(t *testing.T) {
	r := rand.New(rand.NewSource(propSeed)) //nolint:gosec // G404: deterministic test generator.
	for range propIterations {
		opt := &dns.OPT{}
		zv, emptyZV := 0, 0
		for range r.Intn(5) {
			switch r.Intn(4) {
			case 0:
				opt.Option = append(opt.Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID})
			case 1:
				opt.Option = append(opt.Option, emptyOption())
				zv++
				emptyZV++
			case 2:
				opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{Code: dns.EDNS0ZONEVERSION, Data: make([]byte, 1+r.Intn(8))})
				zv++
			default:
				opt.Option = append(opt.Option, &dns.EDNS0_ZONEVERSION{LabelCount: uint8(r.Intn(256)), Version: strings.Repeat("x", r.Intn(6))}) //nolint:gosec // G115: Intn(256) fits.
				zv++
			}
		}
		want := askMalformed
		switch {
		case zv == 0:
			want = askNone
		case zv == 1 && emptyZV == 1:
			want = askVersion
		}
		if got := classify(opt); got != want {
			t.Fatalf("classify(%v) = %d, want %d", opt.Option, got, want)
		}
	}
}

// The cache update rule (ZoneVersion.lean update_*): a fresh entry never
// moves backwards in RFC 1982 order, and the stored serial is always either
// the old one or the one observed.
func TestProperty_CacheUpdate(t *testing.T) {
	r := rand.New(rand.NewSource(propSeed)) //nolint:gosec // G404: deterministic test generator.
	for range propIterations {
		old := entry{serial: r.Uint32(), at: testEpoch}
		if r.Intn(3) == 0 {
			old.serial = r.Uint32() % 4 // Small serials near the wrap and each other.
		}
		s := old.serial + uint32(r.Intn(5)) - 2 //nolint:gosec // G115: wrapping is the point.
		if r.Intn(2) == 0 {
			s = r.Uint32()
		}
		isFresh := r.Intn(4) != 0
		now := testEpoch.Add(time.Duration(r.Intn(60)) * time.Second)
		got, _ := update(old, isFresh, s, now)
		if got.serial != old.serial && got.serial != s {
			t.Fatalf("update(%d, %d) stored %d, which nobody observed", old.serial, s, got.serial)
		}
		if isFresh && got.serial != old.serial && !serialGreater(got.serial, old.serial) {
			t.Fatalf("fresh entry %d moved backwards to %d", old.serial, got.serial)
		}
		if !isFresh && got.serial != s {
			t.Fatalf("stale entry %d not replaced by %d", old.serial, s)
		}
	}
}
