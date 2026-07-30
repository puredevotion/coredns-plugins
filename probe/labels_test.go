package probe

import "testing"

func TestParseQuery(t *testing.T) {
	tests := []struct {
		name     string
		sub      string
		wantOK   bool
		wantTok  string
		wantMods Modifier
	}{
		{name: "baseline token", sub: "a1b2c3d4", wantOK: true, wantTok: "a1b2c3d4"},
		{name: "trailing dot tolerated", sub: "a1b2c3d4.", wantOK: true, wantTok: "a1b2c3d4"},
		{
			name: "single modifier", sub: "_unsigned.a1b2c3d4",
			wantOK: true, wantTok: "a1b2c3d4", wantMods: ModUnsigned,
		},
		{
			// Order must not matter: a browser generating these should not have
			// to know a canonical ordering.
			name: "two modifiers", sub: "_truncate._big.deadbeefcafe",
			wantOK: true, wantTok: "deadbeefcafe", wantMods: ModTruncate | ModBig,
		},
		{
			name: "reversed order is the same set", sub: "_big._truncate.deadbeefcafe",
			wantOK: true, wantTok: "deadbeefcafe", wantMods: ModTruncate | ModBig,
		},
		{
			// 0x20 randomization means we get mixed case off the wire.
			name: "case insensitive", sub: "_UnSigned.A1B2C3D4",
			wantOK: true, wantTok: "a1b2c3d4", wantMods: ModUnsigned,
		},
		{
			name: "max length token", sub: "0123456789abcdef0123456789abcdef",
			wantOK: true, wantTok: "0123456789abcdef0123456789abcdef",
		},

		{name: "apex is not a probe query", sub: "", wantOK: false},
		{name: "token too short", sub: "a1b2c3d", wantOK: false},
		{name: "token too long", sub: "0123456789abcdef0123456789abcdef0", wantOK: false},
		{name: "token not hex", sub: "zzzzzzzz", wantOK: false},
		{name: "unknown modifier", sub: "_nosuchthing.a1b2c3d4", wantOK: false},
		{name: "bare extra label is not a modifier", sub: "www.a1b2c3d4", wantOK: false},
		{name: "repeated modifier", sub: "_big._big.a1b2c3d4", wantOK: false},
		{name: "missing token, modifier only", sub: "_big", wantOK: false},
		{
			// Only one signature exists to spoil, so asking for two spoilings
			// is a client error, not a precedence question.
			name: "conflicting signature modifiers", sub: "_unsigned._badsig.a1b2c3d4", wantOK: false,
		},
		{name: "conflicting expired and future", sub: "_expiredsig._futuresig.a1b2c3d4", wantOK: false},
		{name: "conflicting rcode modifiers", sub: "_nxdomain._servfail.a1b2c3d4", wantOK: false},
		{
			// Different groups compose fine.
			name: "cross-group combination is allowed", sub: "_badsig._truncate.a1b2c3d4",
			wantOK: true, wantTok: "a1b2c3d4", wantMods: ModBadSig | ModTruncate,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseQuery(tc.sub)
			if ok != tc.wantOK {
				t.Fatalf("ParseQuery(%q) ok = %v, want %v", tc.sub, ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if got.Token != tc.wantTok {
				t.Errorf("token = %q, want %q", got.Token, tc.wantTok)
			}
			if got.Mods != tc.wantMods {
				t.Errorf("mods = %v (%d), want %v (%d)",
					got.Mods, got.Mods, tc.wantMods, tc.wantMods)
			}
		})
	}
}

func TestModifierString(t *testing.T) {
	tests := []struct {
		mods Modifier
		want string
	}{
		{mods: 0, want: "none"},
		{mods: ModUnsigned, want: "unsigned"},
		// Stable regardless of the order the bits were set in.
		{mods: ModBig | ModTruncate, want: "truncate,big"},
		{mods: ModTruncate | ModBig, want: "truncate,big"},
	}
	for _, tc := range tests {
		if got := tc.mods.String(); got != tc.want {
			t.Errorf("Modifier(%d).String() = %q, want %q", tc.mods, got, tc.want)
		}
	}
}

func TestEveryModifierIsParseableAndNamed(t *testing.T) {
	// Guards the "one source of truth" claim in labels.go: a modifier added to
	// the bitmask but forgotten in modifierOrder would silently vanish from
	// String(), and one forgotten in modifierNames would be unreachable.
	if len(modifierOrder) != len(modifierNames) {
		t.Fatalf("modifierOrder has %d entries, modifierNames has %d — they must agree",
			len(modifierOrder), len(modifierNames))
	}
	for _, name := range modifierOrder {
		if _, ok := modifierNames[name]; !ok {
			t.Errorf("modifierOrder lists %q but modifierNames has no such entry", name)
		}
	}
	seen := make(map[Modifier]string, len(modifierNames))
	for name, m := range modifierNames {
		if prev, dup := seen[m]; dup {
			t.Errorf("modifiers %q and %q share bit %d", prev, name, m)
		}
		seen[m] = name

		q, ok := ParseQuery("_" + name + ".a1b2c3d4")
		if !ok {
			t.Errorf("modifier %q does not parse", name)
			continue
		}
		if !q.Mods.Has(m) {
			t.Errorf("modifier %q parsed but did not set its bit", name)
		}
	}
}
