package zoneversion

import (
	"slices"
	"testing"

	"github.com/coredns/caddy"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		input  string
		keys   []string
		want   []string
		failed bool
	}{
		{pluginName, []string{testApex}, []string{testApex}, false},
		{"zoneversion Example.COM example.net.", []string{"."}, []string{testApex, "example.net."}, false},
		{"zoneversion example.com example.com", []string{"."}, []string{testApex}, false},
		{pluginName, []string{"example.com:53", "example.org."}, []string{testApex, "example.org."}, false},
		// The root zone would claim every name, forwarded answers included.
		{pluginName, []string{"."}, nil, true},
		{"zoneversion .", []string{testApex}, nil, true},
		{"zoneversion example.com .", []string{testApex}, nil, true},
		{"zoneversion exa..mple.com", []string{"."}, nil, true},
		{"zoneversion example.com {\n serial 1\n}", []string{"."}, nil, true},
		{"zoneversion example.com\nzoneversion example.net", []string{"."}, nil, true},
	} {
		c := caddy.NewTestController("dns", tc.input)
		c.ServerBlockKeys = tc.keys
		got, err := parse(c)
		if tc.failed {
			if err == nil {
				t.Errorf("%q (keys %v): accepted as %v, want an error", tc.input, tc.keys, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q (keys %v): %v", tc.input, tc.keys, err)
			continue
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%q (keys %v): zones %v, want %v", tc.input, tc.keys, got, tc.want)
		}
	}
}

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("dns", "zoneversion example.com")
	if err := setup(c); err != nil {
		t.Fatal(err)
	}
	c = caddy.NewTestController("dns", "zoneversion .")
	if err := setup(c); err == nil {
		t.Fatal("root zone accepted")
	}
}
