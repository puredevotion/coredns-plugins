package zoneversion

import (
	"testing"

	"github.com/miekg/dns"
)

func TestClassify(t *testing.T) {
	other := &dns.EDNS0_NSID{Code: dns.EDNS0NSID}
	for name, tc := range map[string]struct {
		opt  *dns.OPT
		want ask
	}{
		"no OPT":                   {nil, askNone},
		"no options":               {&dns.OPT{}, askNone},
		"another option only":      {&dns.OPT{Option: []dns.EDNS0{other}}, askNone},
		"another local option":     {&dns.OPT{Option: []dns.EDNS0{&dns.EDNS0_LOCAL{Code: 65001}}}, askNone},
		"one empty":                {&dns.OPT{Option: []dns.EDNS0{emptyOption()}}, askVersion},
		"one empty among others":   {&dns.OPT{Option: []dns.EDNS0{other, emptyOption(), other}}, askVersion},
		"two empty":                {&dns.OPT{Option: []dns.EDNS0{emptyOption(), emptyOption()}}, askMalformed},
		"non-empty local":          {&dns.OPT{Option: []dns.EDNS0{&dns.EDNS0_LOCAL{Code: 19, Data: []byte{1}}}}, askMalformed},
		"miekg struct (2 octets)":  {&dns.OPT{Option: []dns.EDNS0{&dns.EDNS0_ZONEVERSION{}}}, askMalformed},
		"empty then non-empty":     {&dns.OPT{Option: []dns.EDNS0{emptyOption(), &dns.EDNS0_ZONEVERSION{}}}, askMalformed},
		"non-empty then empty":     {&dns.OPT{Option: []dns.EDNS0{&dns.EDNS0_ZONEVERSION{}, emptyOption()}}, askMalformed},
		"response-shaped (6 oct.)": {&dns.OPT{Option: []dns.EDNS0{&dns.EDNS0_ZONEVERSION{LabelCount: 2, Version: strayVersion}}}, askMalformed},
	} {
		if got := classify(tc.opt); got != tc.want {
			t.Errorf("%s: classify = %d, want %d", name, got, tc.want)
		}
	}
}
