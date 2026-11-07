package geoscore

import (
	"math"
	"strings"
	"testing"
)

func TestParseEntryValid(t *testing.T) {
	e, err := ParseEntry([]byte(`{"score":0.83,"healthy":true,"updated":1762500000,"signal":"carbon","note":"212 gCO2/kWh"}`))
	if err != nil {
		t.Fatal(err)
	}
	want := Entry{Score: 0.83, Healthy: true, Updated: 1762500000, Signal: "carbon", Note: "212 gCO2/kWh"}
	if e != want {
		t.Fatalf("got %+v, want %+v", e, want)
	}
	if e.Weight() != 8300 {
		t.Errorf("weight %d, want 8300", e.Weight())
	}
	for _, s := range []string{
		`{"score":0,"healthy":false,"updated":1}`,
		`{"score":1,"healthy":true,"updated":253402300799}`,
		`{"score":-0,"healthy":true,"updated":1}`,
		` {"updated":5,"healthy":true,"score":5e-1} `,
	} {
		if _, err := ParseEntry([]byte(s)); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
}

// R14: everything the validator must refuse.
func TestParseEntryRejects(t *testing.T) {
	for _, s := range []string{
		``,
		`null`,
		`[]`,
		`{}`,
		`{"healthy":true,"updated":1}`,
		`{"score":0.5,"updated":1}`,
		`{"score":0.5,"healthy":true}`,
		`{"score":-0.01,"healthy":true,"updated":1}`,
		`{"score":1.0000001,"healthy":true,"updated":1}`,
		`{"score":1e400,"healthy":true,"updated":1}`,
		`{"score":NaN,"healthy":true,"updated":1}`,
		`{"score":"0.5","healthy":true,"updated":1}`,
		`{"score":0.5,"healthy":"yes","updated":1}`,
		`{"score":0.5,"healthy":true,"updated":0}`,
		`{"score":0.5,"healthy":true,"updated":-5}`,
		`{"score":0.5,"healthy":true,"updated":1.5}`,
		`{"score":0.5,"healthy":true,"updated":253402300800}`,
		`{"score":0.5,"healthy":true,"updated":1,"extra":1}`,
		`{"Score":0.5,"healthy":true,"updated":1}`,
		`{"SCORE":0.5,"HEALTHY":true,"UPDATED":1}`,
		`{"score":0.5,"healthy":true,"updated":1,"ſcore":1}`,
		`{"score":0.1,"score":0.9,"healthy":true,"updated":1}`,
		`{"score":0.5,"healthy":true,"updated":1,"note":"a","note":"b"}`,
		`{"score":0.5,"healthy":true,"updated":1,"signal":"Carbon"}`,
		`{"score":0.5,"healthy":true,"updated":1,"signal":"` + strings.Repeat("a", 17) + `"}`,
		`{"score":0.5,"healthy":true,"updated":1,"note":"tab\there"}`,
		`{"score":0.5,"healthy":true,"updated":1,"note":"café"}`,
		`{"score":0.5,"healthy":true,"updated":1,"note":"` + strings.Repeat("n", 101) + `"}`,
		`{"score":0.5,"healthy":true,"updated":1} {}`,
		`{"score":0.5,"healthy":true,"updated":1}x`,
		`{"score":0.5,"healthy":true,"updated":1,"note":"` + strings.Repeat(" ", maxEntryBytes) + `"}`,
	} {
		if e, err := ParseEntry([]byte(s)); err == nil {
			t.Errorf("accepted %q as %+v", s, e)
		}
	}
}

func TestEntryValidateNonFinite(t *testing.T) {
	for _, s := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -1, 2, math.SmallestNonzeroFloat64 - 1} {
		e := Entry{Score: s, Healthy: true, Updated: 1}
		if e.Validate() == nil {
			t.Errorf("score %v accepted", s)
		}
		if _, err := e.Marshal(); err == nil {
			t.Errorf("score %v marshalled", s)
		}
	}
}

func TestWeightRounding(t *testing.T) {
	for score, want := range map[float64]uint32{0: 0, 0.00004: 0, 0.00005: 1, 0.5: 5000, 0.99995: 10000, 1: 10000} {
		e := Entry{Score: score}
		if got := e.Weight(); got != want {
			t.Errorf("Weight(%v) = %d, want %d", score, got, want)
		}
	}
}
