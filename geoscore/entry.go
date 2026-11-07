package geoscore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
)

// The score-map schema (docs/geoscore-plugin.md, "Score map"). The entry for
// endpoint ID of a name is one string value at KeyPrefix + ":" + ID, holding a
// JSON object:
//
//	{"score": 0.83, "healthy": true, "updated": 1762500000,
//	 "signal": "carbon", "note": "212 gCO2/kWh"}
//
// Fields:
//
//   - Field score is required: a JSON number in [0, 1], higher is better. 0
//     drains the endpoint (never selected, R15).
//   - Field healthy is required: a JSON boolean. With false the endpoint is
//     never selected.
//   - Field updated is required: the writer's clock when it computed the
//     score, in Unix seconds, > 0. Staleness is judged from this, never from
//     when the plugin read the key (R21).
//   - Field signal is optional: 0 to 16 of [a-z0-9-], what the score measures.
//   - Field note is optional: up to 100 printable ASCII characters, shown in
//     the rationale TXT.
//
// Anything else (an unknown field, a missing required field, a number out of
// range or not representable, trailing data, more than 512 bytes) makes the
// whole entry invalid, and an invalid entry is never selected (R14).
const (
	maxEntryBytes = 512
	maxSignalLen  = 16
	maxNoteLen    = 100
	// The fixed point the score becomes: weight =
	// round(score * weightScale), so selection works on integers exactly as
	// verification/lean/CorednsPlugins/GeoScore.lean models it.
	weightScale = 10000
	// Bounds `updated` to year 9999, so arithmetic on it with
	// int64 seconds cannot overflow.
	maxUpdated = 253402300799
)

// Entry is one endpoint's score as the writer published it.
type Entry struct {
	Signal  string  `json:"signal,omitempty"`
	Note    string  `json:"note,omitempty"`
	Score   float64 `json:"score"`
	Updated int64   `json:"updated"`
	Healthy bool    `json:"healthy"`
}

// wireEntry tells a missing field from a zero one.
type wireEntry struct {
	Score   *float64 `json:"score"`
	Healthy *bool    `json:"healthy"`
	Updated *int64   `json:"updated"`
	Signal  string   `json:"signal"`
	Note    string   `json:"note"`
}

var (
	errEntryTooLong  = errors.New("geoscore: entry longer than 512 bytes")
	errEntryMissing  = errors.New("geoscore: entry lacks score, healthy or updated")
	errEntryTrailing = errors.New("geoscore: trailing data after the entry")
	errEntryField    = errors.New("geoscore: entry has unknown field")
	errEntryDupField = errors.New("geoscore: entry repeats field")
)

// ParseEntry decodes and validates one stored entry. It is the only way the
// plugin turns store bytes into an Entry.
func ParseEntry(b []byte) (Entry, error) {
	if len(b) > maxEntryBytes {
		return Entry{}, errEntryTooLong
	}
	if err := checkFieldNames(b); err != nil {
		return Entry{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var w wireEntry
	if err := dec.Decode(&w); err != nil {
		return Entry{}, fmt.Errorf("geoscore: entry: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Entry{}, errEntryTrailing
	}
	if w.Score == nil || w.Healthy == nil || w.Updated == nil {
		return Entry{}, errEntryMissing
	}
	e := Entry{Score: *w.Score, Healthy: *w.Healthy, Updated: *w.Updated, Signal: w.Signal, Note: w.Note}
	if err := e.Validate(); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// entryFields are the field names of the schema, spelled exactly.
var entryFields = [...]string{"score", "healthy", "updated", "signal", "note"}

// checkFieldNames refuses a top-level member whose name is not spelled
// exactly as in entryFields, or that appears twice (R14). By itself,
// encoding/json matches names case-insensitively, with Unicode folding
// ("SCORE" and "ſcore" both set score), and lets a repeated member silently
// override the first, so a writer bug or a second JSON parser could read a different score
// from the same bytes. Anything that is not a JSON object is left to Decode
// to refuse.
func checkFieldNames(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil //nolint:nilerr // Not an object: Decode reports it.
	}
	var seen [len(entryFields)]bool
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil //nolint:nilerr // Malformed: Decode reports it.
		}
		name, ok := tok.(string)
		if !ok {
			return nil // Not reachable for a well-formed object; Decode reports it.
		}
		i := 0
		for i < len(entryFields) && entryFields[i] != name {
			i++
		}
		if i == len(entryFields) {
			return fmt.Errorf("%w %q", errEntryField, name)
		}
		if seen[i] {
			return fmt.Errorf("%w %q", errEntryDupField, name)
		}
		seen[i] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil //nolint:nilerr // Malformed: Decode reports it.
		}
	}
	return nil
}

// Validate reports whether e is an entry the plugin may select on: a finite
// score in [0, 1], a plausible timestamp, and printable labels.
func (e *Entry) Validate() error {
	// NaN fails both comparisons, so it is rejected here too.
	if !(e.Score >= 0 && e.Score <= 1) {
		return fmt.Errorf("geoscore: score %v outside [0, 1]", e.Score)
	}
	if e.Updated <= 0 || e.Updated > maxUpdated {
		return fmt.Errorf("geoscore: updated %d is not a Unix time in (0, %d]", e.Updated, int64(maxUpdated))
	}
	if len(e.Signal) > maxSignalLen {
		return fmt.Errorf("geoscore: signal longer than %d", maxSignalLen)
	}
	for i := range len(e.Signal) {
		if c := e.Signal[i]; !isLowerAlnum(c) && c != '-' {
			return fmt.Errorf("geoscore: signal %q: only a-z, 0-9 and '-'", e.Signal)
		}
	}
	if len(e.Note) > maxNoteLen {
		return fmt.Errorf("geoscore: note longer than %d", maxNoteLen)
	}
	for i := range len(e.Note) {
		if c := e.Note[i]; c < 0x20 || c > 0x7e {
			return errors.New("geoscore: note is not printable ASCII")
		}
	}
	return nil
}

// Weight is the fixed-point weight selection uses: round(score * 10000), in
// [0, 10000] for a valid entry. A positive score below 0.00005 rounds to 0
// and drains the endpoint like a score of 0.
func (e *Entry) Weight() uint32 {
	return uint32(math.Round(e.Score * weightScale))
}

// Marshal encodes e in the stored form. A writer in Go can use it; the
// plugin's tests use it to check that ParseEntry reads what is written.
func (e *Entry) Marshal() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("geoscore: marshal entry: %w", err)
	}
	return b, nil
}
