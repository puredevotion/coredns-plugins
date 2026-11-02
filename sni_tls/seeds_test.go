package snitls

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// maxSeedLine skips seed lines too long to be interesting names.
const maxSeedLine = 1024

// readSeedLines returns the usable lines of one seed file, at most limit of
// them when limit > 0, skipping blanks, '#' comments and over-long lines.
func readSeedLines(tb testing.TB, path string, limit int) []string {
	tb.Helper()
	fh, err := os.Open(path) //nolint:gosec // G304: test-only seed paths from the repo or $FUZZ_SEED_DIR.
	if err != nil {
		tb.Fatalf("seed file: %v", err)
	}
	tb.Cleanup(func() {
		if cerr := fh.Close(); cerr != nil {
			tb.Errorf("close %s: %v", path, cerr)
		}
	})

	var lines []string
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() && (limit <= 0 || len(lines) < limit) {
		line := strings.TrimRight(sc.Text(), "\r")
		if line != "" && len(line) <= maxSeedLine && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	if err := sc.Err(); err != nil {
		tb.Fatalf("seed file %s: %v", path, err)
	}
	return lines
}

// stringSeeds returns extra string seeds for the fuzz targets: the committed
// fuzz-seeds/blns.txt, plus every *.txt line under $FUZZ_SEED_DIR (capped per
// file by $FUZZ_SEED_MAX). See fuzz-seeds/README.md.
func stringSeeds(tb testing.TB) []string {
	tb.Helper()
	files := []string{filepath.Join(append(strings.Split("..", "/"), "fuzz-seeds", "blns.txt")...)}
	limit := 0 // Unset or malformed $FUZZ_SEED_MAX: no cap.
	if dir := os.Getenv("FUZZ_SEED_DIR"); dir != "" {
		extra, globErr := filepath.Glob(filepath.Join(dir, "*.txt"))
		if globErr != nil || len(extra) == 0 {
			tb.Fatalf("FUZZ_SEED_DIR %q: no *.txt files (%v)", dir, globErr)
		}
		files = append(files, extra...)
		if n, convErr := strconv.Atoi(os.Getenv("FUZZ_SEED_MAX")); convErr == nil {
			limit = n
		}
	}

	seen := map[string]struct{}{}
	var out []string
	for _, p := range files {
		for _, line := range readSeedLines(tb, p, limit) {
			if _, dup := seen[line]; !dup {
				seen[line] = struct{}{}
				out = append(out, line)
			}
		}
	}
	return out
}
