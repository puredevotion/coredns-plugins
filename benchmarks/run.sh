#!/usr/bin/env bash
# Run every benchmark and write benchstat-ready output to benchmarks/results/.
# Usage: benchmarks/run.sh [label]   (label defaults to the short git sha)
# Compare: benchstat benchmarks/results/<old>.txt benchmarks/results/<new>.txt
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
label=${1:-$(git -C "$root" rev-parse --short HEAD)}
out="$root/benchmarks/results/$label.txt"
mkdir -p "$root/benchmarks/results"
{
	echo "# label: $label"
	echo "# date: $(date -u +%FT%TZ)"
	echo "# go: $(go version)"
	echo "# count=${COUNT:-8} benchtime=${BENCHTIME:-300ms}"
} >"$out"
for m in probe sni_tls dynupdate radnr cookie; do
	(cd "$root/$m" && go test ./... -run='^$' -bench=. -benchmem \
		-count="${COUNT:-8}" -benchtime="${BENCHTIME:-300ms}") | grep -E '^(goos|goarch|pkg|cpu|Benchmark)' >>"$out" || true
done
echo "wrote $out"
