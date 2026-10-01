#!/usr/bin/env bash
# Checks every TLA+ model against the outcome its .cfg declares, then builds
# the Lean proofs. Exits non-zero on any mismatch or proof failure.
#
#   verification/run.sh            # both
#   verification/run.sh tla        # TLC only
#   verification/run.sh lean       # Lean only
#
# Tools: java (17+) and either TLA2TOOLS (path to tla2tools.jar) or network
# access to fetch the pinned jar; lake/lean on PATH for the proofs (the
# toolchain is pinned by lean/lean-toolchain). Downloads are checksummed.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
what=${1:-all}

TLA2TOOLS_VERSION=1.8.0
TLA2TOOLS_SHA256=edee9330068fbb7be0bc9dc2bc928f5918a7635b5ee4da56dbb48556b7afa6a2

fetch_tla2tools() {
  if [[ -n ${TLA2TOOLS:-} ]]; then return; fi
  TLA2TOOLS="$here/.tools/tla2tools-$TLA2TOOLS_VERSION.jar"
  if [[ ! -f $TLA2TOOLS ]]; then
    mkdir -p "$here/.tools"
    curl -fsSL -o "$TLA2TOOLS.part" \
      "https://github.com/tlaplus/tlaplus/releases/download/v$TLA2TOOLS_VERSION/tla2tools.jar"
    echo "$TLA2TOOLS_SHA256  $TLA2TOOLS.part" | sha256sum -c --quiet
    mv "$TLA2TOOLS.part" "$TLA2TOOLS"
  fi
}

# Each .cfg starts with `\* expect: pass` or `\* expect: violated <Property>`,
# naming the invariant, action property or temporal property TLC must report
# as violated first.
check_tla() {
  fetch_tla2tools
  local failed=0 meta
  meta=$(mktemp -d)
  trap 'rm -rf "$meta"' RETURN
  cd "$here/tla"
  for cfg in *.cfg; do
    local spec=${cfg%%_*}.tla expect out
    expect=$(sed -n '1s/^\\\* expect: //p' "$cfg")
    out=$(java -XX:+UseParallelGC -cp "$TLA2TOOLS" tlc2.TLC -workers auto \
      -noGenerateSpecTE -metadir "$meta/${cfg%.cfg}" -config "$cfg" "$spec" 2>&1) || true
    local got
    if grep -q "^Model checking completed. No error has been found." <<<"$out"; then
      got=pass
    elif prop=$(grep -oE "^Error: (Invariant|Action property|Temporal property) [A-Za-z0-9_]+ (is|was) violated" <<<"$out" |
                head -1 | awk '{print $(NF-2)}') && [[ -n $prop ]]; then
      got="violated $prop"
    else
      got="error"
    fi
    if [[ $got == "$expect" ]]; then
      printf 'ok    %-40s %s\n' "$cfg" "$got"
    else
      printf 'FAIL  %-40s expected "%s", got "%s"\n' "$cfg" "$expect" "$got"
      grep -E "^Error|line [0-9]+, col" <<<"$out" | head -20 | sed 's/^/      /'
      failed=1
    fi
  done
  return $failed
}

check_lean() {
  cd "$here/lean"
  lake build
  # Every theorem must rest on Lean's own axioms only: no sorry, no new
  # axiom smuggled in.
  if grep -rnE '\bsorry\b|\badmit\b|^axiom ' CorednsPlugins/; then
    echo "FAIL  proof holes found" >&2
    return 1
  fi
}

case $what in
  tla) check_tla ;;
  lean) check_lean ;;
  all) check_tla && check_lean ;;
  *) echo "usage: $0 [tla|lean|all]" >&2; exit 2 ;;
esac
