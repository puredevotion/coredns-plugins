#!/usr/bin/env bash
# Runs the verification suite. Exits non-zero on any mismatch or failure.
#
#   verification/run.sh            # everything
#   verification/run.sh tla        # sany + tlc + apalache
#   verification/run.sh sany       # parse and level-check every spec
#   verification/run.sh tlc        # explicit-state model checking
#   verification/run.sh apalache   # type checking, bounded model checking,
#                                  #   inductive-invariant proofs
#   verification/run.sh lean       # Lean proofs
#
# Every TLC config in tla/ starts with `\* expect: pass` or
# `\* expect: violated <Property>`, and a second line saying how Apalache
# checks it (`\* apalache: length=<n> inv=<A,B,...> [slow]`, or `skip`).
# Every config in tla/inductive/ starts with `\* expect: proved` or
# `\* expect: refuted`. The run fails if any tool disagrees with what a
# config declares.
#
# Tools: java 17+ (21+ for Apalache); tla2tools.jar and Apalache are fetched at pinned,
# checksummed versions unless TLA2TOOLS (the jar) or APALACHE (the
# apalache-mc launcher) point at local copies; lake/lean on PATH for the
# proofs (lean/lean-toolchain pins the version). APALACHE_SLOW=1 also runs
# the bounded checks marked `slow`, whose properties the inductive proofs
# already cover.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
what=${1:-all}

# The latest stable TLA+ release. Not v1.8.0: that release's tla2tools.jar
# is a nightly build of master, re-uploaded every day under the same URL, so
# no checksum of it holds for long.
TLA2TOOLS_VERSION=1.7.4
TLA2TOOLS_SHA256=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
APALACHE_VERSION=0.62.3
APALACHE_SHA256=83ab873d4dc0f8b607aeea6df0bfebf604f90b4b39f2d464357125698970365c

fetch() { # url sha256 dest
  mkdir -p "$(dirname "$3")"
  curl -fsSL -o "$3.part" "$1"
  echo "$2  $3.part" | sha256sum -c --quiet
  mv "$3.part" "$3"
}

fetch_tla2tools() {
  if [[ -n ${TLA2TOOLS:-} ]]; then return; fi
  TLA2TOOLS="$here/.tools/tla2tools-$TLA2TOOLS_VERSION.jar"
  [[ -f $TLA2TOOLS ]] || fetch \
    "https://github.com/tlaplus/tlaplus/releases/download/v$TLA2TOOLS_VERSION/tla2tools.jar" \
    "$TLA2TOOLS_SHA256" "$TLA2TOOLS"
}

fetch_apalache() {
  if [[ -n ${APALACHE:-} ]]; then return; fi
  local dir="$here/.tools/apalache-$APALACHE_VERSION"
  APALACHE="$dir/bin/apalache-mc"
  if [[ ! -x $APALACHE ]]; then
    fetch "https://github.com/apalache-mc/apalache/releases/download/v$APALACHE_VERSION/apalache.tgz" \
      "$APALACHE_SHA256" "$here/.tools/apalache.tgz"
    mkdir -p "$dir"
    tar -xzf "$here/.tools/apalache.tgz" -C "$dir" --strip-components=1
    rm "$here/.tools/apalache.tgz"
  fi
}

report() { # name got expected
  if [[ $2 == "$3" ]]; then
    printf 'ok    %-44s %s\n' "$1" "$2"
  else
    printf 'FAIL  %-44s expected "%s", got "%s"\n' "$1" "$3" "$2"
    return 1
  fi
}

check_sany() {
  fetch_tla2tools
  local failed=0 spec out
  cd "$here/tla"
  for spec in *.tla; do
    # SANY 1.7.x exits 0 even after semantic or level errors (1.8 added
    # -error-codes for that), so its report decides too.
    if out=$(java -cp "$TLA2TOOLS" tla2sany.SANY "$spec" 2>&1) &&
      ! grep -qE '^Semantic errors:|^\*\*\* Errors:|Parse Error|^Fatal errors' <<<"$out"; then
      report "sany $spec" ok ok
    else
      report "sany $spec" error ok || failed=1
      grep -vE '^Picked up|^\s*$' <<<"$out" | tail -20 | sed 's/^/      /'
    fi
  done
  return $failed
}

# only_temporal_property prints the config's PROPERTY when it lists exactly
# one, on a single PROPERTY/PROPERTIES line, and fails otherwise.
only_temporal_property() { # cfg
  local names
  names=$(sed -nE 's/^PROPERT(Y|IES)[[:space:]]+//p' "$1")
  [[ $(grep -c . <<<"$names") -eq 1 && $names =~ ^[A-Za-z0-9_]+$ ]] && echo "$names"
}

check_tlc() {
  fetch_tla2tools
  local failed=0 meta cfg spec expect out got prop
  meta=$(mktemp -d)
  cd "$here/tla"
  for cfg in *.cfg; do
    spec=${cfg%%_*}.tla
    expect=$(sed -n '1s/^\\\* expect: //p' "$cfg")
    # No trace-spec flag: TLC 1.7.x writes SpecTE files only when asked
    # (-generateSpecTE); 1.8 made that the default (-noGenerateSpecTE).
    out=$(java -XX:+UseParallelGC -cp "$TLA2TOOLS" tlc2.TLC -workers auto \
      -metadir "$meta/${cfg%.cfg}" -config "$cfg" "$spec" 2>&1) || true
    if grep -q "^Model checking completed. No error has been found." <<<"$out"; then
      got=pass
    elif prop=$(grep -oE "^Error: (Invariant|Action property|Temporal property) [A-Za-z0-9_]+ (is|was) violated" <<<"$out" |
                head -1 | awk '{print $(NF-2)}') && [[ -n $prop ]]; then
      got="violated $prop"
    elif grep -q "^Error: Temporal properties were violated." <<<"$out" &&
      prop=$(only_temporal_property "$cfg"); then
      # TLC 1.7.x does not name the violated temporal property. With one
      # PROPERTY in the config there is nothing else it can be.
      got="violated $prop"
    else
      got=error
    fi
    if ! report "tlc $cfg" "$got" "$expect"; then
      grep -E "^Error|line [0-9]+, col" <<<"$out" | head -20 | sed 's/^/      /'
      failed=1
    fi
  done
  rm -rf "$meta"
  return $failed
}

# One Apalache `check`, in a scratch copy of the specs. Prints NoError,
# Error (a property violated), or error (anything else: a type error, an
# unsupported construct, a crash).
apalache_check() { # spec cfg-file init inv length
  local work out
  work=$(mktemp -d)
  cp "$here"/tla/*.tla "$work/"
  cp "$2" "$work/apalache.cfg"
  out=$(cd "$work" && "$APALACHE" check --out-dir="$work/out" --config=apalache.cfg \
    --init="$3" --inv="$4" --length="$5" "$1" 2>&1) || true
  rm -rf "$work"
  grep -oE 'The outcome is: (NoError|Error)' <<<"$out" | awk '{print $NF}' | grep . || {
    echo error
    grep -E '^\[|rror' <<<"$out" | grep -v '^Picked up' | head -10 >&2
  }
}

check_apalache() {
  local major
  major=$(java -XshowSettings:properties -version 2>&1 | sed -n 's/^ *java.specification.version = //p')
  if (( ${major:-0} < 21 )); then
    echo "FAIL  Apalache $APALACHE_VERSION needs Java 21+, found ${major:-none}" >&2
    return 1
  fi
  fetch_apalache
  local failed=0 spec cfg line len inv expect got want tmp step init props
  cd "$here/tla"
  tmp=$(mktemp -d)

  for spec in *.tla; do
    if (cd "$tmp" && "$APALACHE" typecheck --out-dir="$tmp/out" "$here/tla/$spec" >/dev/null 2>&1); then
      report "apalache typecheck $spec" ok ok
    else
      report "apalache typecheck $spec" error ok || failed=1
    fi
  done

  # Bounded model checking of the TLC configs, to TLC's state-graph depth
  # for that instance: the same instances, a different checker.
  for cfg in *.cfg; do
    line=$(sed -n '2s/^\\\* apalache: //p' "$cfg")
    case $line in
      skip*) printf 'skip  %-44s %s\n' "apalache bmc $cfg" "${line#skip }"; continue ;;
      *slow*) if [[ -z ${APALACHE_SLOW:-} ]]; then
                printf 'skip  %-44s %s\n' "apalache bmc $cfg" "slow (APALACHE_SLOW=1 runs it)"; continue
              fi ;;
    esac
    len=$(sed -E 's/.*length=([0-9]+).*/\1/' <<<"$line")
    inv=$(sed -E 's/.*inv=([^ ]+).*/\1/' <<<"$line")
    # The TLC config, with SPECIFICATION swapped for INIT/NEXT: Apalache
    # does not check fairness, so it only ever sees the safety part.
    { sed -n '/^CONSTANTS/,/^SPECIFICATION/p' "$cfg" | grep -v '^SPECIFICATION'
      echo "INIT Init"; echo "NEXT Next"; } > "$tmp/bmc.cfg"
    case $(sed -n '1s/^\\\* expect: //p' "$cfg") in
      pass) want=NoError ;;
      *) want=Error ;;
    esac
    got=$(apalache_check "${cfg%%_*}.tla" "$tmp/bmc.cfg" Init "$inv" "$len")
    report "apalache bmc $cfg (len $len)" "$got" "$want" || failed=1
  done

  # Inductive invariants: Init => Ind, Ind /\ Next => Ind', and Ind => the
  # properties (one step, so action properties are covered too). "proved"
  # needs all three; "refuted" (a negative control) needs one to fail.
  for cfg in inductive/*.cfg; do
    spec=$(basename "${cfg%%_*}").tla
    inv=$(sed -n 's/^\\\* inductive: //p' "$cfg")
    expect=$(sed -n '1s/^\\\* expect: //p' "$cfg")
    got=proved
    for step in "Init $inv 0" "$inv $inv 1" "$inv $(sed -n 's/^\\\* implies: //p' "$cfg") 1"; do
      read -r init props len <<<"$step"
      case $(apalache_check "$spec" "$cfg" "$init" "$props" "$len") in
        NoError) ;;
        Error) got=refuted ;;
        *) got=error; break ;;
      esac
    done
    report "apalache inductive $(basename "$cfg")" "$got" "$expect" || failed=1
  done

  rm -rf "$tmp"
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
  sany) check_sany ;;
  tlc) check_tlc ;;
  apalache) check_apalache ;;
  tla) check_sany && check_tlc && check_apalache ;;
  lean) check_lean ;;
  all) check_sany && check_tlc && check_apalache && check_lean ;;
  *) echo "usage: $0 [sany|tlc|apalache|tla|lean|all]" >&2; exit 2 ;;
esac
