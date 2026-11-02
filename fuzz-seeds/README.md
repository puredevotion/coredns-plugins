# Fuzz seed strings

String seeds for the Go fuzz targets that take a name or other free text
(`sni_tls`, `probe`, `radnr/pkg/dnr`). They only widen the starting corpus;
coverage-guided mutation does the rest. Go's fuzzer has no dictionary support,
so seeds are the only way to feed it known-nasty strings.

| File | Source | Licence |
| --- | --- | --- |
| `blns.txt` | [minimaxir/big-list-of-naughty-strings](https://github.com/minimaxir/big-list-of-naughty-strings) @ `db33ec7` | MIT |

`blns.txt` is always loaded by the targets' `stringSeeds` helper.

## Larger lists (not committed)

[danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) (MIT) is
about 3.7 GB, so it is not vendored. Point `FUZZ_SEED_DIR` at a directory of
`*.txt` files and the helper loads every line as an extra seed; the nightly
workflow fetches a pinned selection this way for the matrix entries marked
`seeds: true` (sni_tls, probe, radnr-dnr): twelve `Discovery/DNS/*` and
`Fuzzing/*` lists from SecLists commit `43cbd03`, with `FUZZ_SEED_MAX=500`.
With that many seeds the fuzzer's baseline-coverage pass can take most of a
short run; lower `FUZZ_SEED_MAX` for quick local campaigns.

```sh
FUZZ_SEED_DIR=/path/to/seeds go test -run=NONE -fuzz=FuzzParseQuery -fuzztime=60s .
```

`FUZZ_SEED_MAX` caps how many lines are loaded per file (default: no cap). With
`FUZZ_SEED_DIR` set, plain `go test` also runs every seed once, so leave it
unset outside fuzzing runs.
