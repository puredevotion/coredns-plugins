# Benchmarks

Stored `go test -bench` output, one file per run, for comparing with
[benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat).

```sh
go install golang.org/x/perf/cmd/benchstat@latest

benchmarks/run.sh my-change          # writes benchmarks/results/my-change.txt
benchstat benchmarks/results/before-alloc-pass.txt benchmarks/results/my-change.txt
```

`COUNT` (default 8) and `BENCHTIME` (default 300ms) override the sample size.

Rules for useful comparisons:

- Compare runs from the same machine; absolute numbers across machines mean nothing.
  Each file records `cpu:` and the Go version in its header.
- Run `run.sh` on a clean checkout of the base commit and again on your change.
  Commit only results you want to keep as a reference point.
- Trust `allocs/op` and `B/op` (deterministic) over `ns/op` (noisy). benchstat marks
  `~` when the difference is not significant.
- Allocation budgets on the hot parse paths are also enforced by `alloc_test.go`
  (`testing.AllocsPerRun`) in `probe` and `radnr/pkg/dnr`.

Profiling a single benchmark:

```sh
go test -run='^$' -bench=ServeDNS/A/unsigned -memprofile mem.out -memprofilerate=1
go tool pprof -sample_index=alloc_objects -top -lines <pkg>.test mem.out
go build -gcflags='-m=2' ./... 2>&1 | grep 'escapes to heap'
```

## Results

| File | What |
| --- | --- |
| `before-alloc-pass.txt` | `main` at v0.7.0, before the `decodeADN` / `toLowerASCII` allocation pass |
| `after-alloc-pass.txt` | after it: `Unmarshal` 7 to 3 allocs (-39% time), mixed-case `ParseQuery` 2 to 1 alloc |
