# TLS-aware candidate comparison

`benchmarks/candidate.txt` is an independent second capture of the same clean
commit, toolchain, machine, and five-by-200 ms single-CPU profile as the refreshed
TLS-aware `benchmarks/baseline.txt`. `benchmarks/benchstat.txt` contains the full
comparison generated with `golang.org/x/perf/cmd/benchstat` after ignoring only
capture metadata fields that intentionally differ.

Both captures were taken on July 20, 2026 with Go 1.24.4 on Linux/amd64 and an
AMD Ryzen 7 8845HS. They are repeatability evidence, not before/after evidence
for a source change.

## Representative medians

| Path | Baseline | Candidate | Allocation result |
|---|---:|---:|---:|
| TLS 1.3 client handshake | 1.465 ms | 1.279 ms | 388,334/935 → 388,317/934 B/allocs |
| TLS fixed byte-ring steady state | 125.8 ns | 70.48 ns | 0/0 in both |
| TLS profile authorization | 15.04 ns | 14.83 ns | 0/0 in both |
| Shared TCP local-port lease | 41.49 ns | 40.39 ns | 0/0 in both |
| Live TCP round trip | 1.584 µs | 1.617 µs | 0/0 in both |
| TCP adapter connect/close | 791.3 ns | 635.9 ns | 1,128 B / 4 allocs in both |

The handshake and fixed-ring timing spread demonstrates why the repository does
not pin exact TLS latency. Standard-library cryptography, worker scheduling,
CPU frequency, and cache state affect these microbenchmarks. The allocation
classification is stable across both captures: repository-owned fixed rings,
profile authorization, shared TCP-port leases, and the live TCP data path remain
allocation-free.

No materially different hardware was used, and neither capture is represented
as hosted-runner or production-signoff evidence. Future release comparisons
should retain the same Go version, CPU class, power policy, sample count,
benchmark duration, and `GOMAXPROCS=1` setting.
