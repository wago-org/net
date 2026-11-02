# TLS-aware baseline summary

The canonical baseline in `benchmarks/baseline.txt` was captured on July 20,
2026 from clean source commit `97b2bfca08df8d3e154bf7b4bb2cc932ec359ca8`.
It uses Go 1.24.4 on Linux/amd64, AMD Ryzen 7 8845HS, `GOMAXPROCS=1`, five
samples, 200 ms per benchmark, and `-benchmem`.

Discovery found **172 top-level benchmark targets in 50 packages**. Subbenchmark
expansion produced 195 distinct benchmark result names. This replaces the
pre-TLS three-by-100 ms baseline and includes the complete current TLS, shared
TCP-port, protocol, ABI, policy, quota, readiness, lifecycle, and guest-binding
benchmark surface.

## TLS and private-transport medians

| Path | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| TLS 1.3 client handshake | 1,465,373 | 388,334 | 935 |
| TLS fixed byte-ring steady state | 125.8 | 0 | 0 |
| TLS profile authorization | 15.04 | 0 | 0 |
| Shared TCP local-port lease acquire/release | 41.49 | 0 | 0 |
| Live in-memory TCP 64-byte round trip | 1,584 | 0 | 0 |
| Private/raw TCP adapter connect/close | 791.3 | 1,128 | 4 |

The TLS handshake allocation result is dominated by Go's standard-library TLS
and X.509 implementation. The repository-owned fixed byte ring, profile
authorization, shared local-port lease, and steady TCP round-trip paths remain
allocation-free.

## Interpretation

- TLS handshake timing is scheduling- and cryptography-sensitive; use repeated
  captures rather than exact timing assertions.
- The retained allocation counts are more stable than small timing differences.
- The byte-ring and profile-authorization paths show no per-operation heap
  growth.
- Shared TCP port leasing remains zero-allocation after raw TCP and private TLS
  transport were moved into one namespace-wide lease domain.
- This capture was produced on the same hardware and toolchain family as the
  preceding optimization evidence, so it is suitable as the repository's new
  TLS-aware local baseline. Release adoption still requires the separate strict
  release and platform gates.
