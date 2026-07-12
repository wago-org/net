# Candidate performance and validation summary

This summary compares the checked-in `benchmarks/baseline.txt` with the current
optimized `benchmarks/candidate.txt`, captured on July 12, 2026. The candidate
uses five 200 ms samples with `GOMAXPROCS=1`; the baseline uses three 100 ms
samples. Both benchmark captures use Go 1.24.4 on Linux/amd64 and an AMD Ryzen 7
8845HS. `benchmarks/benchstat.txt` contains the comparison after removing capture
metadata that would otherwise make benchstat treat the files as separate
configurations.

Because the baseline has only three samples, its confidence intervals are not
strong. Allocation counts and large timing changes are more reliable than small
single-digit timing differences.

## High-impact results

| Package / path | Baseline | Candidate median | Time change | Allocation change |
|---|---:|---:|---:|---:|
| DNS response parse | 1,096 ns | 353 ns | **-67.8%** | 1,048 B / 37 → **16 B / 1** |
| DNS answer selection | 446 ns | 117 ns | **-73.8%** | 592 B / 9 → **0 / 0** |
| DNS request validation | 93.4 ns | 29.5 ns | **-68.4%** | 112 B / 2 → **0 / 0** |
| DNS record validation | 93.5 ns | 30.2 ns | **-67.7%** | 112 B / 2 → **0 / 0** |
| Policy DNS check | 135 ns | 72.4 ns | **-46.2%** | 112 B / 2 → **0 / 0** |
| DNS wire-name decode | 96.2 ns | 37.7 ns | **-60.9%** | 56 B / 5 → **24 B / 1** |
| DNS query packet build | 158 ns | 100 ns | **-36.7%** | 152 B / 4 → **96 B / 1** |
| Caller-owned DNS query packet build | — | 81.2 ns | new path | **0 / 0** |
| DNS query create/close | 838 ns | 428 ns | **-48.9%** | 1,072 B / 17 → **1,408 B / 1** |
| DNS ABI query encode | 206 ns | 40.5 ns | **-80.3%** | 224 B / 4 → **0 / 0** |
| DNS ABI CNAME record encode | 382 ns | 67.5 ns | **-82.3%** | 416 B / 8 → **0 / 0** |
| Guest semantic error mapping | 48.9 ns | 4.83 ns | **-90.1%** | 8 B / 1 → **0 / 0** |
| Guest shared-error mapping | 50.6 ns | 2.49 ns | **-95.1%** | 8 B / 1 → **0 / 0** |
| UDP port lease | 52.2 ns | 38.9 ns | **-25.5%** | 16 B / 1 → **0 / 0** |
| UDP bind/create/close | 425 ns | 280 ns | **-34.3%** | 832 B / 12 → **640 B / 3** |
| TCP listener create/close | 533 ns | 414 ns | **-22.4%** | 1,792 B / 11 → **1,712 B / 7** |

The DNS create/close path now performs one allocation rather than 17 and is about
half the latency, but the single escaping `dnsQuery` is larger because it embeds
the maximum query packet and eight-record inline storage. This increases measured
bytes/op by 336 B. The object retains unique lifetime identity and is not pooled
or reanimated.

## Focused new benchmarks

The full sweep and consolidated `focused-verification.txt` capture record these
new paths:

| Benchmark | Measured result |
|---|---:|
| Embedded resource + queued-byte quota charge | 28.9 ns, 0 B, 0 allocs |
| Parallel embedded resource charge, `GOMAXPROCS=1` | 30.4 ns, 0 B, 0 allocs |
| Parallel embedded resource charge, `GOMAXPROCS=8` | 85.7 ns, 0 B, 0 allocs |
| Shared UDP receive/transmit queue allocation, focused | 371 ns, 4,992 B, 2 allocs |
| UDP zero-payload bind/close | 247 ns, 416 B, 2 allocs |
| DNS response, no CNAME | 190 ns, 0 B, 0 allocs |
| DNS response, one CNAME | 347 ns, 24 B, 1 alloc |
| DNS response, four CNAMEs | 861 ns, 96 B, 4 allocs |
| Policy endpoint check, 256 rules | 2.66 µs, 0 allocs |
| UDP egress scan, 256 sockets | 238 ns, 0 allocs |
| TCP outbound stream scan, 256 streams | 117 ns, 0 allocs |
| Parallel readiness poll, `GOMAXPROCS=1` | 186 ns, 0 allocs |
| Parallel readiness poll, `GOMAXPROCS=8` | 202 ns, 0 allocs |
| Parallel resource lookup, `GOMAXPROCS=1` | 6.19 ns, 0 allocs |
| Parallel resource lookup, `GOMAXPROCS=8` | 24.7 ns, 0 allocs |

The DNS shape results show the remaining parser allocation rule directly: the
no-alias response is allocation-free, while each distinct retained non-request
name currently contributes one string allocation. Repeated uses of the same name
are interned in bounded reusable scratch.

## Protected TCP steady-state paths

An initial ad hoc sweep produced order-sensitive TCP timing noise. The final
candidate was recaptured with the repository's official benchmark script, and a
dedicated ten-sample, 500 ms rerun retained in
`benchmarks/focused-verification.txt` independently checked the same paths:

| TCP benchmark | Baseline | Focused rerun median |
|---|---:|---:|
| Finish connect | 5.41 ns | 5.56 ns |
| Readiness | 13.4 ns | 14.0 ns |
| Accept would-block | 22.2 ns | 22.3 ns |
| Established 64-byte round trip | 1.327 µs | 1.356 µs |

All four focused paths remained at zero allocations. The final official full
sweep measured 5.69 ns, 14.3 ns, 23.0 ns, and 1.370 µs respectively, also close
to baseline and without the earlier ad hoc anomaly.

The focused manager rerun retained in `benchmarks/focused-verification.txt`
measured attach/detach around 1.35 µs with the allocation footprint unchanged at
18,152 B / 12 allocations. Other manager lookup, lock, and idle-poll paths were
near the baseline and allocation-free.

## Validation run for this candidate

The following commands completed successfully after formatting the modified Go
files:

- focused tests for DNS name/namespace/ABI/backend, policy, quota, lneto core,
  UDP, TCP, guest mapping, readiness, resources, and instance core;
- `go test ./...`;
- `go vet ./...`;
- `go test -race` for the focused packages and the complete `./...` package set;
- the complete benchmark sweep, focused DNS/creation/scaling benchmarks, and
  dedicated TCP, manager, UDP zero-payload, and multi-core parallel reruns.

## Remaining measured caveats

- DNS response parsing still allocates once per distinct retained non-request
  decoded name. It is allocation-free for responses whose retained owner is the
  request name and has no distinct CNAME target.
- DNS query creation is down to one allocation, but the embedded query object is
  1,408 B/op in the tested eight-record configuration, larger than the aggregate
  baseline byte count despite far fewer allocations and lower latency.
- Normal UDP bind/close still allocates the socket and two shared queue backing
  objects. Zero-payload UDP avoids payload backing and measured two allocations.
- TCP outbound creation measured 1,416 B / 6 allocations. Embedded quota charges
  removed quota-token allocations, but the stream, lneto connection, and buffer
  storage retain independent lifetimes.
- Single-digit timing changes in unrelated ABI, readiness, packet-link, and
  manager microbenchmarks are within the run-to-run drift visible across these
  captures and are not used to justify architectural lock or policy changes.
