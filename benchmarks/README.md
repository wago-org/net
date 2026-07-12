# Performance baselines

The benchmark suite covers the runtime paths identified as performance-sensitive
in `docs/architecture.md`:

- checked shared, TCP, UDP, and DNS guest-memory codecs;
- namespace value validation and service lookup;
- resource handle creation, lookup, reuse, close, and table teardown;
- policy merge/compile and endpoint/DNS decisions;
- quota reservation, scoped service charging, and snapshots;
- readiness registration and bounded polling at 1, 16, and 256 resources;
- packet-link copy/fill/dequeue paths at representative frame sizes;
- shared lneto service scheduling, UDP port leasing, and readiness;
- UDP bind, queue, send/egress, receive, and readiness paths;
- TCP listen, connect completion, readiness, accept, and a live 64-byte
  client/server round trip;
- DNS query construction, wire-name decode, response parse/selection, query
  creation, record iteration, and readiness;
- instance manager attach/lookup/locking/poll and protocol operation wrappers;
- guest status mapping and complete UDP/TCP guest poll host calls.

The checked-in capture is in `baseline.txt`; `baseline-summary.md` lists the
median timing and allocation result for all 114 benchmark cases. It was captured
with three 100 ms samples to keep the initial audit bounded. The script defaults
to the stronger five-by-200 ms profile for future comparison runs.

These are microbenchmarks. The adapter and guest benchmarks include the locks,
validation, policy, accounting, and copies performed by the named path, but they
do not model operating-system networking or application-level concurrency. The
TCP round-trip benchmark is the broadest data-plane benchmark: it drives two
in-memory lneto stacks through egress, packet-link transfer, ingress, stream read,
and acknowledgement transfer.

## Capture a baseline

```sh
scripts/benchmark-baseline.sh
```

The default writes `benchmarks/baseline.txt`, runs five 200 ms samples of every
benchmark, records allocations, and pins execution to one logical CPU for more
stable comparisons. Override the sampling without editing the script:

```sh
BENCH_COUNT=10 BENCH_TIME=500ms BENCH_CPU=1 \
  scripts/benchmark-baseline.sh benchmarks/candidate.txt
```

Compare two captures with `benchstat` when it is available:

```sh
benchstat benchmarks/baseline.txt benchmarks/candidate.txt
```

Always compare captures from equivalent hardware, power policy, Go toolchain,
`GOMAXPROCS`, and source configuration. Allocation regressions are usually more
portable than small timing differences across machines.
