# Wago Networking

Capability-gated networking plugins for the [Wago](https://github.com/wago-org/wago)
WebAssembly runtime, backed initially by [lneto](https://github.com/soypat/lneto).

The repository exposes the experimental `wago_net.abi_version` core import plus
separately capability-gated `wago_net_udp`, `wago_net_tcp`, and `wago_net_dns`
modules. UDP covers configured-namespace discovery, bind, send, receive, close,
and bounded poll. TCP covers discovery, listen, nonblocking connect completion,
accept, partial read/write, write-half shutdown, kind-specific close, and its own
bounded poll. DNS covers configured resolver discovery, bounded A/AAAA queries,
copied A/AAAA/CNAME iteration, cancellation, close, and bounded poll.
The stable numeric status taxonomy and fixed v1 address/result layouts use central
checked guest memory; exact instance identity, generation/kind-checked handles,
immutable endpoint policy, finite quotas, and deterministic lifecycle cleanup
remain mandatory on every guest operation. The lneto backend uses adapter-owned
fixed UDP queues, immediate frame codecs, and immediate TCP handler primitives;
no host-facing path uses its blocking/backoff wrappers. Protocol polling is
level-triggered and bounded independently by scans, event outputs, namespace
service attempts, and per-attempt packet/byte/operation budgets, with finite
per-instance service-work accounting. The bounded lneto-backed DNS engine uses
generation-safe per-instance query handles with readiness, cancellation, timeout,
quota, and lifecycle cleanup. It correlates exact echoed questions, emits only a
unique reachable CNAME chain plus requested terminal A/AAAA records, rejects
conflicting chains and loops, and directly fuzzes compressed wire parsing. DNS is
UDP-only: truncated responses return `TEMPORARY_FAILURE` because DNS-over-TCP
fallback is not implemented. Privileged packet access remains absent and
unsupported.

```go
rt := wago.NewRuntime()
if err := rt.Use(wagonet.Init(wagonet.Config{})); err != nil {
    return err
}

// A configured deployment can instead provide immutable policy, finite quota,
// readiness, packet-link, static IPv4, UDP queue, TCP pool, and bounded DNS
// resolver settings. Each
// Runtime instance then receives its own isolated namespace and handles.
```

The extension declares that networking state requires physical reinstantiation.
Wago therefore downgrades `ResetMemorySnapshot` and other in-place class reset
requests to `ResetReinstantiate`; UDP/TCP/DNS handles, queues, policy state, and
quota accounts cannot cross leases even when callers request snapshot reuse.

Custom Wago binaries can include the plugin through its self-registering package:

```go
import _ "github.com/wago-org/net/register"
```

The guest ABI is custom to Wago. It may follow WASI socket semantics where useful,
but it is not binary-compatible with WASI Component Model resources.

## Development

Fast local checks:

```sh
go test ./...
go test -race ./...
go vet ./...
scripts/check-source-boundaries.sh
```

The deterministic release gate additionally pins and verifies the production
Wago/lneto/WASI inputs and exact current Wago/networking/workers review objects;
reconstructs the current plugin workspace from immutable packs with a cold,
network-disabled module cache; records publication status without claiming
publisher authentication or hosted activation; emits an unsigned canonical
statement binding the exact subject, provenance, bundle, and review subjects for
external detached signing; optionally verifies a raw Ed25519 signature only
against an explicitly supplied no-discovery trust policy that can pin the exact
statement digest and plugin subject against rollback; publishes public positive
and negative detached-signature interoperability vectors without a private key
or publisher claim; optionally retains a checksummed canonical intermediary
receipt binding the exact signature, statement, trust policy, provenance,
archive, subject, and opaque key label without claiming publisher identity;
keeps production activation behind published exact subjects, executed arm64
evidence, and zero accepted exceptions; atomically retains and independently
verifies checksummed canonical readiness receipts that bind the exact canonical
trust-policy digest, with public ready/blocked/tamper/constraint interoperability
vectors for external automation; audits unsupported pool topology; runs bounded
fuzz smoke, benchmarks, TinyGo,
cross-build, package/custom CLI inspection, and final clean-tree checks; and
records disposable artifacts under `.wago/release-signoff`:

```sh
scripts/release-signoff.sh
```

See [`docs/release-signoff.md`](docs/release-signoff.md) for the exact matrix,
pinned revisions, CI tiers, and the narrowly accepted known WASI preview-1 native
SIGSEGV. Long-running implementation work follows
`.pi/skills/recursive-handoff/SKILL.md` and the durable state in `agent-todo.md`.

## License

Apache-2.0.
