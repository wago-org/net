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

The primary composition API selects only the protocols a runtime should expose:

```go
network := wagonet.New()
if err := tcp.Register(network); err != nil {
    return err
}
// Compose other protocols only when the guest needs them.
if err := udp.Register(network); err != nil {
    return err
}
if err := dns.Register(network); err != nil {
    return err
}

rt := wago.NewRuntime()
if err := rt.Use(network); err != nil {
    return err
}
```

Registering only TCP exposes `net.info` and `net.tcp`, with
`wago_net.abi_version` and the eleven `wago_net_tcp` imports. Registering only
UDP analogously exposes `net.info`, `net.udp`, the shared ABI import, and the six
`wago_net_udp` imports. Registering only DNS exposes `net.info`, `net.dns`, the
shared ABI import, and the six `wago_net_dns` imports. Unregistered protocol
imports are absent and fail normal WebAssembly import resolution. The public
TCP, UDP, and DNS facades each construct an opaque descriptor, and all three
checked host tables live in protocol-specific internal binding packages. An
external public-API matrix covers no protocol, every single protocol, every
pair, and all three. Full compile isolation is not yet claimed: the aggregate
root compatibility path still imports all three binding packages, and the shared
instance operations plus lneto adapter remain unified. Package-local finite
client defaults also remain migration work.

The aggregate advanced compatibility path remains available while protocol
configuration is split into its public packages:

```go
network := wagonet.Init(wagonet.Config{
    // Immutable policy, finite quota/readiness, packet-link, static IPv4,
    // UDP queue, TCP pool, and bounded DNS resolver settings.
})
if err := wago.NewRuntime().Use(network); err != nil {
    return err
}
```

Each configured Runtime instance receives its own isolated namespace and
handles. `Init` explicitly selects UDP, TCP, and DNS; new selective callers
should prefer `New` plus `tcp.Register`, `udp.Register`, and `dns.Register` as
needed.

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
or publisher claim; optionally retains and independently verifies a checksummed
canonical intermediary receipt binding the exact signature, statement, trust
policy, provenance, archive, subject, and opaque key label without claiming
publisher identity or production readiness, with public synthetic positive and
tamper/constraint receipt vectors that store no signature or trust key; keeps
production activation behind published exact subjects, executed arm64
evidence, and zero accepted exceptions; freshly recomputes strict readiness from
the original signed inputs while binding a new v2 decision to the exact retained
trusted-distribution receipt and signature digest; preserves the v1 receipt
contract for compatibility; independently verifies both canonical receipt/
sidecar pairs and their exact linkage under explicit subject, statement,
signature, policy, and intermediary-receipt constraints without treating
retained evidence as fresh cryptography or publisher identity; publishes
synthetic linked ready/blocked/tamper/wrong-link interoperability chains without
signature bytes, trust keys, production identity, or activation claims; audits
unsupported pool topology; runs bounded
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
