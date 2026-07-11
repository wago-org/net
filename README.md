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
network := wagonet.New(
    wagonet.WithConfig(wagonet.Config{StaticIPv4: deploymentNetwork}),
)
if err := tcp.Register(network); err != nil {
    return err
}
return wago.NewRuntime().Use(network)
```

Protocols compose explicitly when a guest needs more than one:

```go
network := wagonet.New(
    wagonet.WithConfig(wagonet.Config{StaticIPv4: deploymentNetwork}),
)
if err := udp.Register(network); err != nil {
    return err
}
if err := tcp.Register(network); err != nil {
    return err
}
if err := dns.Register(network, dns.Resolver("192.0.2.53")); err != nil {
    return err
}
return wago.NewRuntime().Use(network)
```

TCP defaults provide eight finite outbound streams and no listeners. UDP defaults
provide eight finite sockets, ephemeral wildcard client binds, outbound ordinary
unicast, and replies; server ports, privileged binds, loopback, multicast, and
broadcast remain explicit options. DNS installs finite A/AAAA query, response,
record, and retry bounds when `dns.Resolver` supplies an explicit IPv4 resolver.
Caller deny rules always win over composed defaults. `WithConfig` supplies exact
protocol storage, `WithPolicy` adds advanced raw authority, and
`WithoutDefaultAuthority` supports fully caller-authored compatibility policy.
Listener/server grants and the conspicuous `tcp.AllowAll()`, `udp.AllowAll()`,
and `dns.AllowAll()` options never remove finite storage or quota bounds.

Registering only TCP exposes `net.info` and `net.tcp`, with
`wago_net.abi_version` and the eleven `wago_net_tcp` imports. Registering only
UDP analogously exposes `net.info`, `net.udp`, the shared ABI import, and the six
`wago_net_udp` imports. Registering only DNS exposes `net.info`, `net.dns`, the
shared ABI import, and the six `wago_net_dns` imports. Unregistered protocol
imports are absent and fail normal WebAssembly import resolution. The public
TCP, UDP, and DNS facades each construct an opaque descriptor, and all three
checked host tables live in protocol-specific internal binding packages. The
root package no longer imports those public or binding packages. Dependency and
runtime-inspection fixtures cover no protocol, every single protocol, every
pair, and all three. Omitted public, binding, instance-operation, and fixed ABI
packages are rejected from each fixture's Go dependency graph. Shared checked
memory, endpoint/handle codecs, and poll layouts live in `internal/abi/core`;
TCP, UDP, and DNS layouts live only in `internal/abi/tcp`, `/udp`, and `/dns`.
The dependency matrix also rejects each omitted protocol's namespace facet and
`internal/backend/lneto/{tcp,udp,dns}` adapter, and rejects the temporary
aggregate lneto assembler from every selective production graph. One
protocol-neutral instance core still owns exact attachment, resource identity,
readiness, quotas, polling, and teardown, while
`internal/instance/tcp`, `internal/instance/udp`, and `internal/instance/dns`
serialize their operations through that core. Namespace ownership is likewise
split: `internal/namespace/core` owns shared endpoint, failure, readiness,
resource, and bounded-service contracts, while `/tcp`, `/udp`, and `/dns` own
narrow protocol facets and values. Production graphs no longer reach the former
aggregate namespace compatibility package. `internal/backend/lneto/core` now
owns the single lifecycle lock, `StackAsync`, packet link, IPv4 identity, frame
scratch, bounded ingress/egress scheduler, participant ordering, maintenance
charging, shared UDP-port leases, and deterministic close. TCP listeners and
streams, UDP sockets and queues, and DNS query/wire state now live independently
in `internal/backend/lneto/tcp`, `/udp`, and `/dns`. Focused tests preserve
immediate operations, cross-UDP/DNS port collisions, packet and maintenance
accounting, response filtering, quotas, and ordered cleanup. Protocol descriptors
now contribute only their exact adapter after registration freezes. The root
creates one shared lneto core per exact instance, installs selected adapters
transactionally before publishing the namespace, and exposes them through an
immutable protocol-neutral service composition. Failed assembly closes the core
and every installed participant before any instance state is published. The root
imports no aggregate or protocol adapter package, and TCP-only, UDP-only, and
DNS-only fixtures compile only their selected public, binding, operation,
namespace-facet, ABI, and adapter packages. Protocol authority contributions are
deep-copied and composed once before manager construction; one immutable policy
and quota domain remain shared per exact instance, with deny-wins behavior.

The aggregate advanced compatibility path is now explicit:

```go
network := compat.Init(wagonet.Config{
    // Immutable policy, finite quota/readiness, packet-link, static IPv4,
    // UDP queue, TCP pool, and bounded DNS resolver settings.
})
if err := wago.NewRuntime().Use(network); err != nil {
    return err
}
```

Import `github.com/wago-org/net/compat` for that constructor. The former root
`wagonet.Init` symbol was removed because retaining it forced every root and
selective client to compile all protocol bindings. `compat.Init` preserves the
aggregate `Config` behavior and explicitly selects UDP, TCP, and DNS. Each
configured Runtime instance still receives its own isolated namespace and
handles. New callers should prefer `wagonet.New` plus only the protocol-local
registration functions they need. Advanced selective callers pass exact backend
storage through `tcp.WithConfig(tcp.Config{...})`,
`udp.WithConfig(udp.Config{...})`, or `dns.WithConfig(dns.Config{...})`; the
compatibility constructor maps the legacy aggregate protocol fields explicitly.

The extension declares that networking state requires physical reinstantiation.
Wago therefore downgrades `ResetMemorySnapshot` and other in-place class reset
requests to `ResetReinstantiate`; UDP/TCP/DNS handles, queues, policy state, and
quota accounts cannot cross leases even when callers request snapshot reuse.

Custom Wago binaries can self-register exactly one protocol without compiling
the others:

```go
import _ "github.com/wago-org/net/tcp/register" // extension key: net-tcp
// or github.com/wago-org/net/udp/register       // extension key: net-udp
// or github.com/wago-org/net/dns/register       // extension key: net-dns
```

The root package remains the explicit all-protocol bundle:

```go
import _ "github.com/wago-org/net/register" // extension key: net
```

The granular packages install protocol defaults but do not invent deployment
IPv4 identity/link configuration; DNS resolver storage also remains disabled in
the zero-configuration self-registering form. Applications needing those values
should use explicit `wagonet.New` composition.

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
cross-build, direct/dependency inspection, granular `net-tcp`/`net-udp`/`net-dns`
and aggregate `net` custom CLI inspection, and final clean-tree checks; and
records disposable artifacts under `.wago/release-signoff`:

```sh
scripts/release-signoff.sh
```

The current Wago review is replayed on exact upstream
`18615546584ec09e607856a0da99851656f5be80`, and pack-only reconstruction now
validates aggregate plus granular registration under standard Go and TinyGo.
The strict local release gate now uses an exact clean production-Wago worktree,
so a separate user-owned dirty audit checkout is neither cleaned nor used for
compilation. The complete gate passes locally with truthful retained evidence;
production activation remains blocked by absent native/QEMU arm64 execution,
unpublished review and production Wago subjects, and the accepted WASI
preview-1 exceptions.

See [`docs/release-signoff.md`](docs/release-signoff.md) for the exact matrix,
pinned revisions, CI tiers, and the narrowly accepted known WASI preview-1 native
SIGSEGV. Long-running implementation work follows
`.pi/skills/recursive-handoff/SKILL.md` and the durable state in `agent-todo.md`.

## License

Apache-2.0.
