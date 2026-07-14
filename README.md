# Wago Networking

Capability-gated networking plugins for the [Wago](https://github.com/wago-org/wago)
WebAssembly runtime, backed initially by [lneto](https://github.com/soypat/lneto).
UDP, TCP, DNS, bounded ICMPv4 echo, explicit-clock NTP, bounded IPv4 multicast
DNS, DHCPv4, IPv4 link-local/APIPA, and configured IPv6 TCP transport
enablement are implemented today; ICMPv6/NDP and DHCPv6 remain absent and are
not advertised.

> [!WARNING]
> This module is private and experimental. Use it only with the exact Wago
> source revision selected and verified by the repository's signoff tooling;
> the `0.1.0` engine version alone does not identify the reviewed lifecycle and
> callback implementation. The current recorded release decision is blocked and
> must not be treated as production approval.

The repository exposes the experimental `wago_net.abi_version` core import plus
separately capability-gated `wago_net_udp`, `wago_net_tcp`, `wago_net_dns`,
`wago_net_icmpv4`, `wago_net_ntp`, `wago_net_mdns`, `wago_net_dhcpv4`,
`wago_net_linklocal4`, and `wago_net_ipv6` modules. UDP covers configured-namespace discovery, bind, send,
receive, close, and bounded poll. TCP covers discovery, listen, nonblocking
connect completion, accept, partial read/write, write-half shutdown,
kind-specific close, and its own bounded poll. DNS covers configured resolver
discovery, bounded A/AAAA queries, copied A/AAAA/CNAME iteration, cancellation,
close, and bounded poll. ICMPv4 covers copied bounded echo requests, exact reply
validation, service-attempt timeout, cancellation, close, and bounded poll. NTP
covers bounded two-exchange synchronization against one explicit IPv4 server,
uses only an injected host clock, returns a copied offset/delay/corrected-time
sample without adjusting the system clock, and supports cancellation, close, and
bounded poll. mDNS owns the exact shared UDP port 5353 lease, supports copied `.local`
A/PTR/SRV/TXT queries, automatic bounded responses from a copied host service
set, finite service announcements, cancellation, exact-kind close, and bounded
poll over 224.0.0.251 with TTL 255. DHCPv4 owns exact shared UDP port 68 for one
bounded immediate DORA lease and optionally port 67 for an explicitly configured
finite server pool; accepted address/subnet identity can be applied
transactionally over a `0.0.0.0` placeholder and rolls back on release or close.
IPv4 link-local uses the pinned immediate RFC 3927 state machine with an explicit
host clock and deterministic seed, emits only internal ARP probes/announcements,
keeps bounded defense active, and shares DHCPv4's exact single dynamic IPv4
identity lease domain. Repeated defense conflict rolls back the exact identity
before bounded reconfiguration; release and close restore the static
`0.0.0.0` placeholder. IPv6 contributes one static global or link-local
identity and checked immutable configuration introspection. It enables only the
pinned immediate TCP connect and address-specific listen family when TCP is
separately selected; IPv6 UDP, DNS-over-IPv6, extension headers, fragmentation,
flow labels, router discovery, DAD, SLAAC, and NDP are not claimed. The low-level `InfoImports` /
zero-config `Imports(Config{})` path remains core-only
and exposes only `wago_net.abi_version`; resource-owning protocol imports require
Runtime lifecycle ownership.
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
`dns.AllowAll()`, `icmpv4.AllowAll()`, `ntp.AllowAll()`, and
`mdns.AllowAllNames()` options never remove finite storage or quota bounds.
ICMPv4 defaults provide eight exchanges, 256 copied payload bytes
per exchange, two attempts, and finite service-attempt retry spacing; loopback,
multicast, and limited broadcast remain explicit grants. NTP requires an
explicit server plus `ntp.WithClock`; its defaults provide four concurrent
synchronizations, two attempts per exchange, and finite service-attempt spacing.
mDNS defaults provide eight queries, sixteen retained records, 1200-byte
packets, two attempts, finite parser limits, and `.local` authority. Configured
services add finite announcement and response queues. DHCPv4 defaults provide
one observation-only DORA lease, a 576-byte packet bound, four copied DNS
servers, and finite response service attempts; `dhcpv4.ApplyLeaseIdentity()`
requires a configured `0.0.0.0` placeholder, while `dhcpv4.WithServer` explicitly
enables a finite server pool. Caller policy remains deny-wins; neither NTP,
mDNS, DHCPv4, nor link-local authority inherits general UDP, DNS, ICMPv4, or
raw ARP authority. Link-local requires `linklocal4.WithSeed` plus
`linklocal4.WithClock`; defaults permit one claim, sixteen conflicts, and 256
service attempts. It requires a configured `0.0.0.0` placeholder and fails with
`INVALID_STATE` if DHCPv4 or another exact dynamic identity already owns the
namespace. The pinned DHCPv4 client does not implement immediate renewal,
rebinding, or wire DHCPRELEASE; the guest `release` operation is truthful local
identity rollback. IPv6 requires `ipv6.WithConfig` with a finite static address,
prefix, and exact link-local scope when applicable. Its three imports provide
namespace discovery, atomic 64-byte configuration, and bounded shared poll.
Caller denies on the configured identity prevent publication, and raw IPv6
packets remain internal.

Registering only TCP exposes `net.info` and `net.tcp`, with
`wago_net.abi_version` and the eleven `wago_net_tcp` imports. Registering only
UDP analogously exposes `net.info`, `net.udp`, the shared ABI import, and the six
`wago_net_udp` imports. Registering only DNS exposes `net.info`, `net.dns`, the shared ABI import, and
the six `wago_net_dns` imports. Registering only ICMPv4 exposes `net.info`,
`net.icmpv4`, the shared ABI import, and the six `wago_net_icmpv4` imports.
Registering only NTP exposes `net.info`, `net.ntp`, the shared ABI import, and the
six `wago_net_ntp` imports. Registering only mDNS exposes `net.info`, `net.mdns`, the shared ABI import, and
ten `wago_net_mdns` imports. Registering only DHCPv4 exposes `net.info`,
`net.dhcpv4`, the shared ABI import, and seven `wago_net_dhcpv4` imports.
Registering only IPv4 link-local exposes `net.info`, `net.linklocal4`, the shared
ABI import, and seven `wago_net_linklocal4` imports. Registering only IPv6
exposes `net.info`, `net.ipv6`, the shared ABI import, and three
`wago_net_ipv6` imports; its zero deployment configuration is truthfully
disabled until explicit composition supplies static identity. Unregistered protocol
imports are absent and fail normal WebAssembly import resolution. The public TCP,
UDP, DNS, ICMPv4, NTP, mDNS, DHCPv4, link-local, and IPv6 facades each construct
an opaque descriptor, and all nine checked host tables live in protocol-specific
internal binding packages. The
root package no longer imports those public or binding packages. Dependency and
runtime-inspection fixtures cover no protocol and all 512 combinations of the
nine implemented protocols. Omitted public, binding, instance-operation, and fixed ABI
packages are rejected from each fixture's Go dependency graph. Shared checked
memory, endpoint/handle codecs, and poll layouts live in `internal/abi/core`;
TCP, UDP, DNS, ICMPv4, NTP, mDNS, DHCPv4, and link-local layouts live only in
`internal/abi/tcp`, `/udp`, `/dns`, `/icmpv4`, `/ntp`, `/mdns`, `/dhcpv4`,
`/linklocal4`, and `/ipv6`.
The dependency
matrix also rejects each omitted protocol's namespace facet and
`internal/backend/lneto/{tcp,udp,dns,icmpv4,ntp,mdns,dhcpv4,linklocal4,ipv6}`
adapter, and rejects the temporary
aggregate lneto assembler from every selective production graph. One
protocol-neutral instance core still owns exact attachment, resource identity,
readiness, quotas, polling, and teardown, while
`internal/instance/tcp`, `internal/instance/udp`, `internal/instance/dns`, and
`internal/instance/icmpv4`, `internal/instance/ntp`, and
`internal/instance/mdns`, `internal/instance/dhcpv4`, and
`internal/instance/linklocal4` and `internal/instance/ipv6` serialize their
operations through that core.
Namespace ownership is likewise split: `internal/namespace/core` owns shared
endpoint, failure, readiness, resource, and bounded-service contracts, while
`/tcp`, `/udp`, `/dns`, `/icmpv4`, `/ntp`, `/mdns`, `/dhcpv4`, `/linklocal4`,
and `/ipv6` own
narrow protocol facets and values. Production graphs no longer reach the former
aggregate namespace compatibility package. `internal/backend/lneto/core` now
owns the single lifecycle lock, `StackAsync`, packet link, IPv4 identity, frame
scratch, bounded ingress/egress scheduler, participant ordering, maintenance
charging, shared UDP-port leases, and deterministic close. TCP listeners and
streams, UDP sockets and queues, DNS query/wire state, ICMPv4 echo state, NTP
synchronization state, and mDNS query/response/announcement state now live
independently in `internal/backend/lneto/tcp`, `/udp`, `/dns`, `/icmpv4`, `/ntp`,
`/mdns`, `/dhcpv4`, `/linklocal4`, and `/ipv6`. Focused tests preserve immediate
operations, shared UDP/DNS/NTP/mDNS/DHCPv4 port ownership, exact
DHCPv4/link-local identity contention, bounded ARP claim/defense, packet and
maintenance accounting, response filtering, quotas, and ordered cleanup. Protocol descriptors
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
// or github.com/wago-org/net/ipv6/register      // extension key: net-ipv6
```

The root package remains the explicit all-protocol bundle:

```go
import _ "github.com/wago-org/net/register" // extension key: net
```

The granular packages install protocol defaults but do not invent deployment
IPv4 or IPv6 identity/link configuration; DNS resolver storage also remains disabled in
the zero-configuration self-registering form. Applications needing those values
should use explicit `wagonet.New` composition. Likewise, low-level `InfoImports`
and `Imports(Config{})` stay limited to the stateless core ABI-version surface
rather than attempting to expose configured protocol resources without exact
instance ownership.

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

Capture the complete runtime microbenchmark suite and allocation baseline with:

```sh
scripts/benchmark-baseline.sh
```

See [`benchmarks/README.md`](benchmarks/README.md) for scope, sampling controls,
and comparison guidance. The checked-in baseline currently summarizes 114
benchmark cases across guest ABI, ownership/accounting, polling, packet queues,
and the lneto UDP, TCP, and DNS data paths.

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

The current Wago review now ends at integrated subject
`d556b20ff8667a8ae17b1ca399c74a949ac78f2f` on exact upstream `origin/main`
`ff04a6b1093628e025e3c2f78aa6ba6184e78bcb`. That upstream movement passes
through benchmark-only commit `bbaa494e` to authoritative lifecycle commit
`1a912c69` and changes no `src/wago` file. Patch-equivalent preview-1 fix
`16163fb8` follows upstream, `59ce1c13` preserves managed worker table callbacks
by directly invoking local wrapper descriptors, and `d556b20f` bounds forced
synchronous host callbacks to their declared parameter/result slots. Pack-only
reconstruction validates aggregate plus granular registration, exact
direct/managed/external-worker cleanup, standard Go, race, vet, and TinyGo on
that exact line, and the moving-ref gate fails closed on later drift. The strict
local release gate still uses an exact clean production-Wago
worktree, so a separate user-owned dirty audit checkout is neither cleaned nor
used for compilation. The retained production WASI exception is an exact
four-pass/four-fault subtest matrix, not a broad crash grep. Production-derived
fix review `5c7f76dba0aa82ca94a1dd644318ed062b03f7cc` and the current integrated line
both pass their complete matching WASI suites; current WASI `cbdb9b32` supplies
the capability-registration adaptation required by current Wago. Production
activation remains blocked by absent native/QEMU arm64 execution, unpublished
current/production subjects, and publication and adoption of an exact fixed
production Wago input before the two production WASI exceptions can be removed.

See [`docs/release-signoff.md`](docs/release-signoff.md) for the exact matrix,
pinned revisions, CI tiers, strict evidence, and fixed-review status, and
[`docs/wasi-upstream-preview1-audit.md`](docs/wasi-upstream-preview1-audit.md)
for the minimized root cause and fail-closed exception contract. Long-running
implementation work follows `.pi/skills/recursive-handoff/SKILL.md` and the
durable state in `agent-todo.md`.

## License

Apache-2.0.
