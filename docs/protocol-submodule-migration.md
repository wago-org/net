# Protocol submodule migration

Status: approved implementation plan. Stage 1 composition scaffolding is now
implemented: `net.New` creates an empty shared network, protocol descriptors are
recorded through an implementation-neutral `internal/plugin` registry, Wago
registration freezes selection, and exact none/single/pair/all inspection tests
cover capabilities, imports, duplicate selection, freeze behavior, and ordinary
unregistered-import failure. Public `tcp.Register(network, ...Option)`,
`udp.Register(network, ...Option)`, and `dns.Register(network, ...Option)`
facades now construct their exact opaque protocol descriptors directly. The
eleven checked TCP bindings, six checked UDP bindings, and six checked DNS
bindings live in protocol-specific `internal/binding` packages, reached through
a protocol-neutral exact-instance host bridge and shared guest status/poll
helpers. Protocol-local tests prove each single registration's exact
capability/import surface, unresolved imports for both omitted protocols,
duplicate/freeze behavior, and direct host calls against the root-owned exact
instance. An external public-API matrix covers none, each single protocol, every
pair, and all three. Aggregate construction now lives in explicit
`compat.Init(Config)`, and the root production package no longer imports any
public protocol or protocol binding package. The former root `Init` symbol was
removed because source compatibility could not override that dependency
boundary; same-package regression tests use test-only aggregate helpers. Runtime
and Go dependency fixtures cover none, every single protocol, every pair, and
all three, rejecting omitted public, binding, and instance-operation packages.
`internal/instance/core` now owns only exact attachment, shared resources,
readiness, quotas, polling, and teardown; TCP, UDP, and DNS operations live in
independently selected `internal/instance/{tcp,udp,dns}` packages and run under
the core lifecycle mutex. ABI ownership is also split: `internal/abi/core` owns
checked memory, address/endpoint, handle, and poll codecs, while
`internal/abi/{tcp,udp,dns}` own only their fixed protocol layouts. Dependency
fixtures reject every omitted protocol ABI package. Namespace ownership is now
split too: `internal/namespace/core` owns shared endpoint/failure/readiness/
resource/service contracts, and `internal/namespace/{tcp,udp,dns}` own narrow
protocol facets and values. Production code no longer imports the former
aggregate compatibility package, and non-TCP graphs reject the TCP facet.
`internal/backend/lneto/core` now owns the single stack, link, lifecycle lock,
shared IPv4 state, bounded participant scheduler, maintenance charging, error
mapping, shared UDP-port leases, and deterministic close. TCP listener/stream,
UDP socket/queue, and DNS query/wire state are extracted into
`internal/backend/lneto/{tcp,udp,dns}` over that same core. Protocol descriptors
now carry opaque lneto contributions; registration freeze precedes manager
construction, and each exact instance transactionally creates one core, installs
only selected adapters, and publishes an immutable neutral service composition.
Root construction imports no aggregate or protocol adapter package. Dependency
fixtures require selected adapters/facets and reject every omitted adapter/facet
plus the aggregate assembler. Protocol-local finite TCP/UDP/DNS defaults compose
through one copied immutable policy input with caller denies retaining
precedence. Listener/server and special-address grants, raw policy additions,
default suppression, exact storage overrides, and conspicuous `AllowAll` remain
explicit. Granular `tcp/register`, `udp/register`, and `dns/register` packages
compile only their protocol, while root `register` is the explicit all-protocol
bundle. Standard workspace and `GOWORK=off` tests, race, vet, TinyGo,
source-boundary, exact direct/register dependency fixtures, and repeated focused
policy/default/core tests pass for this stage. Practical fuzz, benchmarks,
cross-build/arm64 execution, external reconstruction, and the final heavyweight
release matrix remain.

## Goal

Make TCP, UDP, and DNS independently selectable at both registration time and
Go compile time while preserving one shared per-instance networking ownership
root. A TCP-only client must neither expose nor compile the UDP or DNS plugin
modules.

The default API should support ordinary client networking without requiring raw
policy or quota construction, while advanced callers retain exact control.

## Completion criteria

1. The root `github.com/wago-org/net` package imports no public or backend
   protocol package.
2. Public `tcp`, `udp`, and `dns` packages are separate Go compilation units and
   provide `Register(network, ...Option)` entry points.
3. Registering a protocol provides only its capability and Wasm import module,
   plus the shared `wago_net.abi_version` core import. Unregistered protocols are
   absent from Wago inspection and fail ordinary Wasm import resolution.
4. A TCP-only dependency graph contains no plugin UDP/DNS public, binding,
   instance-operation, or lneto-adapter package. Equivalent isolation holds for
   UDP-only and DNS-only clients.
5. Shared lifecycle hooks, exact caller identity, resource-table identity,
   policy composition, quotas, readiness, namespace ownership, reset safety, and
   deterministic cleanup are installed exactly once per composed network.
6. Protocol defaults are finite and useful for ordinary clients. TCP permits
   bounded outbound connections by default but not listeners; UDP permits
   bounded outbound unicast, ephemeral wildcard bind, and replies but not
   privileged bind, multicast, broadcast, or broad server authority; DNS permits
   bounded A/AAAA queries through an explicit or inherited resolver.
7. Raw policy, limits, buffers, listener/server grants, special address classes,
   and conspicuous `AllowAll` options remain available.
8. Granular `tcp/register`, `udp/register`, and `dns/register` packages compile
   only their protocol. The root `register` package remains an explicit
   all-protocol compatibility bundle.
9. Existing ABI signatures, numeric statuses, fixed layouts, handle safety, and
   lifecycle guarantees remain unchanged.
10. Existing `Init(Config)` callers have a documented compatibility path during
    migration, and the new selective API is the primary README path.

## Target public API

```go
import (
    wagonet "github.com/wago-org/net"
    "github.com/wago-org/net/tcp"
)

network := wagonet.New(
    wagonet.StaticIPv4(/* deployment identity and link options */),
)
if err := tcp.Register(network); err != nil {
    return err
}
return runtime.Use(network)
```

Composition remains explicit:

```go
network := wagonet.New(/* shared namespace options */)
_ = udp.Register(network)
_ = tcp.Register(network)
_ = dns.Register(network, dns.Resolver("192.0.2.53"))
return runtime.Use(network)
```

The root package must not import child protocols. Child packages register opaque
module implementations into the shared builder. Registration is rejected after
the builder is frozen by Wago registration, and duplicate protocol registration
is either idempotent or returns a stable configuration error.

## Target package graph

```text
net                                  public shared builder and lifecycle API
compat                               explicit aggregate Config compatibility
internal/plugin                     shared module composition and freeze state
internal/instance/core              attachment map and common ownership state
internal/namespace/core             endpoint, progress, service and base namespace
internal/backend/lneto/core         stack, packet link and bounded common service

udp                                  public UDP defaults/options/registration
internal/abi/udp                    UDP-only fixed layouts
internal/instance/udp               UDP resource operations
internal/namespace/udp              UDP contracts
internal/backend/lneto/udp          UDP adapter

tcp                                  public TCP defaults/options/registration
internal/abi/tcp                    TCP-only fixed layouts
internal/instance/tcp               TCP resource operations
internal/namespace/tcp              TCP contracts
internal/backend/lneto/tcp          TCP adapter

dns                                  public DNS defaults/options/registration
internal/abi/dns                    DNS-only fixed layouts
internal/instance/dns               DNS resource operations
internal/namespace/dns              DNS contracts
internal/backend/lneto/dns          DNS adapter
```

Directory names may be adjusted while implementing, but package dependency
isolation is mandatory. Shared packages may define neutral interfaces and common
layouts; they must not import protocol implementations.

## Current coupling inventory

The root binding and backend-adapter edges are removed: production `net`
imports no public protocol, `internal/binding/{tcp,udp,dns}`, aggregate lneto
assembler, or protocol lneto adapter package. Aggregate callers move to
`compat.Init`. Stage 4 compile isolation now has these properties:

- `net.go` imports only `internal/backend/lneto/core`, freezes the immutable
  module snapshot before manager construction, and invokes opaque selected
  contributions during exact-instance namespace assembly.
- `internal/backend/lneto/core` now owns only the shared lock, stack, link,
  addressing, scratch, bounded scheduler, participant ordering, maintenance
  epoch, error mapping, and close. It imports no protocol adapter.
- `internal/backend/lneto/tcp` owns TCP listener/stream pools, fixed buffers,
  port allocation, immediate operations, and accepted-slot maintenance.
- `internal/backend/lneto/udp` owns UDP socket state, bounded queues, frame
  codecs, readiness, policy/quota checks, and service participation.
- `internal/backend/lneto/dns` owns DNS query state, wire codecs, retries,
  response filtering, readiness, policy/quota checks, and service participation.
  The temporary aggregate assembler still imports all three only for historical
  focused tests; production fixtures reject it.
- `internal/backend/lneto/core` provides the one UDP-port lease domain shared by
  explicit UDP binds and DNS ephemeral source ports, preserving collisions and
  deterministic release without owning protocol payload or record types.
- `internal/instance/core` is now protocol-neutral, while
  `internal/instance/{tcp,udp,dns}` contain independently selected operations;
  all use one core lifecycle lock, resource table, readiness coordinator, quota
  account, and deterministic close path.
- `internal/namespace/core` now contains only shared endpoint, progress, stream
  I/O, readiness, resource, service, semantic-failure, and immutable keyed
  service-composition declarations;
  `internal/namespace/{tcp,udp,dns}` own narrow protocol facets and values. The
  old aggregate package is compatibility aliases only and is absent from
  production fixture graphs. The extracted UDP and DNS adapters import their
  exact facets, while the TCP adapter is implemented structurally without
  importing its facet.
- `internal/abi/core` now contains only checked memory, address/endpoint, handle,
  and poll layouts; protocol codecs are isolated in `internal/abi/tcp`, `/udp`,
  and `/dns` and are gated from omitted fixture graphs.
- `register/register.go` intentionally constructs the aggregate extension.

Exact runtime registration, protocol implementation compile isolation, finite
client defaults, policy composition, and granular register packages are
implemented. Complete heavyweight release signoff remains.

## Migration sequence

### Stage 1: composition and exact registration

Introduce a root network builder and an opaque module registration mechanism.
The builder owns shared immutable configuration and the instance manager. Module
registration records capabilities and binding installers without importing child
packages. Freeze the builder during Wago `Register`.

Add exact inspection tests for no protocol, TCP-only, UDP-only, DNS-only, pairs,
and all three. Do not yet claim compile isolation if compatibility shims still
reside in the root package.

### Stage 2: move public bindings and configuration

Create `tcp`, `udp`, and `dns` public packages. Move protocol binding tables,
host functions, protocol ABI constants, configuration, options, defaults, and
registration facades out of package `net`. Keep aliases or forwarding helpers
only where required for a bounded compatibility period.

The root `Config` compatibility path must not force new selective clients to
import all protocol packages. This boundary now uses documented
`compat.Init(Config)`, which explicitly composes all three public registrations;
the root `Init` symbol was removed rather than preserving a production dependency
edge. Root same-package regression tests retain test-only aggregate helpers while
the underlying operation packages are split.

### Stage 3: split instance and neutral contracts

Reduce the common instance manager to attachment lookup, shared resource table,
quota/readiness/policy access, namespace handle ownership, polling primitives,
and close. Move protocol resource operations into protocol packages that operate
through narrow common services.

Split protocol-specific namespace interfaces and ABI codecs so importing common
state does not compile every protocol operation. This stage is complete: status
values and genuinely shared checked-memory, address/endpoint, handle, poll,
namespace ownership, readiness, resource, service, and failure contracts remain
in core packages, while each protocol owns its fixed codecs plus narrow namespace
facets and values. Exact omitted UDP/DNS namespace-graph rejection now waits on
selective adapter contributions rather than on adapter extraction itself.

### Stage 4: split the lneto adapter

Extract the common lneto stack, packet link, addressing, shared UDP-port lease
domain, and bounded service scheduler. The common core and all three TCP, UDP,
and DNS adapters are implemented. Root aggregate construction has been replaced
with opaque selective adapter contributions, and manager/namespace factory
assembly is delayed until protocol registration freezes.

The common scheduler calls installed protocol service participants through a
bounded protocol-neutral contract. Focused tests preserve participant ordering,
packet/byte/operation accounting, charged TCP accepted-slot maintenance, one
stack/link owner, and deterministic close. Exact fixture rejection of omitted
adapters waits on removal of the aggregate root assembler.

### Stage 5: defaults and policy composition

Implemented. Package-local finite defaults and ergonomic policy options compose
module grants into one immutable policy before the first instance is created.
Deny rules continue to win. Special endpoint classes and server/listener
operations remain explicit. Client-flow tests cover TCP outbound, UDP ephemeral
unicast/replies, and resolver-backed DNS while denying caller-blocked and broader
authority by default.

### Stage 6: granular packaging and compatibility

Implemented. `tcp/register`, `udp/register`, and `dns/register` self-register
only their protocol. Root `register` explicitly composes all three protocols in
one shared extension. Dependency fixtures reject omitted protocol units from
each granular graph, while the runtime matrix reports exact imports and
capabilities for every direct selective combination.

Update README examples to lead with submodule registration and retain an
advanced compatibility section for raw configuration.

### Stage 7: dependency-boundary and release gates

Small root, TCP-only, UDP-only, DNS-only, pair, and aggregate fixtures now gate
exact runtime capability/import sets under standard Go and TinyGo. Their
standard-Go `go list -deps` gate rejects every omitted public protocol and
binding package plus accidental aggregate-package dependencies. The fixtures
require `internal/instance/core`, `internal/abi/core`,
`internal/namespace/core`, and `internal/backend/lneto/core` in every graph.
They require only selected `internal/instance/{tcp,udp,dns}` operations,
`internal/abi/{tcp,udp,dns}` codecs, `internal/namespace/{tcp,udp,dns}` facets,
and `internal/backend/lneto/{tcp,udp,dns}` adapters. Every omitted protocol unit
is rejected, as are the former aggregate namespace package and aggregate lneto
assembler.

Run the complete standard, race, vet, fuzz, benchmark, TinyGo, cross-build,
worker/lifecycle, source-boundary, and release-signoff matrices before declaring
completion.

## Exact registration matrix

The current ABI contains one core, six UDP, eleven TCP, and six DNS imports.
Expected selected surfaces are:

| Selection | Import count | Capabilities |
|---|---:|---|
| TCP | 12 | `net.info`, `net.tcp` |
| UDP | 7 | `net.info`, `net.udp` |
| DNS | 7 | `net.info`, `net.dns` |
| TCP + UDP | 18 | `net.info`, `net.tcp`, `net.udp` |
| TCP + DNS | 18 | `net.info`, `net.tcp`, `net.dns` |
| UDP + DNS | 13 | `net.info`, `net.udp`, `net.dns` |
| TCP + UDP + DNS | 24 | all four |

An empty builder should either register zero imports or return a clear
configuration error. It must not silently advertise all protocols.

## Risks

- The current concrete lneto namespace interleaves protocol service scheduling;
  splitting it must preserve deterministic fairness and every independent bound.
- The shared resource table uses protocol kinds. Common code may retain stable
  opaque kind identifiers, but must not import protocol implementations.
- Default allow behavior changes the current deny-all configuration experience.
  Defaults must be documented as client-oriented grants rather than unrestricted
  network authority.
- Source compatibility cannot take precedence over root dependency isolation.
  If legacy `Init(Config)` necessarily imports all implementations, it belongs in
  an explicit aggregate compatibility package.
- Go package isolation prevents plugin protocol packages from compiling, but a
  unified third-party lneto package may still compile its own internal transport
  support. Dependency tests should distinguish plugin isolation from upstream
  implementation details while rejecting plugin UDP/DNS adapters in TCP-only
  builds.
