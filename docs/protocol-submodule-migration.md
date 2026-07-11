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
all three, rejecting omitted public and binding packages while recording the
still-unified instance and lneto backend as blockers. Unified instance
operations and the lneto adapter, protocol-local finite defaults, and granular
register packages remain unsplit; full compile-time isolation is therefore not
yet claimed. Standard, race, vet, and TinyGo suites pass after the compatibility
extraction and dependency gates.

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

The root binding edge is now removed: production `net` imports no public
protocol or `internal/binding/{tcp,udp,dns}` package, and aggregate callers move
to `compat.Init`. Full compile isolation is still blocked for these reasons:

- `net.go` imports `internal/backend/lneto`, whose single package contains
  `namespace.go`, `udp.go`, `tcp.go`, and `dns.go`.
- `internal/backend/lneto.Namespace` stores all protocol configuration and live
  collections in one concrete struct.
- `internal/instance/manager.go` combines common attachment lifecycle with
  UDP/TCP/DNS creation and operation methods.
- `internal/namespace` and `internal/abi` combine common and protocol-specific
  declarations in single packages.
- `register/register.go` always constructs the aggregate extension.

Exact runtime registration is implemented, but these remaining package edges
still prevent compile-time isolation.

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
state does not compile every protocol operation. Keep status values and genuinely
shared address/poll layouts in common packages.

### Stage 4: split the lneto adapter

Extract the common lneto stack, packet link, addressing, and bounded service
scheduler. Move UDP socket state/codecs, TCP listener/stream state, and DNS query
state/codecs into separate adapter packages.

The common scheduler may call installed protocol service participants through a
bounded interface. Participant ordering, packet/byte/operation accounting, and
existing deterministic behavior must remain explicit and tested.

### Stage 5: defaults and policy composition

Add package-local finite defaults and ergonomic policy options. Compose module
policy grants into one immutable policy before the first instance is created.
Deny rules continue to win. Special endpoint classes and server/listener
operations remain explicit. Add tests proving defaults permit their documented
client flows and deny privileged or broader authority.

### Stage 6: granular packaging and compatibility

Add `tcp/register`, `udp/register`, and `dns/register`. Convert root `register`
into an explicit aggregate bundle. Update the manifest/build inspection paths so
selected package builds report exact imports and capabilities.

Update README examples to lead with submodule registration and retain an
advanced compatibility section for raw configuration.

### Stage 7: dependency-boundary and release gates

Small root, TCP-only, UDP-only, DNS-only, pair, and aggregate fixtures now gate
exact runtime capability/import sets under standard Go and TinyGo. Their
standard-Go `go list -deps` gate rejects every omitted public protocol and
binding package plus accidental aggregate-package dependencies. The fixtures
currently assert the unified `internal/instance` and `internal/backend/lneto`
packages remain present so the next split cannot be mistaken for completed
isolation. Extend the same gate to protocol-specific instance-operation and
lneto-adapter packages as those packages are extracted.

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
