# Architecture

## Boundary

The public contract is a backend-neutral resource ABI:

```text
WebAssembly guest
  -> Wago host imports
  -> per-instance networking resources
  -> backend-neutral namespace interfaces
  -> lneto backend
  -> deterministic or physical link
```

Guest code will not import lneto-specific Go types. A later host-socket or test
backend must be able to implement the same guest ABI.

## Import namespace decision

Wago assigns one extension owner to an entire import module. Two extensions cannot
independently add functions to the same module under the default collision policy.
The suite therefore uses **protocol import modules**:

- `wago_net` for shared core operations;
- `wago_net_udp` for UDP;
- `wago_net_tcp` for TCP;
- `wago_net_dns` for DNS;
- additional modules only when their implementations exist.

This permits narrow per-protocol capabilities and independent ABI evolution
without multiple owners competing for `wago_net`. The current root extension is
the explicit provider for shared per-instance state across its core and complete
protocol modules; no process-global state or placeholder protocol module is used.

## Current implementation

The root extension owns four distinct import modules: `wago_net` declares
`net.info` and exposes `abi_version`; `wago_net_udp` declares narrow `net.udp`
authority; `wago_net_tcp` declares narrow `net.tcp` authority; and
`wago_net_dns` declares narrow `net.dns` authority. UDP, TCP, and DNS each expose
complete configured-namespace discovery, protocol operations, kind-safe close,
and independently capability-gated bounded poll. The low-level `Imports` bundle
remains core-only because protocol resources require Runtime lifecycle identity.
Registration and implementation share complete binding tables so inspection
metadata, TinyGo-compatible slot shapes, and actual host functions do not drift.
`internal/abi` provides allocation-free checked ranges, fixed-width endpoint,
UDP receive, TCP stream/I/O, inline DNS query/name/record layouts, disjoint
multi-output validation, and bounded poll codecs without exposing lneto types.
`internal/resource` provides O(1) opaque-handle lookup with exact kind checks,
never-reused table identities, per-slot generations, rollover retirement, and
reverse-creation O(live) cleanup. The table exists independently of protocol
resources so its stale, forged, wrong-kind, reuse, and cross-table behavior can
be hardened before sockets are exposed.

`internal/policy` compiles immutable allow/deny rules over transport, direction,
IP prefixes, port ranges, and normalized DNS suffixes. Deny matches always win,
invalid and unmatched requests fail closed, and separate zero-default gates are
required for wildcard binds, loopback, multicast, limited broadcast, and local
bind/listen ports below 1024. IPv4-mapped IPv6 values are rejected rather than
normalized across policy families. Authority-changing operations have explicit
UDP bind/send, TCP listen/connect, and DNS resolve checks. Selected protocol
modules contribute deep-copied grant sets through an opaque shared contract after
registration freezes and before manager construction. Caller policy is copied
first, grants compose monotonically, and one compile step preserves deny-wins
semantics independent of module order. TCP contributes finite outbound-client
authority only; UDP contributes only ephemeral wildcard client bind plus ordinary
outbound unicast/replies; DNS contributes valid-name query authority and becomes
usable only with an explicit finite resolver configuration. Listener/server,
privileged bind, loopback, multicast, broadcast, raw additions, suppression of
default authority, and conspicuous `AllowAll` grants remain protocol-local
options. Special-class grants are compiled per transport, so a TCP option cannot
widen UDP authority or vice versa. Port-zero UDP binds authorize allocation only;
the final concrete ephemeral endpoint is checked against special-class gates and
deny rules without becoming general explicit-port authority. None of these
options creates a second policy or quota domain.

`internal/quota` provides finite per-instance total/protocol resource, queued-byte,
DNS-work, and service-work counters. Tentative reservations must be committed or
rolled back; committed allocations release exactly once. Guest poll uses a
scoped service charge that preserves the same finite concurrent limit and panic
cleanup without allocating retained reservation/allocation tokens. Closing an
instance first closes resources and then closes its quota account, which clears
abandoned reservations and makes late token cleanup harmless.

`internal/namespace/core` defines the backend-neutral endpoint, progress,
stream-I/O, readiness, semantic-error, resource, namespace ownership, and bounded
manual-service contracts. `internal/namespace/tcp`, `/udp`, and `/dns` define
only their narrow creation/resource facets and protocol-local values. Operations
that may await network progress remain single `Try` calls with explicit
would-block or in-progress results. Focused fake backends exercise each contract
without importing lneto; no lneto type is part of these layers. The exact
instance manager stores one quota-owned core namespace resource and protocol
operation packages recover their selected facet through an immutable,
protocol-neutral keyed service composition. The composition imports no protocol
facet itself and retains one protocol-neutral base namespace for trusted link and
service integration. This preserves one namespace handle, one lifecycle lock,
one readiness/service owner, and one teardown path without forcing omitted
protocol facets into the dependency graph.

`internal/packetlink` owns fixed ingress and egress frame slots. Enqueue copies
caller data, dequeue has explicit truncation and byte-budget rollback semantics,
and backend fills commit atomically only after successful immediate production.
Queue-full and oversized failures retain no caller slices, and close clears all
retained bytes synchronously.

`internal/backend/lneto/core` owns one lifecycle lock, `xnet.StackAsync`, packet
link, IPv4 identity, frame scratch buffer, and bounded service scheduler per
namespace. Protocol-neutral participants contribute ordered ingress, egress,
maintenance, and close callbacks; the core preserves DNS-before-UDP ingress,
rotating DNS/UDP/stack egress priority, charged zero-frame TCP maintenance, and
DNS/TCP/UDP teardown order without importing a protocol adapter. Only immediate
Ethernet ingress and egress calls enter bounded manual service; no lneto
blocking, deadline, goroutine, or backoff wrapper is used. Service alternates
directions under independent packet, byte, and operation bounds and maps backend
errors to semantic namespace failures. Opaque protocol descriptors configure
and install only their exact adapter after registration freezes. The root creates
one common core per exact instance, installs every selected contribution before
namespace publication, and closes that core transactionally on any failure. The
temporary aggregate `internal/backend/lneto` assembler remains only for focused
historical backend tests and is rejected from production dependency fixtures.
`internal/backend/lneto/udp` owns fixed datagram
queues and lneto's immediate Ethernet/IPv4/UDP frame codecs. This design is
deliberate: lneto's high-level UDP wrappers back off, while its exported
immediate mux cannot represent an empty payload. The adapter preserves empty and
truncated datagrams, validates checksums and fragmentation, enforces policy on
bind and every send, reserves exact finite resource/retained-storage quota,
rotates egress deterministically, and clears all queue bytes on close.
`internal/backend/lneto/tcp` independently owns TCP
listener/stream pools, ports, and fixed buffers over the same core lock and stack.
It uses only immediate `tcp.Handler` buffer/state primitives and never calls
`tcp.Conn`'s backoff-based `Read`, `Write`, or `Flush` wrappers. Fixed listener
pools and
outbound streams have bounded receive/transmit storage, partial I/O, connect and
accept progress, half-close, level readiness, endpoint policy, quota ownership,
port reuse, and deterministic abort cleanup. Adapter creation seeds only a
small stream-registry capacity hint and grows that registry as streams are
actually created rather than preallocating for the full theoretical
`MaxOutboundStreams + MaxListeners*AcceptBacklog` population. Closing an
accepted stream releases its resource quota immediately. lneto retains the
closed pool entry until its listener performs maintenance; the next bounded
egress service probe reclaims that entry and now reports one charged service
operation even when no frame is
emitted. This preserves lneto's private accepted-list bookkeeping without unsafe
direct slot reuse, while making the finite maintenance cost and reuse point
observable. `internal/backend/lneto/dns` owns immediate IPv4 UDP queries plus
lneto DNS codecs, finite query/record/response bounds,
policy and quota ownership, deterministic service-attempt retransmission and
timeout, semantic RCode mapping, and copied A/AAAA/CNAME records. Each query has
an active transport phase (UDP source-port lease, `byPort` dispatch entry, retry
state) and a guest-visible terminal phase (handle, retained records or failure,
quota until close). Successful completion, timeout, cancellation, parser
failure, and other terminal failures retire the transport phase before the query
publishes its terminal result, so late packets cannot mutate committed records.
Responses must echo the exact requested names/classes/types. Only a unique CNAME
chain reachable from the requested name and requested A/AAAA records at its
terminal name are emitted; irrelevant and duplicate answers are ignored, while
conflicts and loops fail closed. Compressed names and resource framing have
 direct fuzz coverage. Truncated UDP responses map to temporary failure because
DNS-over-TCP fallback is not implemented. `MaxQueries` still limits live guest
query handles until close even after terminal transport retirement. UDP sockets
and DNS queries reserve local ports through one protocol-neutral core lease
domain, preserving exact collision, release, deterministic allocation, and close
behavior without moving datagrams or DNS records into core. Root namespace
construction imports only the shared lneto core. Root, single-protocol, pair,
and all-protocol dependency fixtures require exactly the selected
adapters/facets and reject every omitted one plus the aggregate assembler,
completing the Stage 4 compile-isolation boundary.
Granular `tcp/register`, `udp/register`, and `dns/register` packages now own only
their selected public facade and exact implementation graph. The root `register`
package explicitly composes all three protocols in one extension rather than
using the aggregate compatibility constructor.

`internal/readiness` attaches a finite coordinator to each instance resource
table. Registrations retain opaque handle plus exact kind, level-triggered polls
scan at most one bounded pass, output only caller-budgeted events, and make only
bounded namespace service attempts. Stale generation handles are removed during
the bounded scan; polling never sleeps. The guest `poll` import validates the
complete event capacity and result range before work, uses per-instance scratch
storage, and transactionally accounts `scans + events + service_attempts` against
finite service-work quota for the duration of each call. The scoped accounting
path eliminates quota-token allocations; pointer-backed host-module benchmarks
now measure the complete UDP and TCP guest poll calls at zero allocations rather
than including a value-to-interface boxing artifact.

Each `Extension` owns one private instance-state manager shared by its core, UDP,
TCP, and DNS module bindings. Runtime instantiation attaches one resource table,
readiness coordinator, immutable policy, and finite quota ledger to the exact
`*wago.Instance`. Optional static
IPv4 configuration transactionally reserves namespace quota, constructs the
backend, inserts a generation-safe handle, and registers bounded readiness before
the state is published. UDP, TCP, and DNS creation repeat that transaction for
exact socket, listener, stream, or query handles and poll registration; every
failed stage closes the backend resource and releases accounting. DNS handles
support copied record iteration, explicit cancellation, backend service-attempt
timeout, stale/wrong-kind/cross-instance rejection, and deterministic lifecycle
close. DNS host bindings prevalidate complete fixed query, handle, record, event,
and poll outputs; record encoding is atomic and AGAIN/EOF/error paths do not
mutate output. TCP guest bindings prevalidate all complete
endpoint, descriptor, payload, result, event, and poll ranges before backend
work. Connect and accept roll back newly owned handles if descriptor encoding
cannot complete; AGAIN and EOF stream results leave guest outputs unchanged.
Host imports recover exact identity through the additive
`wago.InstanceHostModule` interface, and `BeforeClose` removes the attachment
before polling shutdown, reverse-creation resource cleanup, and quota shutdown.
The extension also calls `Registry.RequireReinstantiation`, so class resets that
would reuse a physical instance are engine-downgraded to the same deterministic
close-and-recreate path. Failed later setup and class replacement use that close
path as well. No process-global instance map is used. The low-level `Imports` bundle remains
suitable only for stateless core imports such as `abi_version`; resource-owning
protocol extensions require the Runtime lifecycle path.

The companion Wago branch `net/instance-close-hooks` now merges both prerequisite
histories at `97e6f91`: its first parent preserves lifecycle/reset/identity work
through `54499ba`, while its second parent preserves the divergent worker plugin
history at `ffd5ef4b`. Runtime instance metadata carries origin, GC inheritance,
and an optional expiring worker host-call scope outside `Instance`, so the
776-byte instance layout and TinyGo-compatible `HostFunc` shape remain unchanged.
Worker registration is transactional, workers retain finite runtime/queue quotas,
linked parent close waits for child disposal, hook panics cannot skip network
cleanup, and direct or worker host calls still expose exact instance identity.

## Pool reset enforcement

The networking extension declares `Registry.RequireReinstantiation`. A class may
still request `wago.ResetMemorySnapshot`, but `Class.ResetPolicy` reports and
`Lease.Release` enforces `wago.ResetReinstantiate` while networking is registered.
The old physical instance is closed before its fresh replacement is published;
old UDP/TCP/DNS handles become closed in the retired state and fail as
cross-table handles in the new state. Tests rebind UDP/TCP resources on fresh
leases and exercise linked workers whose child instances own all three protocol
kinds. Parent release waits for worker disposal, reverse hooks observe state
before networking detaches it, an isolated hook panic cannot prevent cleanup,
failed callback validation retires the child's state and releases worker quota,
and the next lease receives fresh parent and worker identities.

## Release gate

`scripts/release-signoff.sh` is the single reproducible local/CI entry point. It
pins the merged Wago branch and the lneto/WASI audits, runs standard Go, race,
bounded fuzz, benchmarks, TinyGo, a distinct package cross-build, optional
bounded native/QEMU arm64 execution, custom CLI inspection, source-boundary and
plugin-plan compatibility and reviewed-upstream WASI audits, companion
repository tests, and final clean checks. It then exports deterministic non-thin
Git packs containing the exact plugin subject and pinned Wago/lneto/WASI commit
and source-tree objects, including both ordered Wago parents, before emitting a
timestamp-free deterministic provenance manifest with exact revisions/trees/
toolchains, named check outcomes, inspection facts, accepted exceptions,
truthful skipped-execution limitations, and sorted SHA-256 evidence. A standalone
semantic verifier rejects policy, evidence, pack inventory, tree, or parent-order
drift without rerunning the gate, and a normalized deterministic tar.gz exports
only the verified review set. These packs remove moving-ref dependence for source
review but do not establish publisher authenticity or claim upstream publication.
Exact inputs, CI tiers, artifacts, bundle verification, and the narrowly accepted
known WASI preview-1 native SIGSEGV are documented in
`docs/release-signoff.md`. Hosted CI
remains blocked until the merged Wago prerequisite is published at a fetchable
immutable ref; the reviewed newer plugin-plan snapshot requires a separate
identity/cleanup/worker migration and is not a substitute pin.
