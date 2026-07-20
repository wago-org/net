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
- `wago_net_tcp` for raw TCP;
- `wago_net_tls` for outbound verified TLS client streams;
- `wago_net_dns` for DNS;
- `wago_net_icmpv4` for ICMPv4 echo;
- `wago_net_ntp` for explicit-clock NTP synchronization;
- `wago_net_mdns` for bounded multicast DNS queries, responses, and announcements;
- `wago_net_dhcpv4` for bounded DORA leases and explicitly configured finite server service;
- `wago_net_linklocal4` for bounded RFC 3927 claim-and-defend operations;
- `wago_net_ipv6` for configured IPv6 namespace introspection and service;
- `wago_net_icmpv6` for bounded echo and Neighbor Discovery;
- `wago_net_dhcpv6` for bounded initial DHCPv6 acquisition and copied configuration observations.

This permits narrow per-protocol capabilities and independent ABI evolution
without multiple owners competing for `wago_net`. The current root extension is
the explicit provider for shared per-instance state across its core and complete
protocol modules; no process-global state or placeholder protocol module is used.

## Current implementation

The selectable extension surface owns thirteen distinct import modules: `wago_net` declares
`net.info` and exposes `abi_version`; `wago_net_udp` declares narrow `net.udp`
authority; `wago_net_tcp` declares narrow `net.tcp` authority;
`wago_net_dns` declares narrow `net.dns` authority; `wago_net_icmpv4`
declares narrow `net.icmpv4` authority; `wago_net_ntp` declares narrow
`net.ntp` authority; `wago_net_mdns` declares narrow `net.mdns` authority;
`wago_net_dhcpv4` declares narrow `net.dhcpv4` authority;
`wago_net_linklocal4` declares narrow `net.linklocal4` authority;
`wago_net_ipv6` declares narrow `net.ipv6` authority; and `wago_net_icmpv6`
declares narrow `net.icmpv6` authority; and `wago_net_dhcpv6` declares narrow
`net.dhcpv6` authority; granular `wago_net_tls` declares distinct `net.tls`
authority. UDP, TCP, TLS, DNS, ICMPv4, NTP, mDNS, DHCPv4, IPv4
link-local, IPv6, ICMPv6, and DHCPv6 each expose complete configured-namespace discovery plus their truthful
operation or introspection surface and independently capability-gated bounded
poll. Resource-owning modules retain kind-safe close; IPv6 configuration owns no
separate guest resource. The explicit low-level
`InfoImports` bundle remains core-only because protocol resources require
Runtime lifecycle identity.
Registration and implementation share complete binding tables so inspection
metadata, TinyGo-compatible slot shapes, and actual host functions do not drift.
`internal/abi/core` provides allocation-free checked ranges, shared endpoint and
poll layouts, disjoint multi-output validation, and common handle/memory codecs
without exposing lneto types. `internal/abi/tcp`, `/udp`, `/dns`, `/icmpv4`,
`/ntp`, `/mdns`, `/dhcpv4`, `/linklocal4`, `/ipv6`, `/icmpv6`, and `/dhcpv6` hold only TCP stream/I/O,
UDP receive-result, inline DNS query/name/record, ICMPv4 echo, NTP sample, mDNS
query/record/announcement, DHCPv4 request/lease, link-local request/result,
IPv6 configuration, ICMPv6 echo/neighbor, and DHCPv6 configuration layouts, so omitted protocol ABI units stay out of selective
dependency graphs.
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
UDP bind/send, TCP listen/connect, TLS connect, and DNS resolve checks. TLS
allows are evaluated as TLS authority, while applicable TCP denies additionally
constrain the private byte transport without requiring any raw-TCP allow. Selected protocol
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

`internal/quota` provides finite per-instance total/protocol resource,
queued-byte, DNS-work, active-ICMPv4-work, active-NTP-work, active-mDNS-work,
active-DHCPv4-work, active-link-local-work, one configured IPv6 namespace resource, ICMPv6 resources, active ICMPv6 echo/resolution work, DHCPv6 resources and
active acquisition work, and service-work counters. Tentative reservations must be committed or
rolled back; committed allocations release exactly once. Guest poll uses a
scoped service charge that preserves the same finite concurrent limit and panic
cleanup without allocating retained reservation/allocation tokens. Closing an
instance first closes resources and then closes its quota account, which clears
abandoned reservations and makes late token cleanup harmless.

`internal/namespace/core` defines the backend-neutral endpoint, progress,
stream-I/O, readiness, semantic-error, resource, namespace ownership, and bounded
manual-service contracts. `internal/namespace/tcp`, `/udp`, `/dns`, `/icmpv4`, `/ntp`, `/mdns`,
`/dhcpv4`, `/linklocal4`, `/ipv6`, `/icmpv6`, and `/dhcpv6` define
only their narrow creation/resource or configuration facets and protocol-local values. NTP additionally
defines the explicit host clock contract; no ambient wall clock is available to
the adapter. Operations
that may await network progress remain single `Try` calls with explicit
would-block or in-progress results. Focused fake backends exercise each contract
without importing lneto; no lneto type is part of these layers. The exact
instance manager stores one quota-owned core namespace resource and protocol
operation packages recover their selected facet through an immutable,
protocol-neutral keyed service composition. The composition imports no protocol
facet itself and retains one protocol-neutral base namespace for trusted link and
service integration. The common UDP/TCP/DNS cases use inline service storage, so
shared composition avoids per-selected-protocol heap growth while preserving a
map-backed overflow path for future larger compositions. This preserves one
namespace handle, one lifecycle lock, one readiness/service owner, and one
teardown path without forcing omitted protocol facets into the dependency graph.
Namespace, base, and service resolution fails closed on typed-nil direct values,
typed-nil carriers, and typed-nil carrier results before invoking another method.
Nested ownership/composition unwrapping is bounded, so malformed carrier cycles
or excessive depth cannot turn resolution into unbounded recursion.

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
listener/stream pools and fixed buffers over the same core lock and stack. Local
TCP ports are leased from one namespace-owned domain in
`internal/backend/lneto/core`, shared by listeners, raw outbound streams, and
private TLS transports. Opaque owner identities and exactly-once leases prevent
one adapter or a stale release from colliding with another adapter's live port.
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
observable. `internal/backend/gotls` owns the standard-library `crypto/tls`
client engine over fixed plaintext/ciphertext rings and exactly three workers per
finite stream. `internal/backend/lneto/tls` owns only lneto transport pumping and
a private TCP adapter. TLS stream teardown joins workers before private TCP
teardown; no raw TCP handle is published. Every pump and handshake is bounded by
bytes, operations, record-sized attempts, queues, certificate/handshake limits,
and service attempts. `internal/backend/lneto/icmpv4` owns immediate Ethernet/IPv4/ICMP echo codecs,
finite copied payload and exchange storage, address-only deny-wins policy,
resource/byte/active-work quota, deterministic service-attempt retry and timeout,
exact source/identifier/sequence/checksum/payload correlation, cancellation, and
synchronous close. It does not use lneto's blocking ICMP client.
`internal/backend/lneto/ntp` owns immediate Ethernet/IPv4/UDP/NTP exchanges,
shared UDP-port leases, exact server/port/origin correlation, IPv4 and UDP
integrity checks, two-exchange offset and round-trip sampling, finite attempts
and service-attempt timeout, NTP resource/active-work quota, cancellation, and
synchronous close. It uses only the exported immediate NTP codec/client state
machine with an explicitly injected host clock; it neither adjusts the system
clock nor uses ambient `time.Now`, deadlines, sleeps, backoff, or goroutines.
`internal/backend/lneto/mdns` owns one namespace-lifetime exact UDP 5353 lease,
224.0.0.251/01:00:5e:00:00:fb framing with IPv4 TTL 255, bounded copied `.local`
A/PTR/SRV/TXT query resources, question-correlated txid-zero response selection,
finite retries and service-attempt timeout, copied configured services, bounded
automatic response slots, finite announcement resources, mDNS resource/byte/work
quota, cancellation, and synchronous close. It uses exported immediate DNS
codecs rather than the pinned combined high-level mDNS client, so nested service
slices are never retained and irrelevant records cannot complete an unrelated
query. `internal/backend/lneto/dhcpv4` owns exact shared UDP 68 client and
optional UDP 67 server leases, one bounded immediate DORA resource, finite
copied options and DNS addresses, service-attempt timeout, exact XID/MAC/server
correlation, and an optional exact transactional IPv4 identity contribution.
Configured server mode has a finite client table and protocol-local pool
authority. Existing packet adapters read the core's current IPv4 identity, and
release/close restores the configured static identity synchronously. The pinned
blocking DHCP wrapper, deadlines, sleeps, backoff, goroutines, automatic
renew/rebind, and retained guest slices are not used.
`internal/backend/lneto/ipv6` owns one exact static global or link-local IPv6
configuration contribution, one finite protocol resource charge, and a strict
base-header ingress validator with a zero extension-header bound. It enables the
pinned `x/xnet.Stack6` only during shared core construction and exposes no raw
IPv6 packets. The existing TCP adapter uses the pinned immediate IPv6 TCP path
for bounded connect and address-specific listen, mandatory pseudo-header
checksums, copied stream buffers, and deterministic close; nonzero flow labels,
wrong link-local scopes, IPv4-mapped addresses, IPv6 UDP, DNS-over-IPv6,
fragmentation, jumbograms, router discovery, DAD, SLAAC, and NDP are not claimed.
IPv6 transport uses only the explicitly configured gateway MAC; the separately
selected guest neighbor cache is not claimed as a transport route table. Caller
configured-identity denies win before namespace publication.
`internal/backend/lneto/icmpv6` owns copied bounded echo exchanges, finite
pending Neighbor Solicitations, exact cache entries, and bounded automatic echo
replies and Neighbor Advertisements. It uses exported immediate Ethernet II,
IPv6, and ICMPv6 codecs with strict base-header, pseudo-header checksum, hop
limit 255, code, option length/type/MAC, solicited-node multicast, Ethernet
multicast mapping, target/source, and pending-query correlation checks. Echo,
resolution, cache, queued response, retained-byte, active-work, retry, and
service dimensions are finite and synchronously released. Router discovery,
redirects, DAD, SLAAC, route tables, multicast echo, raw packets, blocking,
deadline, sleep, backoff, and goroutine APIs remain absent.
`internal/backend/lneto/dhcpv6` owns exact internal UDP 546/547 semantics and
one bounded initial Solicit/Advertise/Request/Reply acquisition over direct
Ethernet II, IPv6, UDP, and pinned DHCPv6 immediate codecs. It requires the
configured scoped link-local IPv6 identity, mandatory UDP pseudo-header
checksums, exact multicast mapping, transaction/client/server DUID/IAID/server
source correlation, success status, strict IA nesting, and finite repeated
option bounds before mutation. It removes the pinned Reconfigure Accept option
because Reconfigure is not exposed. Accepted address, prefix, DNS, domain, NTP, and
server data are copied observations only. Renew, rebind, release, decline,
confirm, information-request, Reconfigure, rapid commit, relay, server,
identity-apply, and raw-packet operations remain unsupported. Resource, byte,
active-work, retry, response countdown, port, parser, and service dimensions are
finite and synchronously released; no general UDP6, blocking, deadline, sleep,
backoff, goroutine, or retained guest-slice API is introduced.
`internal/backend/lneto/linklocal4` owns one exact bounded RFC 3927 claim and
its namespace-lifetime defense resource. It uses only the pinned exported
immediate link-local handler plus Ethernet II and ARP codecs, an explicit host
clock, a deterministic injected seed, finite conflict and service-attempt
bounds, protocol-local deny-wins candidate/defense policy, and exact resource
and work quota. ARP remains internal: the guest sees claim, result, cancel,
release, close, and poll only. The adapter requires the configured static
identity to be `0.0.0.0`, applies the claimed `/16` through the same exact
`IPv4IdentityLease` domain as DHCPv4, releases it immediately when repeated
defense conflict causes reconfiguration, and fails `INVALID_STATE` without
mutation if another dynamic contributor owns the domain. No lneto blocking,
deadline, sleep, retry/backoff, goroutine, or retained guest-slice API is used.
`internal/backend/lneto/dns` owns immediate IPv4 UDP queries plus lneto DNS
codecs, finite query/record/response bounds,
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
completing the Stage 4 compile-isolation boundary; runtime composition separately
covers all 4096 selective registrations.
Granular `tcp/register`, `udp/register`, `dns/register`, `icmpv4/register`,
`ntp/register`, `mdns/register`, `dhcpv4/register`, `linklocal4/register`,
`ipv6/register`, `icmpv6/register`, and `dhcpv6/register` packages own only their
selected public facade and exact implementation graph. TLS intentionally has no
self-registering package because no secure zero-configuration extension can
invent trust roots, identities, ALPN, credentials, or profile IDs. Explicit TLS
Go composition may compile the neutral TCP facet and private lneto TCP adapter,
but not the public TCP facade, TCP binding, TCP instance operations, or TCP ABI.
The root `register` package intentionally continues to compose the eleven
previously signed-off protocols in one extension rather than using the aggregate
compatibility constructor. TLS remains granular-only until TinyGo and complete
release-signoff evidence are refreshed.

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

Each `Extension` owns one private instance-state manager shared by its core,
UDP, TCP, DNS, ICMPv4, NTP, mDNS, DHCPv4, link-local, IPv6, ICMPv6, and DHCPv6 module bindings. Runtime instantiation attaches one resource table,
readiness coordinator, immutable policy, and finite quota ledger to the exact
`*wago.Instance`. Optional static
IPv4 configuration transactionally reserves namespace quota, constructs the
backend, inserts a generation-safe handle, and registers bounded readiness before
the state is published. UDP, TCP, DNS, ICMPv4, NTP, mDNS, DHCPv4, link-local,
ICMPv6, and DHCPv6 creation repeat that transaction for exact socket, listener,
stream, query, echo, synchronization, announcement, lease, claim, neighbor, or
DHCPv6 acquisition handles
and poll registration; every
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
That unpublish-before-close step is intentional: new manager lookups fail closed
immediately, while any in-flight `State.WithLock` or `State.Poll` call still
holds the per-state lifecycle mutex until its callback returns and teardown can
proceed. Teardown removes ownership first, attempts readiness, every resource,
and quota cleanup despite errors or panics, clears instance scratch/handles, and
retires each lifecycle record exactly once. The initiating caller re-panics only
after those invariants are restored; concurrent detach waiters receive the
stable `ErrTeardownPanicked` result, same-instance reattachment waits for record
retirement, and unrelated instances continue independently. Panic capture and
re-propagation occur in separate ordinary call frames so the same policy works
under both standard Go and TinyGo. The extension also calls
`Registry.RequireReinstantiation`, so class
resets that would reuse a physical instance are engine-downgraded to the same
deterministic close-and-recreate path. Failed later setup and class replacement
use that close path as well. No process-global instance map is used. The low-level
`InfoImports` bundle remains suitable only for stateless core imports such as
`abi_version`; resource-owning protocol extensions require the Runtime
lifecycle path.

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
discovered bounded fuzz, every benchmark discovered by
`scripts/benchmark-smoke.sh`, TinyGo, a distinct package cross-build, optional
bounded native/QEMU arm64 execution, custom CLI inspection, source-boundary and
plugin-plan compatibility and reviewed-upstream WASI audits, companion
repository tests, and final clean checks. It then exports deterministic non-thin
Git packs containing the exact plugin subject and pinned Wago/lneto/WASI commit
and source-tree objects, including both ordered Wago parents, before emitting a
timestamp-free deterministic provenance manifest with exact revisions/trees/
toolchains, named check outcomes, inspection facts, positive benchmark
package/target counts, exact `100ms`/`count=1`/`cpu=1`/`benchmem` settings,
accepted exceptions,
truthful skipped-execution limitations, and sorted SHA-256 evidence. A standalone
semantic verifier rejects policy, evidence, pack inventory, tree, or parent-order
drift without rerunning the gate, and a normalized deterministic tar.gz exports
only the verified review set. These packs remove moving-ref dependence for source
review but do not establish publisher authenticity or claim upstream publication.
Exact inputs, CI tiers, artifacts, bundle verification, and the narrowly accepted
known WASI preview-1 native SIGSEGV are documented in
`docs/release-signoff.md`. Baseline hosted CI fetches the exact reviewed Wago and
lneto commits into ignored dependency worktrees and runs ordinary, shuffled,
race, vet, checkptr, and backend-neutral linux/386 checks. Full linux/386 remains
visibly blocked by pinned Wago's missing `runtime.HostCtrlFrameBytes`; production
activation still depends on the stricter publication, arm64-execution, and WASI
release gates. The reviewed newer plugin-plan snapshot requires a separate
identity/cleanup/worker migration and is not a substitute pin.
