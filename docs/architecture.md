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

This permits selective compilation and narrow capabilities without two extensions
competing to own `wago_net`. Shared per-instance state will be coordinated by an
explicit provider object rather than process globals. No protocol package will be
created merely as a placeholder.

## Current implementation

The root package is the core extension. It owns `wago_net`, declares `net.info`,
and exposes only `abi_version`. The extension and low-level import bundle are both
derived from one binding table so inspection metadata and actual bindings do not
drift. `internal/abi` provides allocation-free checked memory ranges and the
fixed-width IPv4/IPv6 address codec for future protocol packages.
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
UDP bind/send, TCP listen/connect, and DNS resolve checks.

`internal/quota` provides finite per-instance total/protocol resource, queued-byte,
DNS-work, and service-work counters. Tentative reservations must be committed or
rolled back; committed allocations release exactly once. Closing an instance
first closes resources and then closes its quota account, which clears abandoned
reservations and makes late token cleanup harmless.

`internal/namespace` defines the backend-neutral endpoint, UDP, TCP, DNS,
readiness, semantic-error, and bounded manual-service contracts. Operations that
may await network progress are single `Try` calls with explicit would-block or
in-progress results. Result validators make partial stream I/O, datagram
truncation, DNS record ownership, and service-budget bounds explicit. A
compile-time fake backend exercises the contracts without importing lneto; no
lneto type is part of this layer.

`internal/packetlink` owns fixed ingress and egress frame slots. Enqueue copies
caller data, dequeue has explicit truncation and byte-budget rollback semantics,
and backend fills commit atomically only after successful immediate production.
Queue-full and oversized failures retain no caller slices, and close clears all
retained bytes synchronously.

`internal/backend/lneto` owns one `xnet.StackAsync` and one packet link per
namespace. Only immediate Ethernet ingress and egress calls enter bounded manual
service; no lneto blocking, deadline, goroutine, or backoff wrapper is used.
Service alternates directions under independent packet, byte, and operation
bounds and maps backend errors to semantic namespace failures. IPv4 UDP is now
implemented with adapter-owned fixed datagram queues and lneto's immediate
Ethernet/IPv4/UDP frame codecs. This design is deliberate: lneto's high-level UDP
wrappers back off, while its exported immediate mux cannot represent an empty
payload. The adapter preserves empty and truncated datagrams, validates checksums
and fragmentation, enforces policy on bind and every send, reserves exact finite
resource/retained-storage quota, rotates egress deterministically, and clears all
queue bytes on close. TCP and DNS constructors remain truthfully unsupported.

`internal/readiness` attaches a finite coordinator to each instance resource
table. Registrations retain opaque handle plus exact kind, level-triggered polls
scan at most one bounded pass, output only caller-budgeted events, and make only
bounded namespace service attempts. Stale generation handles are removed during
the bounded scan; polling never sleeps and exposes no guest import yet.

Each `Extension` now owns a private instance-state manager. Runtime
instantiation attaches one resource table, readiness coordinator, immutable
policy, and finite quota ledger to the exact `*wago.Instance`. Optional static
IPv4 configuration transactionally reserves namespace quota, constructs the
backend, inserts a generation-safe handle, and registers bounded readiness before
the state is published. UDP creation repeats that transaction for its socket
handle and poll registration; every failed stage closes the backend resource and
releases accounting. Host imports recover exact identity through the additive
`wago.InstanceHostModule` interface, and `BeforeClose` removes the attachment
before polling shutdown, reverse-creation resource cleanup, and quota shutdown.
Failed later setup and `ResetReinstantiate` replacement use the same close path.
No process-global instance map is used. The low-level `Imports` bundle remains
suitable only for stateless core imports such as `abi_version`; resource-owning
protocol extensions require the Runtime lifecycle path.

The companion Wago branch `net/instance-close-hooks` contains the prerequisites:
commit `dd82ec9a8963463e6516bf803bec58b3a89b89b3` adds deterministic close hooks,
and commit `0156936` adds optional exact host-call instance identity without
expanding the minimal `HostModule` interface.

## Pool reset restriction

`wago.ResetMemorySnapshot` is **not supported** for any class using networking
extensions. It reuses a physical instance without a close or reset hook, so
lease-scoped network resources would cross tenant boundaries. Such classes are
blocked by project policy and must use `wago.ResetReinstantiate`. This restriction
cannot yet be enforced by the plugin because Wago does not expose reset-policy
eligibility to extensions; do not enable snapshot reuse until Wago provides a
reset lifecycle hook or an extension eligibility control and this suite adds
corresponding cleanup tests.
