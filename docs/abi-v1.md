# Wago networking ABI v1

Status: **experimental**. Existing signatures and numeric values become immutable
only when ABI v1 is declared stable. Breaking changes before then must still be
recorded in the durable ledger and release notes.

## Version

`wago_net.abi_version() -> i32` returns `0x0001_0000`, encoding major version 1
and minor version 0.

Except for `abi_version`, networking imports return one `i32` status and write
additional values through checked guest-memory output pointers. `InfoImports()`
and the historical zero-config `Imports(Config{})` helper intentionally expose
only `wago_net.abi_version`; every resource-owning UDP/TCP/DNS/ICMPv4/NTP/mDNS/DHCPv4/link-local import requires
exact Runtime lifecycle identity and is therefore available only through
extension registration. The completed `internal/backend/lneto/core` plus `/tcp`,
`/udp`, and `/dns` adapter extraction and selective opaque contribution assembly
change only Go implementation ownership. Unregistered adapters/facets are now
absent from the Go dependency graph as well as the Wasm import surface. The
shared UDP-port lease domain used by UDP binds and DNS source ports is likewise
internal: import names, signatures, numeric statuses, fixed sizes/offsets,
checked-range rules, output atomicity, and handle semantics in this document
remain unchanged.

## Scalar conventions

- guest pointers and lengths: `i32`, interpreted as unsigned;
- opaque handles: `i64`; zero is invalid, and bit layout is not guest ABI;
- durations: `i64` nanoseconds;
- integer structure fields: little-endian;
- network address bytes: network byte order;
- reserved input fields must be zero;
- reserved output fields are written as zero.

## Address structure

`wago_net_addr_v1` is a fixed 32-byte structure:

```c
struct wago_net_addr_v1 {
    uint8_t  family;
    uint8_t  flags;
    uint16_t port;
    uint32_t scope_id;
    uint8_t  address[16];
    uint32_t flow_info;
    uint32_t reserved;
};
```

Family `1` is IPv4 and family `2` is IPv6. IPv4 uses the first four address
bytes and requires the remaining twelve bytes, `scope_id`, and `flow_info` to be
zero. IPv6 flow information is limited to its low 20 bits. A nonzero IPv6 scope
ID is accepted only for link-local unicast (`fe80::/10`) or multicast addresses.
IPv4-mapped IPv6 addresses are rejected; callers must select IPv4 explicitly.
ABI v1 defines no flag bits, so `flags` and `reserved` must be zero on input and
are zeroed on output. Wildcard, loopback, multicast, and broadcast addresses are
represented literally; authority to use them is enforced by operation policy,
not by the structural codec.

Memory ranges are checked with `uint64` pointer-plus-length arithmetic. A
zero-length range at the exact end of memory is valid. Output helpers validate
the complete range before mutation. Multi-output operations reject overlapping
nonempty output ranges, and no guest-memory slice may be retained after a host
call.

The implementation keeps these shared memory, address, endpoint, handle, and
poll codecs in `internal/abi/core`. TCP stream/I/O, UDP receive-result, DNS name/query/record, ICMPv4 echo, NTP sample, mDNS name/query/record/announcement, and DHCPv4
request/lease and link-local request/result layouts are separate compilation
units in `internal/abi/tcp`, `internal/abi/udp`, `internal/abi/dns`,
`internal/abi/icmpv4`, `internal/abi/ntp`, `internal/abi/mdns`,
`internal/abi/dhcpv4`, and `internal/abi/linklocal4`. This package
split changes no guest-visible size, offset, validation rule, or numeric value.

## UDP module and signatures

Complete UDP operations are defined in the independently capability-gated
`wago_net_udp` import module. Every function returns one status as `i32`:

```text
namespace_default(out_handle_ptr: i32) -> i32
bind(namespace: i64, local_addr_ptr: i32, out_socket_ptr: i32) -> i32
send(socket: i64, payload_ptr: i32, payload_len: i32, remote_addr_ptr: i32) -> i32
receive(socket: i64, payload_ptr: i32, payload_len: i32, out_result_ptr: i32) -> i32
close(socket: i64) -> i32
poll(events_ptr: i32, event_capacity: i32, budget_ptr: i32, out_result_ptr: i32) -> i32
```

`namespace_default` discovers the single configured namespace for the exact
calling instance. It returns `NOT_SUPPORTED` when no namespace is configured.
The namespace remains host-owned and is not closed by the guest. `bind` writes a
new socket handle only on `OK`. `send` either accepts the whole datagram and
returns `OK`, accepts none and returns `AGAIN`, or returns another failure.
`receive` consumes exactly one datagram only after both output ranges have been
validated. It writes payload bytes and result metadata only on `OK`; `AGAIN`
leaves both outputs unchanged. `close` accepts only a live UDP socket handle.

All resource operations require the narrow `net.udp` capability. They resolve
state through the exact calling Wago instance and do not support the low-level
stateless import path.

## UDP receive result

`wago_net_udp_receive_result_v1` is 48 bytes:

```c
struct wago_net_udp_receive_result_v1 {
    struct wago_net_addr_v1 source; // offset 0
    uint32_t copied;                // offset 32
    uint32_t datagram_bytes;        // offset 36
    uint32_t flags;                 // offset 40
    uint32_t reserved;              // offset 44
};
```

Flag bit `1` is `TRUNCATED`; no other v1 bits are valid. `copied` is the payload
prefix written to the guest buffer. `datagram_bytes` is the original datagram
payload size. Truncation consumes and discards the unread suffix. Empty datagrams
are represented by `OK`, zero lengths, and a valid source endpoint; they are not
confused with `AGAIN`.

## TCP module and signatures

The complete backend-neutral TCP ABI is independently gated in the
`wago_net_tcp` module by the narrow `net.tcp` capability. Every resource call
requires exact Runtime instance identity; no TCP resource import is exposed by
the low-level stateless `InfoImports` bundle. The signatures all return one
`i32` status:

```text
namespace_default(out_handle_ptr: i32) -> i32
listen(namespace: i64, local_addr_ptr: i32, out_listener_ptr: i32) -> i32
connect(namespace: i64, remote_addr_ptr: i32, out_stream_ptr: i32) -> i32
accept(listener: i64, out_stream_ptr: i32) -> i32
finish_connect(stream: i64) -> i32
read(stream: i64, payload_ptr: i32, payload_len: i32, out_result_ptr: i32) -> i32
write(stream: i64, payload_ptr: i32, payload_len: i32, out_result_ptr: i32) -> i32
shutdown_write(stream: i64) -> i32
close_listener(listener: i64) -> i32
close_stream(stream: i64) -> i32
poll(events_ptr: i32, event_capacity: i32, budget_ptr: i32, out_result_ptr: i32) -> i32
```

`namespace_default` returns `NOT_SUPPORTED` when no static namespace is
configured. `listen` writes an opaque listener handle only on `OK`. `connect`
writes a stream structure on both `OK` and `IN_PROGRESS`; the latter is completed
by bounded service plus `finish_connect`. `accept` returns only fully established
streams and writes no output on `AGAIN`.
`read` and `write` report one immediate partial operation: `OK` writes result
metadata, `AGAIN` accepts or consumes no bytes and leaves output unchanged, and
`EOF` applies only to reads after buffered input is drained. A zero-length read
or write may return `OK` with zero bytes. `shutdown_write` initiates a local FIN
without waiting for acknowledgement. Listener and stream close are separate so
wrong-kind handles always fail closed.

Before any state change, create operations validate their complete endpoint and
stream-output ranges and require nonempty input/output ranges to be disjoint.
Read and write likewise validate the complete payload and result ranges before
consuming or accepting stream bytes. A checked range failure returns
`INVALID_ARGUMENT` without backend work or output mutation. Descriptor encoding
failure after connect or accept closes the newly allocated stream handle before
returning. No guest-memory slice may be retained beyond the host call. TCP
`poll` uses the shared layouts and state coordinator but is registered under
`net.tcp`; it never depends on a guest holding `net.udp`.

`wago_net_tcp_stream_v1` is 72 bytes:

```c
struct wago_net_tcp_stream_v1 {
    uint64_t handle;                    // offset 0
    struct wago_net_addr_v1 local;      // offset 8
    struct wago_net_addr_v1 remote;     // offset 40
};
```

The structure is encoded atomically after validating the nonzero handle and both
endpoints. It is used by `connect` and `accept`; exposing the selected ephemeral
local port prevents backend-specific endpoint discovery APIs.

`wago_net_tcp_io_result_v1` is 8 bytes:

```c
struct wago_net_tcp_io_result_v1 {
    uint32_t bytes;                     // offset 0
    uint32_t reserved;                  // offset 4, written zero
};
```

`bytes` is the immediate prefix copied or accepted and may be less than the
supplied buffer length. The structure is written only on `OK`. Would-block and
EOF are represented by status values and leave it unchanged, avoiding ambiguous
zero-byte progress.

## DNS module, signatures, and layouts

The complete checked DNS ABI is independently gated in the `wago_net_dns`
module by the narrow `net.dns` capability. Every resource call requires exact
Runtime instance identity; no DNS resource import is exposed by the low-level
stateless `InfoImports` bundle. The table is:

```text
namespace_default(out_handle_ptr: i32) -> i32
resolve(namespace: i64, query_ptr: i32, out_query_ptr: i32) -> i32
next(query: i64, out_record_ptr: i32) -> i32
cancel(query: i64) -> i32
close(query: i64) -> i32
poll(events_ptr: i32, event_capacity: i32, budget_ptr: i32, out_result_ptr: i32) -> i32
```

`wago_net_dns_name_v1` is 260 bytes: a little-endian `uint16_t length`, a zero
`uint16_t reserved`, 253 inline normalized lowercase ASCII name bytes, and three
zero padding bytes. Length is 1..253. Unused bytes must be zero on input and are
zeroed on output. Numeric IP literals, trailing dots, wildcard or empty labels,
non-ASCII bytes, uppercase bytes, and labels outside the DNS limits are rejected.

`wago_net_dns_query_v1` is 268 bytes: an inline DNS name at offset 0, a
little-endian `uint32_t record_types` at offset 260, and zero `uint32_t reserved`
at offset 264. Record-type bit `1` requests A and bit `2` requests AAAA; at least
one bit is required and no other bits are accepted. `resolve` checks the complete
query and handle output and requires them to be disjoint before policy, quota, or
backend work. It writes the handle only on `OK` or `IN_PROGRESS`.

`wago_net_dns_record_v1` is 560 bytes:

```c
struct wago_net_dns_record_v1 {
    struct wago_net_dns_name_v1 name;       // offset 0
    uint32_t type;                          // offset 260
    uint32_t ttl_seconds;                   // offset 264
    struct wago_net_addr_v1 address;        // offset 268
    struct wago_net_dns_name_v1 canonical;  // offset 300
};
```

Type `1` is A, `2` is AAAA, and `3` is CNAME. A/AAAA populate only `address`
with a zero port and leave `canonical` all zero. CNAME populates only
`canonical` and leaves `address` all zero. The encoder validates the complete
backend-neutral record and output range, builds a zeroed temporary structure,
and copies it atomically. `next` validates the complete output before consuming
a record; `AGAIN`, `EOF`, and failures leave output unchanged. Cancel makes an
unfinished query terminal with `CANCELED`, retires its transport immediately,
and does not retire its guest-visible handle; `close` performs generation
retirement and deterministic quota/storage cleanup.

The configured backend sends bounded UDP queries to one static IPv4 recursive
resolver. A response is accepted only from that resolver and only while the
query remains transport-active. Terminal queries retire their UDP source port
and response-dispatch entry before publishing success or failure, so late or
duplicate packets cannot mutate committed results. A response is also accepted
only when its UDP port, destination port, transaction ID, IPv4/UDP integrity,
nonfragmented shape, and complete echoed question names/classes/types match the
request. Successful answers preserve the first unique reachable CNAME chain in
chain order, followed by unique requested A/AAAA records at the terminal name.
Irrelevant records, unrequested address types, and semantic duplicates are
ignored. Conflicting CNAME targets, CNAME loops, malformed compression,
malformed resources, and retention-limit overflow fail closed. A successful
response may contain no relevant records, in which case `next` returns `EOF`.
Truncated UDP responses return `TEMPORARY_FAILURE`; ABI v1 does not implement
DNS-over-TCP fallback.

## ICMPv4 module, signatures, and layouts

The complete checked ICMPv4 ABI is independently gated in the
`wago_net_icmpv4` module by `net.icmpv4`:

```text
namespace_default(out_handle_ptr: i32) -> i32
echo(namespace: i64, request_ptr: i32, out_echo_ptr: i32) -> i32
result(echo: i64, payload_ptr: i32, payload_capacity: i32, out_result_ptr: i32) -> i32
cancel(echo: i64) -> i32
close(echo: i64) -> i32
poll(events_ptr: i32, event_capacity: i32, budget_ptr: i32, out_result_ptr: i32) -> i32
```

`wago_net_icmpv4_echo_request_v1` is 48 bytes: a `wago_net_addr_v1`
IPv4 destination with zero port at offset 0, little-endian `uint32_t payload_ptr`
and `uint32_t payload_len` at offsets 32 and 36, and a zero `uint64_t reserved`
at offset 40. The fixed request, indirect payload, and handle output must be
pairwise disjoint and completely in bounds before policy, quota, or backend
work. The backend copies the payload during `echo`; no guest slice is retained.

`wago_net_icmpv4_echo_result_v1` is 48 bytes:

```c
struct wago_net_icmpv4_echo_result_v1 {
    struct wago_net_addr_v1 source;  // offset 0, IPv4 with zero port
    uint16_t identifier;             // offset 32
    uint16_t sequence;               // offset 34
    uint32_t copied;                 // offset 36
    uint32_t payload_bytes;          // offset 40
    uint32_t reserved;               // offset 44, written zero
};
```

`result` validates disjoint payload/result outputs before lookup. On `OK`, it
copies at most `payload_capacity` bytes and reports both the copied prefix and
complete echoed payload size. `AGAIN`, cancellation, timeout, and failures leave
both outputs unchanged. Echo replies must match the exact destination,
identifier, sequence, checksum, and copied request payload. Attempts and retry
countdowns advance only through bounded service calls; cancellation and close
are deterministic and release active-work or retained-resource quota exactly
once.

## NTP module, signatures, and sample layout

The complete checked NTP ABI is independently gated in the `wago_net_ntp`
module by `net.ntp`:

```text
namespace_default(out_handle_ptr: i32) -> i32
sync(namespace: i64, out_sync_ptr: i32) -> i32
result(sync: i64, out_sample_ptr: i32) -> i32
cancel(sync: i64) -> i32
close(sync: i64) -> i32
poll(events_ptr: i32, event_capacity: i32, budget_ptr: i32, out_result_ptr: i32) -> i32
```

`sync` validates the complete handle output before policy, quota, clock, or
backend work and writes it only on `OK` or `IN_PROGRESS`. Each handle owns one
bounded two-exchange NTPv4 client synchronization against the module's explicit
IPv4 server on UDP port 123. The adapter timestamps packets only through the
host-injected clock supplied during registration; it has no ambient wall-clock
authority and never adjusts the host system clock. General UDP authority does
not grant NTP authority. Exact server address, source/destination ports, echoed
origin timestamp, IPv4/UDP integrity, unfragmented shape, server mode, version,
leap indicator, stratum, and fixed 48-byte basic response shape are validated.

`wago_net_ntp_sample_v1` is 72 bytes:

```c
struct wago_net_ntp_sample_v1 {
    struct wago_net_addr_v1 server; // offset 0, IPv4 with zero port
    int64_t  corrected_unix_seconds; // offset 32
    uint32_t corrected_nanoseconds;  // offset 40, 0..999999999
    uint8_t  stratum;                // offset 44, 1..15
    uint8_t  leap;                   // offset 45, 0..2
    uint8_t  version;                // offset 46, exactly 4
    uint8_t  reserved_flags;         // offset 47, zero
    int64_t  offset_nanoseconds;     // offset 48
    int64_t  round_trip_nanoseconds; // offset 56, nonnegative
    uint8_t  reference_id[4];        // offset 64
    uint32_t reserved;               // offset 68, zero
};
```

The corrected instant is the explicit host clock sampled at completion plus the
calculated offset. It is a returned observation, not a claim that any clock was
set. `result` writes the structure atomically only on `OK`; `AGAIN`, timeout,
cancellation, and failures leave it unchanged. Attempts and retry countdowns
advance only through bounded service calls. Cancellation and close are
deterministic and release active-work, UDP-port, and resource quota exactly
once. Registration without a server and clock exposes a truthful disabled
module whose `sync` returns `NOT_SUPPORTED`.

## mDNS module, signatures, and layouts

The complete checked IPv4 multicast DNS ABI is independently gated in
`wago_net_mdns` by `net.mdns`:

```text
namespace_default(out_handle_ptr: i32) -> i32
query(namespace: i64, query_ptr: i32, out_query_ptr: i32) -> i32
next(query: i64, out_record_ptr: i32) -> i32
cancel_query(query: i64) -> i32
close_query(query: i64) -> i32
announce(namespace: i64, announcement_ptr: i32, out_announcement_ptr: i32) -> i32
finish_announcement(announcement: i64) -> i32
cancel_announcement(announcement: i64) -> i32
close_announcement(announcement: i64) -> i32
poll(events_ptr: i32, event_capacity: i32, budget_ptr: i32, out_result_ptr: i32) -> i32
```

`wago_net_mdns_name_v1` is 260 bytes and has the same length/reserved/inline
shape as the DNS name structure, but permits lowercase ASCII underscore labels
for DNS-SD service names. Names must end in `.local`; spaces, escapes, wildcards,
non-ASCII labels, trailing dots, uppercase bytes, and IP literals are rejected.
`wago_net_mdns_query_v1` is 268 bytes: one inline mDNS name, a `uint32_t` type
bitset at offset 260, and zero reserved word at 264. Bits 1, 2, 4, and 8 request
A, PTR, SRV, and TXT respectively.

`wago_net_mdns_record_v1` is 832 bytes: name at offset 0, type at 260, TTL at
264, address at 268, target name at 300, SRV port/priority/weight at 560/562/564,
TXT length at 566, 255 inline TXT bytes at 568, flags at 824, and zero reserved
word at 828. Type values 1..4 are A, PTR, SRV, and TXT. Flag bit 1 preserves the
mDNS cache-flush class bit. Type-specific unused fields and TXT padding are
zero. `wago_net_mdns_announcement_v1` is 8 bytes containing a zero-based
`uint32_t` configured-service index and a zero reserved word.

The adapter owns one exact shared UDP port 5353 lease for the namespace lifetime;
a public UDP bind to that port therefore returns `ADDRESS_IN_USE`. Outgoing
packets use 224.0.0.251, Ethernet 01:00:5e:00:00:fb, source/destination UDP port
5353, txid zero, and IPv4 TTL 255. Query correlation uses the requested
name/class/type because mDNS has no transaction identifier. Irrelevant and
duplicate records are ignored; the first packet containing a relevant bounded
record completes the query. Configured host services are deeply copied and may
produce bounded automatic PTR/SRV/TXT/A responses. Announcements are finite
retry resources. Query and announcement cancellation is deterministic, and
exact-kind close synchronously releases retained record/packet/work quota.
General UDP or DNS authority cannot widen mDNS, and caller denies win over the
module's exact multicast and `.local` defaults.

## DHCPv4 module, signatures, and layouts

The checked DHCPv4 ABI is independently gated in `wago_net_dhcpv4` by
`net.dhcpv4`:

```text
namespace_default(out_handle_ptr: i32) -> i32
acquire(namespace: i64, request_ptr: i32, out_handle_ptr: i32) -> i32
result(lease: i64, out_result_ptr: i32) -> i32
cancel(lease: i64) -> i32
release(lease: i64) -> i32
close(lease: i64) -> i32
poll(events_ptr: i32, event_capacity: i32, budget_ptr: i32, out_result_ptr: i32) -> i32
```

`wago_net_dhcpv4_request_v1` is 112 bytes. It contains a 32-byte IPv4 address
structure with zero port at offset 0, hostname and client-ID lengths at offsets
32 and 34, 36 inline hostname bytes at 36, 32 inline client-ID bytes at 72, and
eight zero reserved bytes at 104. An unspecified requested address means no
preference. Unused inline bytes are zero and no guest slice is retained.

`wago_net_dhcpv4_lease_v1` is 280 bytes: assigned, server, router, and broadcast
IPv4 address structures at offsets 0, 32, 64, and 96; subnet prefix bits at 128;
lease, renewal, and rebind seconds at 132, 136, and 140; DNS count at 144; flags
at 148; and four inline DNS address structures at 152. Flag bit 1 means the
accepted address/subnet is currently applied as the namespace's exact dynamic
identity contribution. Optional absent addresses are all-zero structures. The
encoder validates the complete lease and output before one atomic copy.

The client owns exact shared UDP port 68 and performs one bounded immediate DORA
sequence over broadcast UDP port 67. Result publication requires exact XID,
hardware address, selected server/source, message type, framing, checksum,
fragmentation, and option-bound validation. Explicit identity application is
permitted only over a configured `0.0.0.0` placeholder and rolls back on
`release`, `close`, or instance teardown. `release` is local rollback: the pinned
client has no immediate DHCPRELEASE, renewal, or rebinding operation, and ABI v1
does not claim those wire operations. Explicitly configured host server mode is
automatic bounded namespace service rather than a raw guest packet API; it owns
port 67, a finite client pool, and protocol-local inbound/outbound authority.

## IPv4 link-local module, signatures, and layouts

The checked RFC 3927/APIPA ABI is independently gated in
`wago_net_linklocal4` by `net.linklocal4`:

```text
namespace_default(out_handle_ptr: i32) -> i32
claim(namespace: i64, request_ptr: i32, out_handle_ptr: i32) -> i32
result(claim: i64, out_result_ptr: i32) -> i32
cancel(claim: i64) -> i32
release(claim: i64) -> i32
close(claim: i64) -> i32
poll(events_ptr: i32, event_capacity: i32, budget_ptr: i32, out_result_ptr: i32) -> i32
```

`wago_net_linklocal4_request_v1` is the fixed 32-byte address structure. Its
port, scope, flow, flags, and reserved fields are zero. Address `0.0.0.0`
requests deterministic selection from the configured finite candidate sequence;
a nonzero address must be in `169.254.1.0` through `169.254.254.255` and is tried
first. The request and handle output must be disjoint and completely checked
before policy, quota, clock, or backend work.

`wago_net_linklocal4_result_v1` is 48 bytes:

```c
struct wago_net_linklocal4_result_v1 {
    struct wago_net_addr_v1 address; // offset 0, usable IPv4 link-local address
    uint32_t subnet_bits;            // offset 32, exactly 16
    uint32_t conflicts;              // offset 36, bounded cumulative conflicts
    uint32_t flags;                  // offset 40, bit 1 = identity applied
    uint32_t reserved;               // offset 44, zero
};
```

The module requires an explicitly injected host clock and nonzero deterministic
seed before finite defaults activate. It exposes claim/result/cancel/release
semantics rather than raw ARP. The immediate backend emits bounded internal ARP
probes, announcements, and at most one defense per permitted defense interval;
a repeated conflict rolls back the exact identity and returns the resource to
bounded claim progress. `result` returns `AGAIN` while initially claiming or
reconfiguring and writes atomically only while the exact identity remains
applied. The configured static IPv4 identity must be `0.0.0.0`. DHCPv4 and
link-local share one exact dynamic `IPv4IdentityLease` domain, so a competing
owner causes `INVALID_STATE` without replacement or mutation. `release` and
`close` synchronously restore the configured static placeholder. General UDP,
ICMPv4, or raw-packet authority cannot widen link-local authority, caller denies
win, and no raw ARP guest API exists.

## Bounded poll layouts

`wago_net_poll_budget_v1` is 24 bytes, containing six consecutive `uint32_t`
fields: `scans`, `events`, `service_attempts`, `service_packets`,
`service_bytes`, and `service_operations`. `scans` and `events` must be nonzero.
If `service_attempts` is nonzero, all three per-attempt service bounds must also
be nonzero. The requested event count must not exceed `event_capacity`.

Each 16-byte `wago_net_poll_event_v1` contains `uint64_t handle`, `uint32_t
readiness`, and a zero `uint32_t reserved` field. Readiness is level-triggered:
bit `1` readable, bit `2` writable, bit `4` accept, bit `8` connected, bit `16`
DNS result, bit `32` error, bit `64` closed, bit `128` ICMPv4 reply, bit `256`
NTP result, bit `512` mDNS query result, bit `1024` mDNS announcement completion, and bit
`2048` DHCPv4 lease result, and bit `4096` IPv4 link-local result. Unknown bits
are invalid.

`wago_net_poll_result_v1` is 24 bytes, containing six consecutive `uint32_t`
fields: `events`, `scanned`, `service_attempts`, `service_completed`,
`stale_registrations`, and zero `reserved`. `poll` validates its complete event
capacity and result output before service begins. It writes the first `events`
entries and the result on both `OK` and `AGAIN`; unused event slots are unchanged.
No call sleeps, scans beyond the supplied bound, emits beyond the event bound, or
services beyond the supplied attempt and per-attempt budgets. Before polling, the
host transactionally reserves `scans + events + service_attempts` service-work
units from the exact instance quota and releases them when the call returns. A
request above the finite limit returns `RESOURCE_LIMIT` without service or output
mutation.

## Status values

| Value | Name |
|---:|---|
| 0 | `OK` |
| 1 | `AGAIN` |
| 2 | `IN_PROGRESS` |
| 3 | `EOF` |
| 4 | `ACCESS_DENIED` |
| 5 | `INVALID_ARGUMENT` |
| 6 | `BAD_HANDLE` |
| 7 | `INVALID_STATE` |
| 8 | `NOT_SUPPORTED` |
| 9 | `NO_MEMORY` |
| 10 | `RESOURCE_LIMIT` |
| 11 | `ADDRESS_IN_USE` |
| 12 | `ADDRESS_NOT_AVAILABLE` |
| 13 | `REMOTE_UNREACHABLE` |
| 14 | `CONNECTION_REFUSED` |
| 15 | `CONNECTION_RESET` |
| 16 | `CONNECTION_ABORTED` |
| 17 | `CONNECTION_BROKEN` |
| 18 | `TIMED_OUT` |
| 19 | `MESSAGE_TOO_LARGE` |
| 20 | `NAME_NOT_FOUND` |
| 21 | `TEMPORARY_FAILURE` |
| 22 | `IO` |
| 23 | `CANCELED` |
| 24 | `OTHER` |

Unknown backend or Go errors map to a stable status, normally `OTHER` or `IO`.
Unstable Go error strings are not returned to guests.

Resource handles are scoped to one runtime instance and checked against an exact
resource kind. Closing a resource invalidates its handle before backend cleanup;
slot reuse advances a generation, and generation exhaustion retires the slot.
Handles from another instance, stale handles, wrong-kind handles, zero, and
malformed values return `BAD_HANDLE`. Guests must not derive or inspect handle
bits.

Endpoint-changing imports enforce immutable instance policy on every bind,
listen, connect, datagram destination, DNS request, ICMPv4 echo destination,
NTP server synchronization, mDNS query/announcement/response authority, and
DHCPv4 client/server endpoint authority, and IPv4 link-local candidate and
defense authority.
Unmatched or malformed requests are denied. Wildcard binds, loopback, multicast,
limited IPv4 broadcast, and local bind/listen ports below 1024 require separate
explicit grants so a broad prefix rule cannot grant them accidentally.
IPv4-mapped IPv6 addresses are rejected rather than reinterpreted across policy
families.

Resource creation, retained packet bytes, DNS work, active ICMPv4 work, active
NTP work, active mDNS query/announcement work, active DHCPv4 DORA work, active
IPv4 link-local claim/defense work, and manual service work are also
subject to finite per-instance quotas. A failed operation must roll back its
tentative reservation, and instance teardown clears both committed allocations
and abandoned reservations. Exact default limits remain implementation policy,
not ABI constants.

The host extension requires physical reinstantiation between class leases.
Consequently, a Wago class configured with an in-place reset policy is safely
executed as `ResetReinstantiate` while networking is registered. This is an
embedding/lifecycle guarantee rather than a guest-visible status or layout: no
handle, queued byte, listener, stream, socket, readiness registration, or quota
token survives into the next lease.

## Compatibility boundary

This is a Wago-specific core Wasm ABI. It is not a WASI Component Model or WIT
resource ABI, even where operation semantics are intentionally similar.
