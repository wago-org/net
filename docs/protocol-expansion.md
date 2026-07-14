# lneto protocol expansion plan

Status: active implementation plan. ICMPv4, NTP, mDNS, DHCPv4, and IPv4
link-local/APIPA are complete; IPv6 and later modules remain planned.

## Goal

Expose every operational network protocol supplied by the pinned `lneto`
revision as an independently selectable Wago networking submodule, while
preserving the existing backend-neutral ABI, exact-instance ownership,
capability gates, immutable deny-wins authority, finite quotas, bounded polling,
and deterministic teardown rules.

Each implementation slice is limited to three atomic commits. A slice must leave
all committed behavior tested and must not advertise an import module before its
backend and lifecycle path are usable.

## Included guest submodules

The expansion covers these protocol packages beyond the existing TCP, UDP, and
DNS modules:

| Planned submodule | lneto package or facility | Initial guest scope |
|---|---|---|
| `icmpv4` | `ipv4/icmpv4` | complete: bounded copied echo requests and exact replies |
| `ntp` | `ntp` | complete: bounded two-exchange client sampling using an explicit host clock |
| `mdns` | `dns/mdns` | complete: bounded multicast query, response, and announcement operations |
| `dhcpv4` | `dhcp/dhcpv4` | complete: bounded client DORA leases and explicitly authorized finite server operation |
| `linklocal4` | `ipv4/linklocal4` | complete: bounded RFC 3927 claim-and-defend address selection |
| `ipv6` | `ipv6` and `x/xnet` IPv6 stack | configured IPv6 namespace and transport enablement |
| `icmpv6` | `ipv6/icmpv6` | bounded echo and Neighbor Discovery operations |
| `dhcpv6` | `dhcp/dhcpv6` | the finite client/configuration subset implemented by the pinned library |

DHCPv6 must truthfully document and return `NOT_SUPPORTED` for functionality the
pinned library does not implement, including relay-agent and dynamic-server-pool
operation.

## Existing stack infrastructure

Ethernet II, ARP, and IPv4 are already required internally by the shared lneto
namespace. They remain backend infrastructure rather than privileged raw-frame
guest APIs. IPv6 needs an explicit selectable module because enabling it changes
namespace construction, endpoint families, and ICMPv6/NDP behavior.

The `phy` package and MDIO support are hardware-abstraction facilities rather
than instance-owned network protocols. They remain outside the Wasm guest ABI.
Packet capture likewise remains host-side diagnostic infrastructure.

## Explicit exclusions

- HTTP is excluded from this repository's protocol modules. Applications may
  layer it over TCP or use a separate streaming library.
- TLS 1.3 is not implemented by the pinned lneto revision and is not added here.
- NTS is deferred because usable NTS requires the excluded TLS and external
  cryptography path.
- HTTPS and every other TLS-dependent application protocol are consequently
  deferred.
- Raw Ethernet, ARP, IPv4, IPv6, or PHY access is not implied by the protocol
  modules above.

## Required shape of every module

Each new protocol must follow the selective composition boundary already used by
`tcp`, `udp`, and `dns`:

1. a public `<protocol>.Register` facade with finite defaults and conspicuous
   authority options;
2. one exact capability and one `wago_net_<protocol>` import module;
3. protocol-local fixed ABI codecs and checked guest-memory operations;
4. protocol-local instance operations and generation/kind-checked resources;
5. a narrow backend-neutral namespace facet;
6. one exact `internal/backend/lneto/<protocol>` adapter or an explicit shared
   core configuration contribution;
7. bounded readiness/service work, quota accounting, cancellation where work can
   remain pending, and synchronous close cleanup;
8. selective dependency tests proving omitted modules and adapters do not enter
   unrelated build graphs;
9. granular self-registration plus explicit aggregate registration only after
   the selective module is complete.

No module may use lneto's blocking, deadline, goroutine, sleep, or retry/backoff
wrappers. Retained guest slices are forbidden. Every packet, byte, resource,
retry, queue, scan, and operation dimension must have a finite configured bound.

## Recommended implementation order

1. ICMPv4, establishing raw IP-protocol policy and bounded request resources.
2. NTP, establishing explicit clock injection without ambient time authority.
3. mDNS, establishing multicast name operations and shared UDP-port ownership.
4. DHCPv4, followed by IPv4 link-local, establishing transactional namespace
   identity changes.
5. IPv6 namespace construction.
6. ICMPv6/NDP.
7. The implemented DHCPv6 client/configuration subset.

The order is dependency-driven. Later modules may reuse only backend-neutral
contracts established by earlier modules; they must not import another public
protocol facade or binding package.

## Completion ledger

ICMPv4 is exposed as independently selectable `icmpv4.Register`, capability
`net.icmpv4`, and import module `wago_net_icmpv4`. Its fixed request ABI checks
the inline destination, indirect payload, and handle output before work and the
backend copies payload bytes immediately. Exact-instance echo handles have a
protocol resource kind, reply readiness bit, finite resource/queued-byte/active
work quota, bounded service-attempt retries and timeout, cancellation, and
synchronous generation-safe close. The immediate adapter uses only exported
Ethernet II, IPv4, and ICMPv4 frame codecs; it validates source, identifier,
sequence, checksums, fragmentation, and exact echoed bytes. Selective dependency
fixtures reject the adapter, namespace facet, instance operations, ABI, binding,
and public facade whenever ICMPv4 is omitted. Ethernet II, ARP, IPv4, PHY/MDIO,
and packet capture remain internal infrastructure rather than guest APIs.

NTP is exposed as independently selectable `ntp.Register`, capability `net.ntp`,
and import module `wago_net_ntp`. Registration requires one explicit unicast
IPv4 server and injected host clock before finite defaults become active; the
zero configuration remains a truthful disabled module. Its fixed checked ABI
owns exact-instance synchronization handles, atomic 72-byte samples, NTP result
readiness, finite resource/active-work/service quota, bounded attempts and
service-attempt timeout, cancellation, and synchronous generation-safe close.
The immediate adapter uses exported Ethernet II, IPv4, UDP, and NTP codecs plus
the nonblocking NTP client state machine only. It leases shared UDP ports,
validates exact server/port/origin correlation, checks IPv4/UDP integrity,
rejects fragmented, malformed, unsynchronized, wrong-mode, wrong-version, and
non-basic responses, and returns offset, nonnegative round-trip delay, stratum,
reference ID, and a corrected observation without adjusting any system clock.
Caller deny rules win over the configured server grant, and general UDP
authority cannot widen NTP. Selective dependency fixtures reject every omitted NTP layer; the composition
matrix established here has since expanded to all 256 combinations of the eight
completed protocols, and granular plus aggregate registration are documented
and tested.
No TLS or NTS behavior is included.

mDNS is exposed as independently selectable `mdns.Register`, capability
`net.mdns`, and ten-function import module `wago_net_mdns`. Its fixed checked ABI
owns exact-instance query and announcement handles, inline canonical `.local`
names with DNS-SD underscore labels, A/PTR/SRV/TXT type bits, an atomic 832-byte
record union with inline 255-byte TXT storage, and zero-based configured-service
announcement requests. One namespace-owned adapter reserves UDP port 5353 in the
same lease domain as public UDP, DNS, and NTP, so later conflicting binds fail
with `ADDRESS_IN_USE`. It uses exact 224.0.0.251 and
01:00:5e:00:00:fb framing, UDP source/destination port 5353, IPv4 TTL 255,
checksum and nonfragmented-frame validation, txid-zero name/class/type
correlation, finite first-relevant-response retention, duplicate and irrelevant
record filtering, bounded attempts and service timeout, cancellation, and
synchronous close. Configured services and TXT bytes are deeply copied;
incoming matching questions produce only bounded queued responses, while finite
announcement resources provide deterministic completion. mDNS has protocol-local
`.local`, multicast, and port authority with caller deny precedence; general UDP
or DNS grants cannot widen it. Resource, retained-byte, active-work, and service
quotas cover every host-retained dimension. The pinned combined high-level mDNS
client is not used because its shallow service copy and combined query/response
state do not provide the required ownership and correlation boundaries; only
exported immediate DNS and packet codecs enter host paths. Selective dependency
fixtures reject every omitted mDNS layer; granular plus aggregate registration
are tested. Ethernet II, ARP, IPv4, PHY/MDIO, and packet capture remain internal
infrastructure rather than guest APIs.

DHCPv4 is exposed as independently selectable `dhcpv4.Register`, capability
`net.dhcpv4`, and seven-function import module `wago_net_dhcpv4`. Its fixed
checked ABI owns exact-instance lease handles, an inline 112-byte request, and an
atomic 280-byte copied lease with at most four DNS servers. The immediate adapter
uses the pinned exported DHCPv4 client/server state machines and Ethernet II,
IPv4, and UDP codecs only. One client transaction owns exact UDP port 68; an
explicit finite server owns port 67 in the same shared lease domain. Client DORA
validates Ethernet/IP/UDP integrity, nonfragmented packets, XID, hardware address,
message type, selected server identity, source address, option bounds, and finite
service-attempt timeout. Accepted address/subnet identity can be applied only by
an explicit option and only over a configured `0.0.0.0` static placeholder; the
exact lease contribution rolls back synchronously on release or close, while all
existing packet adapters read the shared current identity. Server mode is off by
default, requires an exact local address, subnet, lease duration, and bounded
client count, and checks protocol-local privileged bind plus per-offer outbound
pool authority. General UDP authority cannot widen DHCPv4 and caller denies win.
The pinned client implements immediate Discover/Offer/Request/Ack only: automatic
renew/rebind and wire DHCPRELEASE are not claimed; `release` is explicitly local
identity rollback. Resource, retained-byte, active-work, port, parser, queue, and
service dimensions are finite. Selective dependency fixtures reject every
omitted DHCPv4 layer, runtime composition now covers all 256 combinations of the
eight completed protocols, and granular plus aggregate registration are tested.
No HTTP, TLS, HTTPS, NTS, raw Ethernet, ARP, IPv4, PHY/MDIO, or packet-capture
guest API is added.

IPv4 link-local/APIPA is exposed as independently selectable
`linklocal4.Register`, capability `net.linklocal4`, and seven-function import
module `wago_net_linklocal4`. Registration remains truthfully disabled until a
nonzero deterministic seed and explicit host clock are supplied; finite defaults
permit one exact claim, sixteen cumulative conflicts, and 256 service attempts.
Its checked fixed ABI uses a 32-byte inline first-candidate request and atomic
48-byte claimed result, exact-instance generation/kind-checked claim handles,
link-local result readiness, finite protocol resource/active-work quota,
cancellation, release, bounded poll, and synchronous close. The immediate
adapter uses only the pinned exported heapless `ipv4/linklocal4.Handler` plus
Ethernet II and ARP codecs. It bounds candidates, conflicts, scheduling attempts,
frames, resources, and work; validates ARP framing before conflict observation;
and applies protocol-local candidate/defense policy on every emitted operation,
with caller denies winning over the default RFC 3927 prefix grant. ARP remains
internal infrastructure: no raw frame or ARP import is exposed. A configured
static `0.0.0.0` placeholder is required. Link-local and DHCPv4 share the same
single exact transactional `IPv4IdentityLease` domain, so neither can replace
the other's active identity; contention returns `INVALID_STATE` without
mutation. Repeated defense conflict releases only the exact link-local owner
before bounded reconfiguration, and guest release/close restores the configured
placeholder synchronously. The adapter uses no lneto blocking wrapper, deadline,
sleep, retry/backoff helper, goroutine, ambient clock, or retained guest slice.
Selective dependency fixtures reject every omitted link-local layer, runtime
composition covers all 256 combinations of the eight completed protocols, and
granular plus aggregate registration are tested. Ethernet II, ARP, IPv4,
PHY/MDIO, and packet capture remain internal rather than guest APIs.
