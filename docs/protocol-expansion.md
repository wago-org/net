# lneto protocol expansion plan

Status: active implementation plan. ICMPv4 is complete; later modules remain planned.

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
| `ntp` | `ntp` | bounded client synchronization using an explicit host clock |
| `mdns` | `dns/mdns` | bounded multicast query, response, and announcement operations |
| `dhcpv4` | `dhcp/dhcpv4` | bounded client leases and explicitly authorized server operation |
| `linklocal4` | `ipv4/linklocal4` | bounded RFC 3927 claim-and-defend address selection |
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
