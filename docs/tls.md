# Outbound TLS client capability

`github.com/wago-org/net/tls` is a separately selectable, client-only secure
stream protocol. It declares `net.tls` and `wago_net_tls`; it does not declare
`net.tcp` or install `wago_net_tcp`. The lneto implementation privately owns an
internal TCP stream, never publishes that stream in the guest resource table,
and closes both TLS and TCP ownership exactly once.

## Public API and authority

Hosts construct immutable profiles with `NewClientProfile`, exact profile IDs,
`AllowServerNames`, optional `RequireALPN`, and an ordinary `*crypto/tls.Config`.
The configuration, roots, certificate DER, ALPN list, and name authority are
cloned. Later caller mutation cannot change registration. Client private-key
objects stay in host memory and no certificate chain or private key appears in
the guest ABI.

The first release rejects `InsecureSkipVerify`, `KeyLogWriter`, renegotiation,
verification callbacks, certificate-selection callbacks, client session caches,
and Encrypted ClientHello callbacks/configuration. Session resumption and 0-RTT
are disabled by the absence of a client session cache and any early-data API.
TLS 1.3 is the default minimum and maximum. TLS 1.2 is available only when the
host combines an explicit TLS 1.2 minimum with `EnableTLS12`; Go's standard safe
cipher-suite defaults remain in effect. Manual cipher, signature, curve,
record, key-derivation, and certificate-verification implementations are absent.

A guest supplies a finite profile ID, remote IP endpoint, and authorized
verification identity. DNS names are normalized before transport creation and
verified by Go's `crypto/x509` hostname rules. IP strings remain IP identities
and require an IP SAN. Common Name fallback is not used. Offered ALPN comes only
from the host profile; required ALPN must be negotiated before connection
completion. TLS allow/deny rules and special endpoint gates apply first, and
matching raw-TCP deny rules additionally constrain the private transport without
requiring a raw-TCP allow rule. `tls.AllowLoopback()` adds only the TLS-scoped
loopback gate; raw TCP still requires its own TCP-scoped grant. Multicast and
limited broadcast remain unsupported TLS destinations even if advanced policy
mentions those endpoint classes.

TLS intentionally has no `tls/register` package or zero-configuration extension.
A self-registering package cannot safely invent trust roots, profile IDs,
verification identities, ALPN, or client credentials. Hosts must call
`tls.NewClientProfile` and `tls.Register` explicitly in Go composition.

## Nonblocking engine

`internal/backend/gotls` runs Go's `crypto/tls` client over a fixed-capacity
bridge. Each live TLS stream owns exactly three workers established at stream
construction: handshake, decrypted reader, and plaintext writer. Worker count is
therefore bounded by `MaxStreams`. Workers never retain guest memory. Guest calls
only copy to or from fixed plaintext rings and perform bounded private-transport
pumps; they never wait for network packets or worker completion.

Each pump is bounded by caller packet/byte/operation budgets and
`MaxRecordsPerService`. Handshakes additionally stop after
`MaxServiceAttemptsPerHandshake` or `MaxHandshakeBytes`. Ciphertext and
plaintext queues are fixed at registration. Close cancels the handshake, closes
the bridge, wakes every condition wait, joins all three workers, clears retained
plaintext, and aborts the private TCP stream without waiting for peer packets,
acknowledgements, or `close_notify`. Shared namespace teardown joins workers
before the private TCP participant releases transport state.

The current bounded bridge is intentionally granular-only and experimental. It
has a named standard-Go ordinary/race release check in `scripts/tls-signoff.sh`.
TinyGo 0.41.1 does not provide the `crypto/tls` client APIs required by the real
engine, so TLS is explicitly excluded there rather than replaced by a stub.
`scripts/tinygo-supported-test.sh` still tests all 123 supported packages and
compares the exact five-package standard-Go-only closure with the reviewed
manifest. TLS remains outside aggregate `register`; complete strict release and
executed arm64 evidence are still required before production readiness.

## ABI

`wago_net_tls` exports thirteen operations on the server-foundation branch:

- `namespace_default`
- `listen`
- `accept`
- `connect`
- `finish_connect`
- `read`
- `write`
- `shutdown_write`
- `connection_info`
- `connection_info_v2`
- `close`
- `close_listener`
- `poll`

`finish_connect` reports success only after TCP establishment, TLS handshake,
certificate-chain validation, DNS/IP identity validation, and required ALPN.
No plaintext is readable or writable before that point. `connection_info`
retains the exact client-era v1 byte contract: offset 68 is only the resumed
boolean 0 or 1. `connection_info_v2` additively reports resumed, local server
role, and peer-authenticated flags without reinterpreting v1. Both versions
return only bounded local/remote endpoints, TLS version, cipher-suite number,
negotiated ALPN (maximum 32 bytes), optional peer leaf SPKI SHA-256, and the
client-side verified server identity type. Arbitrary certificate DER is not
exported.

All input/output ranges are checked before backend work. Server-name bytes are
copied during the host call. Outputs remain unchanged on errors, would-block,
EOF, and invalid state. Handles are generation-, table-, instance-, and
kind-checked. Clean peer `close_notify` becomes level-triggered `EOF`; after
that transition repeated service calls report zero work and would-block rather
than repeatedly charging the already-known transport EOF. Raw TCP EOF without
`close_notify` and corrupted records become `TLS_PROTOCOL`.

## Default finite bounds

The default registration allows eight live streams and four concurrent
handshakes. Per stream it reserves 16 KiB receive and transmit plaintext, 32 KiB
receive and transmit ciphertext, and private TCP receive/transmit buffers of 32
KiB each. Fixed 32 KiB plaintext and 16 KiB ciphertext scratch are included in
the same checked per-stream accounting. Defaults also limit handshake bytes to
256 KiB, retained certificate chain bytes to 192 KiB, peer certificates to
eight, server names to 253 bytes, ALPN to eight protocols and 256 aggregate
bytes, handshake service attempts to 4096, and TLS pump work to sixteen
record-sized transport operations per call.

Registration rejects more than 64 streams or handshakes, any plaintext,
ciphertext, or private-transport queue above 1 MiB, handshake input above 4 MiB,
retained peer chains above 2 MiB, or a configuration whose checked possible
fixed retention exceeds 64 MiB. It also caps profiles, names per profile, peer
certificate count, ALPN dimensions, transport packet slots, and handshake
service attempts. Every field and combined allocation must fit target `int`;
all additions and the `MaxStreams` multiplication are checked in `uint64` before
backend construction, including simulated and actual 386 builds.

TLS resources, active handshakes, plaintext bytes, ciphertext bytes, global
retained bytes, and the underlying private TCP resource/storage are all charged
to the exact instance quota ledger. Every setup path rolls back both layers;
close and failed verification release each charge exactly once.

## Unsupported scope

There is no HTTP/HTTPS request API, DTLS, QUIC TLS, STARTTLS upgrade,
guest-handle wrapping, arbitrary guest TLS configuration, or session-ticket key
rotation. Server listeners and bounded inbound handshakes are available only
through explicit granular TLS registration and authority; they do not place TLS
in aggregate `register`. The certificate-validation clock is the cloned host
`tls.Config.Time` function when provided, otherwise Go's standard clock.
