# Bounded TLS client and server capability

`github.com/wago-org/net/tls` is a separately selectable secure stream protocol
with outbound clients and explicitly authorized inbound listeners. It declares
`net.tls` and `wago_net_tls`; it does not declare `net.tcp` or install
`wago_net_tcp`. The lneto implementation privately owns internal TCP streams and
listeners, never publishes them in the guest resource table, and closes TLS and
TCP ownership exactly once.

## Public API and authority

Hosts construct immutable profiles with `NewClientProfile`, exact profile IDs,
`AllowServerNames`, optional `RequireALPN`, and an ordinary `*crypto/tls.Config`.
The configuration, roots, certificate DER, ALPN list, and name authority are
cloned. Later caller mutation cannot change registration. Client certificate
chains and leaf/key correspondence are parsed eagerly. Private keys stay in host
memory and no certificate chain or private key appears in the guest ABI.

The first release rejects `InsecureSkipVerify`, `KeyLogWriter`, renegotiation,
verification callbacks, certificate-selection callbacks, caller-supplied clock
callbacks, caller-supplied client session caches, and Encrypted ClientHello
callbacks/configuration. `ValidationTime` may install one immutable UTC-normalized
validation instant without retaining caller code; otherwise Go's standard system
clock is used. Hosts may explicitly add
`EnableClientSessionResumption(maxEntries, maxBytes)`. That option
creates a separate cache for every Wago instance, retains only serialized
standard-library session state under exact entry and byte bounds, reserves its
maximum against the instance queued-byte quota before allocation, and clears
retained tickets and state during deterministic teardown. Early-data state is
forced off and the guest ABI exposes no 0-RTT operation. TLS 1.3 is the default
minimum and maximum. TLS 1.2 is available only when the
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

Hosts construct server profiles with `NewServerProfile` and static certificate
chains. Every DER certificate is parsed during profile construction, each chain
link is signature-checked, and each leaf public key must match its private key.
Certificate DER, OCSP staples, SCTs, ALPN, and CA pools are cloned. Private keys
remain host-owned but are restricted to standard in-memory RSA, NIST ECDSA, and
Ed25519 implementations. Arbitrary `crypto.Signer` wrappers and HSM callbacks are
rejected because `crypto.Signer.Sign` has no cancellation contract and could
otherwise prevent deterministic worker teardown. Dynamic certificate/config
selection and verification callbacks are also rejected. Client SNI may select
only among the immutable static certificates supplied by the host; it cannot
select a new configuration or credential source. Server session tickets remain
disabled by default.
`EnableServerSessionTickets` accepts one to four explicit nonzero, unique
32-byte keys. The first key encrypts new stateless tickets and every supplied
key may decrypt, supporting bounded deployment rotation from `[new, old]` to
`[new]` without ambient key generation or mutable guest authority.

A stored server profile grants no endpoint authority. Hosts must separately opt
in with `tls.AllowListeners()` or supply explicit advanced inbound TLS policy.
That authority does not grant raw-TCP listen, and applicable raw-TCP inbound deny
rules continue to constrain the private listener. Listener handles and accepted
TLS streams remain kind-separated and finite.

TLS intentionally has no `tls/register` package or zero-configuration extension.
A self-registering package cannot safely invent trust roots, profile IDs,
verification identities, ALPN, server certificates, private keys, or listen
policy. Hosts must call profile constructors and `tls.Register` explicitly in Go
composition.

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
plaintext queues are fixed at registration. `shutdown_write` already provides
the graceful TLS stream path: it drains accepted plaintext and emits
`close_notify`, while peer `close_notify` becomes stable EOF. Resource `close`
remains the bounded abort path: it cancels the handshake, closes the bridge,
wakes every condition wait, joins all three workers, clears retained plaintext,
and aborts the private TCP stream without waiting for peer packets or
acknowledgements. Shared namespace teardown joins workers, clears any bounded
client resumption cache, and releases its quota before the private TCP
participant releases transport state.

The current bounded bridge is intentionally granular-only and experimental. It
has a named standard-Go ordinary/race release check in `scripts/tls-signoff.sh`.
TinyGo 0.41.1 does not provide the `crypto/tls` client APIs required by the real
engine, so TLS is explicitly excluded there rather than replaced by a stub.
`scripts/tinygo-supported-test.sh` still tests all 123 supported packages and
compares the exact five-package standard-Go-only closure with the reviewed
manifest. TLS remains outside aggregate `register`; complete strict release and
executed arm64 evidence are still required before production readiness.

## ABI

`wago_net_tls` exports fourteen operations on the standard-Go stream branch:

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
- `channel_binding`
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
exported. `channel_binding` additively returns the fixed 32-byte RFC 9266
`tls-exporter` channel binding after verified completion. Its label and length
are not guest-selectable, and it returns `AGAIN` without output mutation while
the handshake is incomplete.

All input/output ranges are checked before backend work. Server-name bytes are
copied during the host call. Outputs remain unchanged on errors, would-block,
EOF, and invalid state. Handles are generation-, table-, instance-, and
kind-checked. Clean peer `close_notify` becomes level-triggered `EOF`; after
that transition repeated service calls report zero work and would-block rather
than repeatedly charging the already-known transport EOF. Raw TCP EOF without
`close_notify` and corrupted records become `TLS_PROTOCOL`.

## Default finite bounds

The default registration allows eight live streams, four TLS listeners, an
accept backlog of four private TCP streams per listener, and four concurrent
handshakes. Listener authority is disabled until explicitly granted. Per stream
it reserves 16 KiB receive and transmit plaintext, 32 KiB
receive and transmit ciphertext, and private TCP receive/transmit buffers of 32
KiB each. Fixed 32 KiB plaintext and 16 KiB ciphertext scratch are included in
the same checked per-stream accounting. Defaults also limit handshake bytes to
256 KiB, retained certificate chain bytes to 192 KiB, peer certificates to
eight, server names to 253 bytes, ALPN to eight protocols and 256 aggregate
bytes, handshake service attempts to 4096, and TLS pump work to sixteen
record-sized transport operations per call. Session resumption is off by
default. When enabled, one client profile may retain at most 64 entries and 4
MiB of serialized state; all enabled profile caches together remain under the
64 MiB aggregate TLS retention ceiling. A server profile accepts at most four
ordered ticket keys.

Registration rejects more than 64 streams or handshakes, any plaintext,
ciphertext, or private-transport queue above 1 MiB, handshake input above 4 MiB,
retained peer chains above 2 MiB, or a configuration whose checked possible
fixed retention exceeds 64 MiB. It also caps profiles, names per profile, peer
certificate count, ALPN dimensions, transport packet slots, and handshake
service attempts. Every field and combined allocation must fit target `int`;
all additions and the `MaxStreams` multiplication are checked in `uint64` before
backend construction, including simulated and actual 386 builds.

TLS listener and stream resources, active handshakes, plaintext bytes,
ciphertext bytes, optional resumption-cache bytes, global retained bytes,
accept-backlog transport storage, and the underlying private TCP
resource/storage are all charged to the exact instance quota ledger. Cache
capacity is conservatively reserved before cache allocation. Every setup path
rolls back both layers; close and failed verification release each charge
exactly once.

## Unsupported scope

There is no HTTP/HTTPS request API, DTLS, QUIC TLS, STARTTLS upgrade,
guest-handle wrapping, arbitrary guest TLS configuration, live mutation of an
already registered profile, external/HSM signer callback, caller clock callback,
or 0-RTT. Certificate rotation uses immutable profiles/static SNI certificates
and listener replacement; session-ticket key rotation uses an ordered bounded
key set supplied when constructing a new immutable server profile. Server
listeners and bounded inbound handshakes are available only through explicit
granular TLS registration and authority; they do not place TLS in aggregate
`register`. Certificate validation uses the immutable `ValidationTime` option
when supplied, otherwise Go's standard system clock.
