<div align="center">
  <h1><code>net</code></h1>
  <p>Bounded, capability-gated networking for the <a href="https://github.com/wago-org/wago">Wago</a> WebAssembly runtime.</p>
</div>

<p align="center">
  <a href="https://github.com/wago-org/net/actions/workflows/ci.yml"><img src="https://github.com/wago-org/net/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/go-%3E%3D1.24-00ADD8.svg" alt="Go >= 1.24"></a>
  <a href="https://github.com/wago-org/wago"><img src="https://img.shields.io/badge/wago-%3E%3D0.1.0-6E56CF.svg" alt="Wago >= 0.1.0"></a>
</p>

`net` gives Wago guests checked TCP, UDP, DNS, ICMP, NTP, mDNS, DHCP, IPv4
link-local, IPv6, and outbound TLS. Each protocol is a separate plugin with its
own guest imports, authority, storage limits, and lifecycle.

The host chooses the network configuration and policy. Guests receive opaque,
generation-checked handles and bounded nonblocking operations. Every guest
pointer is checked, polling has finite work budgets, and closing an instance
releases all of its network state.

The first backend is [lneto](https://github.com/soypat/lneto). The guest ABI is
backend-neutral and documented in [docs/abi-v1.md](docs/abi-v1.md).

> [!WARNING]
> `net` is private and experimental (`v0.1.0`). The current release decision is
> blocked. Use it only with the exact Wago revision accepted by the repository's
> [release signoff](docs/release-signoff.md); the engine version alone does not
> identify a reviewed runtime lifecycle.

## Install

Install only the protocol package you need:

```sh
wago add github.com/wago-org/net/tcp
```

Or add the Go module directly:

```sh
go get github.com/wago-org/net
```

The root package publishes an all-protocol provider plus selective providers for
each manifest subpackage. Generated runtimes link explicit, side-effect-free
`/register` catalogs. Nothing self-registers through `init` or blank imports.

## Protocols

| Package | Guest module | Surface |
| --- | --- | --- |
| `tcp` | `wago_net_tcp` | Client streams, listeners, accept, partial I/O, half-close, and poll |
| `udp` | `wago_net_udp` | Bind, send, receive, close, and poll |
| `dns` | `wago_net_dns` | Bounded A/AAAA queries and copied A/AAAA/CNAME results |
| `icmpv4` | `wago_net_icmpv4` | Bounded IPv4 echo requests and exact reply validation |
| `ntp` | `wago_net_ntp` | Two-exchange synchronization against one server and an injected host clock |
| `mdns` | `wago_net_mdns` | Bounded `.local` A/PTR/SRV/TXT queries, responses, and announcements |
| `dhcpv4` | `wago_net_dhcpv4` | One bounded DORA lease and an optional finite server pool |
| `linklocal4` | `wago_net_linklocal4` | RFC 3927 claim, defense, release, and reconfiguration |
| `ipv6` | `wago_net_ipv6` | Static IPv6 configuration and IPv6 TCP enablement |
| `icmpv6` | `wago_net_icmpv6` | Bounded echo and Neighbor Solicitation/Advertisement operations |
| `dhcpv6` | `wago_net_dhcpv6` | Initial Solicit/Advertise/Request/Reply acquisition |
| `tls` | `wago_net_tls` | Outbound client TLS through finite host-defined profiles |

Every selected protocol also exposes the shared `wago_net.abi_version` import.
Unselected protocol imports stay absent and fail normal WebAssembly import
resolution.

The implementation is intentionally narrower than a host socket API. DNS is
UDP-only. IPv6 does not provide UDP, SLAAC, DAD, router discovery,
fragmentation, or extension headers. DHCPv6 implements initial acquisition, not
renewal or identity application. Privileged raw packet access is not exposed.

## Use a catalog provider

Each protocol has a small catalog package. A custom Wago runtime can link only
TCP like this:

```go
package main

import (
	"context"

	"github.com/wago-org/net/tcp/register"
	wago "github.com/wago-org/wago"
)

func loadTCP(ctx context.Context, runtime *wago.Runtime, selections []wago.PluginSelection) error {
	return runtime.LoadPlugins(ctx, wago.PluginSet{
		Providers:  register.Providers(),
		Selections: selections,
	})
}
```

The generated runtime normally supplies `selections` from `wago-lock.json`,
including the exact definition digest, authority grants, and configuration.
The root `github.com/wago-org/net/register` catalog contains the aggregate
provider and every published selective provider except TLS.

Zero-configuration catalog providers do not invent deployment identity. TCP
and UDP have finite client defaults, but DNS remains disabled until a resolver
is supplied, and IPv6 remains disabled until a static address is supplied.

## Compose a network

Use one deployment-owned provider when several protocols must share the same
instance network and policy:

```go
package network

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/dns"
	"github.com/wago-org/net/tcp"
	"github.com/wago-org/net/udp"
	wago "github.com/wago-org/wago"
)

func Provider(deploymentNetwork *wagonet.StaticIPv4Config) wago.PluginProvider {
	return wagonet.Provider(wagonet.ProviderSpec{
		ID:          "example.com/acme/runtime/network",
		Name:        "Acme runtime network",
		Description: "TCP, UDP, and DNS for the Acme guest",
		Modules: []string{
			wagonet.Module,
			wagonet.TCPModule,
			wagonet.UDPModule,
			wagonet.DNSModule,
		},
		Factory: func() (*wagonet.Network, error) {
			network := wagonet.New(
				wagonet.WithConfig(wagonet.Config{StaticIPv4: deploymentNetwork}),
			)
			if err := tcp.Register(network); err != nil {
				return nil, err
			}
			if err := udp.Register(network); err != nil {
				return nil, err
			}
			if err := dns.Register(network, dns.Resolver("192.0.2.53")); err != nil {
				return nil, err
			}
			return network, nil
		},
	})
}
```

Protocol packages configure their own finite storage and authority. Common
options include:

- `WithConfig(...)` for exact protocol storage and work limits.
- `WithPolicy(...)` for additional raw authority rules.
- `WithoutDefaultAuthority()` for a fully caller-authored policy.
- Explicit server, listener, loopback, multicast, broadcast, or privileged-bind
  grants where the protocol supports them.

Deny rules always win. Options such as `tcp.AllowAll()` and `udp.AllowAll()`
expand endpoint authority but never remove quotas or storage limits.

The aggregate compatibility constructor remains available as `compat.Init`,
but new code should prefer `wagonet.New` and register only the protocols it
uses.

## TLS

TLS is a granular client capability. It does not expose raw TCP and is not part
of the aggregate catalog because trust roots, verification identities, ALPN,
client credentials, and profile IDs belong to the deployment.

```go
profile, err := wagonettls.NewClientProfile(
	1,
	hostTLSConfig,
	wagonettls.AllowServerNames("api.example.com"),
	wagonettls.RequireALPN("h2"),
)
if err != nil {
	return err
}

if err := wagonettls.Register(network, wagonettls.WithClientProfile(profile)); err != nil {
	return err
}
```

The guest selects a host-defined profile ID, remote IP endpoint, and authorized
verification name. Certificate-chain and DNS/IP SAN verification are mandatory.
TLS 1.3 is the default; TLS 1.2 requires `EnableTLS12()`. See
[docs/tls.md](docs/tls.md) for the complete policy and ABI.

## Compose with other plugins

Networking provides the typed
`github.com/wago-org/net/service@1` contract as `wagonet.Contract`. Consumers
declare both a package requirement and a contract requirement, then acquire a
`*plugin.Ref[wagonet.Service]` with `plugin.Require`.

Calls stay inside `Ref.With`. `Service.ImportModules` returns a copy of the
selected guest-module topology, and `Service.Ready(caller)` checks only the
active synchronous guest caller. The contract never exposes a runtime,
instance, namespace, or resource handle.

Shutdown rejects new calls, drains calls already inside `Ref.With`, stops
consumers before the provider, and then closes every instance-owned network
resource.

## Test

```sh
go test ./...
go test -race -shuffle=on -count=1 ./...
go vet ./...
scripts/check-source-boundaries.sh
scripts/ci-checkptr.sh
scripts/ci-386.sh
```

The suite covers protocol operations, checked guest memory, quotas, polling,
policy, exact-instance teardown, selective dependency boundaries, and all 4096
protocol combinations. Benchmarks and their comparison workflow are documented
in [benchmarks/README.md](benchmarks/README.md).

Release candidates have a separate provenance and compatibility gate:

```sh
scripts/release-signoff.sh
```

That gate does not make the current release production-ready. Its exact inputs,
exceptions, and blockers are recorded in
[docs/release-signoff.md](docs/release-signoff.md).

## Architecture

- `net.go` owns shared composition, policy, quotas, readiness, and lifecycle.
- Protocol packages such as `tcp`, `udp`, and `dns` contribute only their own
  guest imports, authority, storage, and backend adapter.
- `internal/abi` contains fixed guest layouts and checked memory codecs.
- `internal/backend/lneto` contains the shared packet core and protocol
  adapters.
- `register` and the protocol-local `/register` packages expose explicit
  provider catalogs.

See [docs/architecture.md](docs/architecture.md) for the full design and
[docs/protocol-expansion.md](docs/protocol-expansion.md) for the rules a new
protocol must follow.

## Contributing

Run the test, race, vet, and source-boundary checks before opening a pull
request. Keep new guest operations bounded, capability-gated, checked at the
memory boundary, and tied to exact instance cleanup.

## License

This project is distributed under the [Apache License 2.0](LICENSE).

## Contact

File issues at [GitHub Issues](https://github.com/wago-org/net/issues), or join
the [Wago Discord](https://wago.sh/discord).
