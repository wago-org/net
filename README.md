# Wago Networking

Capability-gated networking plugins for the [Wago](https://github.com/wago-org/wago)
WebAssembly runtime, backed initially by [lneto](https://github.com/soypat/lneto).

The repository now exposes the experimental `wago_net.abi_version` core import
and a separately capability-gated `wago_net_udp` module for discovery of one
configured namespace plus nonblocking UDP bind, send, receive, and close. The
stable numeric status taxonomy and fixed v1 address/receive layouts use central
checked guest memory; exact instance identity, generation/kind-checked handles,
immutable endpoint policy, finite quotas, and deterministic lifecycle cleanup
remain mandatory on every guest operation. The lneto backend uses adapter-owned
fixed UDP queues and immediate frame codecs, preserving empty and truncated
datagrams without blocking or backoff. Guest polling is level-triggered and
bounded independently by scans, event outputs, namespace service attempts, and
per-attempt packet/byte/operation budgets; each call transactionally reserves and
releases finite per-instance service-work quota. Immediate lneto TCP listeners,
connect/accept, partial stream I/O, half-close, policy/quota ownership, readiness,
and deterministic teardown are implemented internally, and the checked v1 TCP
layouts are fixed; `wago_net_tcp` remains deliberately absent until every guest
binding is hardened. DNS and privileged packet access remain absent and
truthfully unsupported.

```go
rt := wago.NewRuntime()
if err := rt.Use(wagonet.Init(wagonet.Config{})); err != nil {
    return err
}

// A configured deployment can instead provide immutable policy, finite quota,
// readiness, packet-link, static IPv4, UDP queue, and internal TCP settings. Each Runtime
// instance then receives its own isolated namespace and generation-safe handles.
```

Networking extensions currently require ordinary Runtime instances or classes
using `wago.ResetReinstantiate`. Do not use `wago.ResetMemorySnapshot`: Wago does
not yet notify extensions when a physical instance is reset between leases.

Custom Wago binaries can include the plugin through its self-registering package:

```go
import _ "github.com/wago-org/net/register"
```

The guest ABI is custom to Wago. It may follow WASI socket semantics where useful,
but it is not binary-compatible with WASI Component Model resources.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
```

Long-running implementation work follows `.pi/skills/recursive-handoff/SKILL.md`
and the current durable state in `agent-todo.md`.

## License

Apache-2.0.
