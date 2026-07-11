# Wago Networking

Capability-gated networking plugins for the [Wago](https://github.com/wago-org/wago)
WebAssembly runtime, backed initially by [lneto](https://github.com/soypat/lneto).

The repository is in its ABI-foundation phase. The implemented surface is the
experimental `wago_net.abi_version` import and the stable numeric status taxonomy.
TCP, UDP, DNS, polling, namespace backends, and privileged packet access are not
yet implemented and are not advertised as available.

```go
rt := wago.NewRuntime()
if err := rt.Use(wagonet.Init(wagonet.Config{})); err != nil {
    return err
}
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
