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

Each `Extension` now owns a private instance-state manager. Runtime
instantiation attaches one resource table to the exact `*wago.Instance`; host
imports recover that identity through the additive `wago.InstanceHostModule`
interface, and `BeforeClose` removes the attachment before reverse-creation
resource cleanup. Failed later setup and `ResetReinstantiate` replacement use the
same close path. No process-global instance map is used. The low-level `Imports`
bundle remains suitable only for stateless core imports such as `abi_version`;
resource-owning protocol extensions require the Runtime lifecycle path.

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
