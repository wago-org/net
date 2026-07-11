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

No networking resources or backend are attached yet. Wago main at revision
`8ef17eeb3a74f4982ef64d125282c1dab8c8e240` lacks an instance-close hook. The
companion Wago branch `net/instance-close-hooks` adds a zero-footprint
`BeforeClose` hook in commit `dd82ec9a8963463e6516bf803bec58b3a89b89b3`;
resource-owning imports remain blocked until that change is integrated into the
Wago dependency used by this module.
