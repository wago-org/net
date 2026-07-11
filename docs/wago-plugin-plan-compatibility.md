# Wago plugin-plan compatibility audit

This audit compares networking's exact Wago prerequisite
`97e6f91e6c822491577faa86f3c30aa5a8fff1e8` with the fetched
`origin/plugin-improvements` snapshot
`07a70b58ff26d2c8c49b5f879e7733cb375ec13f`. The latter includes current Wago
main as observed at `7794acc82692aac4ff98756a46a017d0d8768087` and retains the
reviewed worker parent `ffd5ef4`, but it does not contain the exact networking
merge.

Run the executable evidence check after fetching Wago refs:

```sh
git -C .audit/wago fetch --all --prune
REQUIRE_CURRENT_PLUGIN_PLAN=1 scripts/wago-plugin-plan-compat.sh
```

Without `REQUIRE_CURRENT_PLUGIN_PLAN=1`, the script audits the exact reviewed
objects and reports later movement of the remote-tracking heads. This makes the
committed release gate reproducible while ensuring a new moving-head review is
an explicit operation.

## Compatibility matrix

| Networking requirement | `97e6f91` | `07a70b5` | Decision |
|---|---|---|---|
| Runtime-owned before/after close hooks | Present | Present through the capability-scoped lifecycle API | Retained concept, registration migration required |
| Exact synchronous caller identity | Public optional `InstanceHostModule` | Private scoped host module, resolved through `InstanceManager.Caller` | Source-incompatible; a least-authority public resolver is required |
| Reset safety for extension-owned state | `Registry.RequireReinstantiation` dynamically prevents pooled reuse | `RequireReinstantiation`, `Class`, and pool implementation removed | No drop-in API; prove all replacement ownership paths physically close instances |
| Worker lifecycle and finite queues | Reviewed `Workers`, worker origins, linked-parent close, and worker tests | Worker API/tests removed; generic `ManagedInstance` ownership introduced | Semantic migration and new networking tests required |
| Close-hook panic isolation | Hook panics are converted to errors and cannot skip later hooks or resource release | Close hooks are invoked directly; the reviewed panic-isolated runner is absent | Blocking regression for deterministic networking cleanup |
| Declarative plugin authority | No plugin-plan grant layer | `PluginPlan`, explicit host/lifecycle/manage capabilities, budgets, services | Desirable, but manifests and registration must declare exact powers |
| Exact networking merge topology | Exact two-parent merge | Not an ancestor | Cannot replace immutable publication of `97e6f91` |

The current networking production source depends directly on two APIs absent
from the redesign: `Registry.RequireReinstantiation` in `net.go` and
`InstanceHostModule` in `internal/instance/core/manager.go`. It therefore does not
compile unchanged against `07a70b5`. More importantly, source adaptation alone
would be insufficient because the redesign removed the reviewed worker/class
model and currently lacks the close-hook panic containment that ensures one
extension cannot prevent networking teardown.

## Migration decision

**Do not move or rewrite the Wago pin.** Publish `97e6f91` unchanged at an
immutable fetchable ref first. Treat plugin-plan integration as a separate Wago
and networking migration with its own reviewed merge and pin update.

A valid migration must provide all of the following before networking can adopt
it:

1. a public, least-authority way for an ordinary host import to resolve the exact
   active `*wago.Instance` without exposing runtime internals or retaining caller
   authority beyond the synchronous call;
2. panic-isolated before/after close execution that continues deterministic
   cleanup, preserves reverse order and shared metadata, and reports failures;
3. proof that every direct and managed ownership path closes extension-owned
   state exactly once, with no snapshot/class/managed reuse path bypassing close;
4. capability declarations for host imports and instance lifecycle, without
   requesting `instance.manage` merely to recover ordinary caller identity;
5. replacements for the linked worker tests covering exact child identity,
   parent/child close ordering, finite ownership, callback failure rollback, and
   UDP/TCP/DNS state retirement; and
6. standard Go, race, TinyGo, package inspection, and full networking release
   signoff against the resulting immutable Wago revision.

`InstanceManager.Caller` is useful evidence that the redesign has an expiring
exact-caller primitive, but requiring the networking plugin to own a managed
instance service solely for identity would over-grant authority. Networking
should request only host-import and lifecycle powers unless it actually creates
managed guest instances.

This compatibility audit does not claim the redesign is generally defective; it
records that the reviewed snapshot is not yet a production-compatible substitute
for networking's narrower, already-tested lifecycle/identity/worker contract.
