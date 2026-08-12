# Wago vNext plugin compatibility

The earlier plugin-plan compatibility audit is superseded by the breaking vNext
plugin migration. Networking now targets the explicit-provider API in the Wago
revision selected by `go.mod`; the old production pin is not API-compatible and
must not be used to build this branch.

## Required Wago surface

Networking depends on these narrow integration seams:

- `PluginProvider`, immutable `PluginDefinition`, and transactional `Registrar`;
- `host.import.define` grants scoped to `wago_net` and the selected protocol
  modules only;
- `host.caller.identify` through an expiring `CallerResolver`;
- `instance.instantiate.intercept` to attach exact-instance state after identity
  exists and before guest start;
- `instance.close.observe` to unpublish and close that state;
- typed Contracts and callback-scoped `plugin.Ref.With`; and
- graph validation for explicit requirements, definition digests, Authority
  Grants, configuration, and Contract bindings.

Networking does not request instance-management authority and never receives a
raw Runtime or Instance through an observation callback. The opaque identity
used by instantiate, synchronous caller resolution, and close is the sole key
for production state. Repository-local unit fixtures retain a separate direct
pointer path that is not wired into plugin registration.

## Executable check

Run:

```sh
WAGO_DIR=/path/to/exact/wago scripts/wago-plugin-plan-compat.sh
```

The check validates the exact vNext symbols in the selected Wago source and the
matching networking registrations. It does not fetch refs, accept a moving
branch, or reinterpret an older manifest/API as vNext.

Compatibility is established only together with standard tests, race tests,
`go vet`, strict v1 manifest validation, explicit catalog inspection, exact
Authority-scope tests, provider-to-consumer Contract tests, in-flight shutdown,
revocation, and instance attach/detach rollback.
