# Wago networking ABI v1

Status: **experimental**. Existing signatures and numeric values become immutable
only when ABI v1 is declared stable. Breaking changes before then must still be
recorded in the durable ledger and release notes.

## Version

`wago_net.abi_version() -> i32` returns `0x0001_0000`, encoding major version 1
and minor version 0.

Except for `abi_version`, networking imports return one `i32` status and write
additional values through checked guest-memory output pointers.

## Scalar conventions

- guest pointers and lengths: `i32`, interpreted as unsigned;
- opaque handles: `i64`; zero is invalid, and bit layout is not guest ABI;
- durations: `i64` nanoseconds;
- integer structure fields: little-endian;
- network address bytes: network byte order;
- reserved input fields must be zero;
- reserved output fields are written as zero.

## Address structure

`wago_net_addr_v1` is a fixed 32-byte structure:

```c
struct wago_net_addr_v1 {
    uint8_t  family;
    uint8_t  flags;
    uint16_t port;
    uint32_t scope_id;
    uint8_t  address[16];
    uint32_t flow_info;
    uint32_t reserved;
};
```

Family `1` is IPv4 and family `2` is IPv6. IPv4 uses the first four address
bytes and requires the remaining twelve bytes, `scope_id`, and `flow_info` to be
zero. IPv6 flow information is limited to its low 20 bits. A nonzero IPv6 scope
ID is accepted only for link-local unicast (`fe80::/10`) or multicast addresses.
IPv4-mapped IPv6 addresses are rejected; callers must select IPv4 explicitly.
ABI v1 defines no flag bits, so `flags` and `reserved` must be zero on input and
are zeroed on output. Wildcard, loopback, multicast, and broadcast addresses are
represented literally; authority to use them is enforced by operation policy,
not by the structural codec.

Memory ranges are checked with `uint64` pointer-plus-length arithmetic. A
zero-length range at the exact end of memory is valid. Output helpers validate
the complete range before mutation. Overlapping writes follow ordinary `copy`
semantics, and no guest-memory slice may be retained after a host call.

## Status values

| Value | Name |
|---:|---|
| 0 | `OK` |
| 1 | `AGAIN` |
| 2 | `IN_PROGRESS` |
| 3 | `EOF` |
| 4 | `ACCESS_DENIED` |
| 5 | `INVALID_ARGUMENT` |
| 6 | `BAD_HANDLE` |
| 7 | `INVALID_STATE` |
| 8 | `NOT_SUPPORTED` |
| 9 | `NO_MEMORY` |
| 10 | `RESOURCE_LIMIT` |
| 11 | `ADDRESS_IN_USE` |
| 12 | `ADDRESS_NOT_AVAILABLE` |
| 13 | `REMOTE_UNREACHABLE` |
| 14 | `CONNECTION_REFUSED` |
| 15 | `CONNECTION_RESET` |
| 16 | `CONNECTION_ABORTED` |
| 17 | `CONNECTION_BROKEN` |
| 18 | `TIMED_OUT` |
| 19 | `MESSAGE_TOO_LARGE` |
| 20 | `NAME_NOT_FOUND` |
| 21 | `TEMPORARY_FAILURE` |
| 22 | `IO` |
| 23 | `CANCELED` |
| 24 | `OTHER` |

Unknown backend or Go errors map to a stable status, normally `OTHER` or `IO`.
Unstable Go error strings are not returned to guests.

Resource handles are scoped to one runtime instance and checked against an exact
resource kind. Closing a resource invalidates its handle before backend cleanup;
slot reuse advances a generation, and generation exhaustion retires the slot.
Handles from another instance, stale handles, wrong-kind handles, zero, and
malformed values return `BAD_HANDLE`. Guests must not derive or inspect handle
bits.

## Compatibility boundary

This is a Wago-specific core Wasm ABI. It is not a WASI Component Model or WIT
resource ABI, even where operation semantics are intentionally similar.
