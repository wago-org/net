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
- opaque handles: `i64`;
- durations: `i64` nanoseconds;
- integer structure fields: little-endian;
- network address bytes: network byte order;
- reserved input fields must be zero;
- reserved output fields are written as zero.

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

## Compatibility boundary

This is a Wago-specific core Wasm ABI. It is not a WASI Component Model or WIT
resource ABI, even where operation semantics are intentionally similar.
