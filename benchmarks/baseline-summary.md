# Baseline summary

This summary is derived from `benchmarks/baseline.txt`. Values are medians of three 100 ms samples with `GOMAXPROCS=1` on Go 1.24.4, Linux/amd64, AMD Ryzen 7 8845HS.

| Package | Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|---:|
| `.` | `BenchmarkGuestDNSPoll` | 94.3 | 0 | 0 |
| `.` | `BenchmarkGuestUDPPoll` | 116.3 | 0 | 0 |
| `.` | `BenchmarkGuestTCPPoll` | 112.5 | 0 | 0 |
| `/internal/abi/core` | `BenchmarkSlice` | 1.718 | 0 | 0 |
| `/internal/abi/core` | `BenchmarkWrite` | 8.590 | 0 | 0 |
| `/internal/abi/core` | `BenchmarkZero` | 8.320 | 0 | 0 |
| `/internal/abi/core` | `BenchmarkReadUint32LE` | 1.280 | 0 | 0 |
| `/internal/abi/core` | `BenchmarkWriteUint32LE` | 1.484 | 0 | 0 |
| `/internal/abi/core` | `BenchmarkCheckRanges` | 5.377 | 0 | 0 |
| `/internal/abi/core` | `BenchmarkElements` | 1.913 | 0 | 0 |
| `/internal/abi/core` | `BenchmarkEncodeAddressV1` | 11.7 | 0 | 0 |
| `/internal/abi/core` | `BenchmarkDecodeAddressV1` | 22.4 | 0 | 0 |
| `/internal/abi/core` | `BenchmarkEncodeEndpointV1` | 23.6 | 0 | 0 |
| `/internal/abi/core` | `BenchmarkDecodeEndpointV1` | 39.9 | 0 | 0 |
| `/internal/abi/core` | `BenchmarkEncodeHandleV1` | 1.490 | 0 | 0 |
| `/internal/abi/core` | `BenchmarkDecodePollBudgetV1` | 2.541 | 0 | 0 |
| `/internal/abi/core` | `BenchmarkEncodePollEventsV1/events=1` | 5.268 | 0 | 0 |
| `/internal/abi/core` | `BenchmarkEncodePollEventsV1/events=16` | 26.9 | 0 | 0 |
| `/internal/abi/core` | `BenchmarkEncodePollEventsV1/events=256` | 411.8 | 0 | 0 |
| `/internal/abi/core` | `BenchmarkEncodePollResultV1` | 8.640 | 0 | 0 |
| `/internal/abi/dns` | `BenchmarkEncodeDNSNameV1` | 99.0 | 112 | 2 |
| `/internal/abi/dns` | `BenchmarkDecodeDNSNameV1` | 155.3 | 136 | 3 |
| `/internal/abi/dns` | `BenchmarkEncodeDNSQueryV1` | 205.6 | 224 | 4 |
| `/internal/abi/dns` | `BenchmarkDecodeDNSQueryV1` | 249.2 | 248 | 5 |
| `/internal/abi/dns` | `BenchmarkCheckDNSResolveV1` | 3.643 | 0 | 0 |
| `/internal/abi/dns` | `BenchmarkEncodeDNSRecordV1/A` | 215.8 | 224 | 4 |
| `/internal/abi/dns` | `BenchmarkEncodeDNSRecordV1/AAAA` | 224.0 | 224 | 4 |
| `/internal/abi/dns` | `BenchmarkEncodeDNSRecordV1/CNAME` | 381.7 | 416 | 8 |
| `/internal/abi/tcp` | `BenchmarkCheckListenV1` | 3.690 | 0 | 0 |
| `/internal/abi/tcp` | `BenchmarkCheckCreateV1` | 3.609 | 0 | 0 |
| `/internal/abi/tcp` | `BenchmarkCheckIOV1` | 3.666 | 0 | 0 |
| `/internal/abi/tcp` | `BenchmarkEncodeStreamV1` | 42.4 | 0 | 0 |
| `/internal/abi/tcp` | `BenchmarkEncodeIOResultV1` | 4.912 | 0 | 0 |
| `/internal/abi/udp` | `BenchmarkEncodeReceiveResultV1` | 28.8 | 0 | 0 |
| `/internal/abi/udp` | `BenchmarkValidReceiveFlagsV1` | 1.242 | 0 | 0 |
| `/internal/backend/lneto/core` | `BenchmarkNamespaceReadiness` | 17.0 | 0 | 0 |
| `/internal/backend/lneto/core` | `BenchmarkUDPPortLeaseAcquireRelease` | 52.2 | 16 | 1 |
| `/internal/backend/lneto/core` | `BenchmarkUDPPortLeaseRangeAcquireRelease` | 53.0 | 16 | 1 |
| `/internal/backend/lneto/core` | `BenchmarkNamespaceTryServiceIdle` | 65.5 | 0 | 0 |
| `/internal/backend/lneto/core` | `BenchmarkNamespaceTryServiceIngress` | 43.0 | 0 | 0 |
| `/internal/backend/lneto/core` | `BenchmarkNamespaceTryServiceEgress` | 63.7 | 0 | 0 |
| `/internal/backend/lneto/dns` | `BenchmarkBuildDNSQueryPacket` | 158.2 | 152 | 4 |
| `/internal/backend/lneto/dns` | `BenchmarkDecodeDNSName` | 96.2 | 56 | 5 |
| `/internal/backend/lneto/dns` | `BenchmarkParseDNSResponse` | 1096 | 1048 | 37 |
| `/internal/backend/lneto/dns` | `BenchmarkSelectDNSAnswers` | 445.7 | 592 | 9 |
| `/internal/backend/lneto/dns` | `BenchmarkAdapterTryResolveClose` | 837.7 | 1072 | 17 |
| `/internal/backend/lneto/dns` | `BenchmarkQueryTryNext` | 90.6 | 80 | 2 |
| `/internal/backend/lneto/dns` | `BenchmarkQueryReadiness` | 4.065 | 0 | 0 |
| `/internal/backend/lneto/tcp` | `BenchmarkAdapterTryListenClose` | 533.0 | 1792 | 11 |
| `/internal/backend/lneto/tcp` | `BenchmarkTCPStreamFinishConnect` | 5.414 | 0 | 0 |
| `/internal/backend/lneto/tcp` | `BenchmarkTCPStreamReadiness` | 13.4 | 0 | 0 |
| `/internal/backend/lneto/tcp` | `BenchmarkTCPListenerTryAcceptWouldBlock` | 22.2 | 0 | 0 |
| `/internal/backend/lneto/tcp` | `BenchmarkTCPStreamRoundTrip` | 1327 | 0 | 0 |
| `/internal/backend/lneto/udp` | `BenchmarkAdapterTryBindClose` | 425.4 | 832 | 12 |
| `/internal/backend/lneto/udp` | `BenchmarkUDPSocketSendEgress` | 146.9 | 0 | 0 |
| `/internal/backend/lneto/udp` | `BenchmarkUDPSocketReceive` | 34.1 | 0 | 0 |
| `/internal/backend/lneto/udp` | `BenchmarkUDPSocketReadiness` | 4.437 | 0 | 0 |
| `/internal/backend/lneto/udp` | `BenchmarkUDPDatagramQueueRoundTrip` | 20.1 | 0 | 0 |
| `/internal/guest` | `BenchmarkFromProgress` | 1.242 | 0 | 0 |
| `/internal/guest` | `BenchmarkFromIOResult` | 1.682 | 0 | 0 |
| `/internal/guest` | `BenchmarkFromError/semantic` | 48.9 | 8 | 1 |
| `/internal/guest` | `BenchmarkFromError/shared` | 50.6 | 8 | 1 |
| `/internal/instance/core` | `BenchmarkManagerAttachDetach` | 1248 | 18152 | 12 |
| `/internal/instance/core` | `BenchmarkManagerForInstance` | 4.023 | 0 | 0 |
| `/internal/instance/core` | `BenchmarkStateWithLock` | 4.697 | 0 | 0 |
| `/internal/instance/core` | `BenchmarkStatePollIdle` | 25.8 | 0 | 0 |
| `/internal/instance/dns` | `BenchmarkResolveClose` | 87.0 | 0 | 0 |
| `/internal/instance/dns` | `BenchmarkNext` | 135.1 | 112 | 2 |
| `/internal/instance/dns` | `BenchmarkCancel` | 15.7 | 0 | 0 |
| `/internal/instance/tcp` | `BenchmarkConnectClose` | 81.5 | 0 | 0 |
| `/internal/instance/tcp` | `BenchmarkEndpoints` | 44.0 | 0 | 0 |
| `/internal/instance/tcp` | `BenchmarkFinishConnect` | 14.4 | 0 | 0 |
| `/internal/instance/tcp` | `BenchmarkRead` | 16.8 | 0 | 0 |
| `/internal/instance/tcp` | `BenchmarkWrite` | 16.9 | 0 | 0 |
| `/internal/instance/tcp` | `BenchmarkShutdownWrite` | 14.4 | 0 | 0 |
| `/internal/instance/udp` | `BenchmarkBindClose` | 81.0 | 0 | 0 |
| `/internal/instance/udp` | `BenchmarkSend` | 17.4 | 0 | 0 |
| `/internal/instance/udp` | `BenchmarkReceive` | 28.6 | 0 | 0 |
| `/internal/namespace/core` | `BenchmarkEndpointValid` | 2.131 | 0 | 0 |
| `/internal/namespace/core` | `BenchmarkIOResultValid` | 1.686 | 0 | 0 |
| `/internal/namespace/core` | `BenchmarkReadinessValid` | 1.243 | 0 | 0 |
| `/internal/namespace/core` | `BenchmarkServiceReportValidResult` | 1.707 | 0 | 0 |
| `/internal/namespace/core` | `BenchmarkResolveNamespaceService` | 8.930 | 0 | 0 |
| `/internal/namespace/core` | `BenchmarkResolveNamespaceBase` | 4.171 | 0 | 0 |
| `/internal/namespace/dns` | `BenchmarkRequestValid` | 93.3 | 112 | 2 |
| `/internal/namespace/dns` | `BenchmarkRecordValid` | 93.5 | 112 | 2 |
| `/internal/packetlink` | `BenchmarkLinkTryEnqueueDequeue/bytes=64` | 24.6 | 0 | 0 |
| `/internal/packetlink` | `BenchmarkLinkTryEnqueueDequeue/bytes=512` | 34.0 | 0 | 0 |
| `/internal/packetlink` | `BenchmarkLinkTryEnqueueDequeue/bytes=1514` | 49.0 | 0 | 0 |
| `/internal/packetlink` | `BenchmarkLinkTryFillDequeue` | 37.0 | 0 | 0 |
| `/internal/packetlink` | `BenchmarkLinkSnapshot` | 11.8 | 0 | 0 |
| `/internal/policy` | `BenchmarkMerge` | 421.7 | 1136 | 16 |
| `/internal/policy` | `BenchmarkCompile` | 587.6 | 792 | 17 |
| `/internal/policy` | `BenchmarkPolicyCheckEndpoint` | 33.2 | 0 | 0 |
| `/internal/policy` | `BenchmarkPolicyCheckDNS` | 134.7 | 112 | 2 |
| `/internal/quota` | `BenchmarkReserveResourceRollback` | 44.0 | 80 | 1 |
| `/internal/quota` | `BenchmarkReserveResourceCommitRelease` | 60.6 | 88 | 2 |
| `/internal/quota` | `BenchmarkWithService` | 20.9 | 0 | 0 |
| `/internal/quota` | `BenchmarkSnapshot` | 11.7 | 0 | 0 |
| `/internal/readiness` | `BenchmarkCoordinatorRegisterUnregister` | 36.4 | 0 | 0 |
| `/internal/readiness` | `BenchmarkCoordinatorTryPoll/registrations=1` | 27.5 | 0 | 0 |
| `/internal/readiness` | `BenchmarkCoordinatorTryPoll/registrations=16` | 177.8 | 0 | 0 |
| `/internal/readiness` | `BenchmarkCoordinatorTryPoll/registrations=256` | 2608 | 0 | 0 |
| `/internal/readiness` | `BenchmarkCoordinatorTryPollService` | 27.5 | 0 | 0 |
| `/internal/resource` | `BenchmarkNewTable` | 22.3 | 64 | 1 |
| `/internal/resource` | `BenchmarkTableAddCloseHandle` | 12.3 | 0 | 0 |
| `/internal/resource` | `BenchmarkTableLen` | 3.999 | 0 | 0 |
| `/internal/resource` | `BenchmarkMakeHandle` | 1.256 | 0 | 0 |
| `/internal/resource` | `BenchmarkSplitHandle` | 1.483 | 0 | 0 |
| `/internal/resource` | `BenchmarkTableLookupBadHandle` | 5.348 | 0 | 0 |
| `/internal/resource` | `BenchmarkTableLookup` | 5.978 | 0 | 0 |
| `/internal/resource` | `BenchmarkTableCloseLive/resources=1` | 199.2 | 176 | 4 |
| `/internal/resource` | `BenchmarkTableCloseLive/resources=64` | 3014 | 10080 | 73 |
| `/internal/resource` | `BenchmarkTableCloseLive/resources=1024` | 44362 | 157408 | 1037 |

## Initial findings

- The steady-state shared ABI, resource lookup/reuse, quota scoped charge, readiness polling, packet-link, UDP data plane, TCP data plane, and guest poll paths are allocation-free in this baseline.
- The live in-memory TCP 64-byte round trip is about 1.33 µs and 0 allocations; UDP send plus frame egress is about 147 ns and 0 allocations.
- DNS is the largest optimization surface: response parsing is about 1.10 µs with 1,048 B and 37 allocations; answer selection is about 0.45 µs with 592 B and 9 allocations.
- DNS name/request/record validation and DNS policy checks currently allocate because normalization/validation builds temporary strings or label slices. This also appears in DNS ABI encoding/decoding and record iteration.
- UDP port lease creation allocates one 16-byte lease object per acquisition. Resource/quota creation paths allocate by design, while reuse and scoped service paths do not.
- `guest.FromError` allocates 8 B once per mapped error in this baseline; simple progress and I/O-result status mapping are allocation-free.

Treat sub-10 ns results as compiler- and CPU-sensitive. Use the raw multi-sample file and `benchstat` for regression decisions rather than comparing a single rounded number.
