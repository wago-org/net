package net

// Stable ABI v1 fixed-width layout sizes. Guest structures use little-endian
// integers and network-order address bytes as documented in docs/abi-v1.md.
//
// These public compatibility constants intentionally remain literal values so
// the protocol-neutral root package does not import protocol ABI packages.
const (
	AddressV1Size           uint32 = 32
	HandleV1Size            uint32 = 8
	UDPReceiveResultV1Size  uint32 = 48
	TCPStreamV1Size         uint32 = 72
	TCPIOResultV1Size       uint32 = 8
	TLSStreamV1Size         uint32 = 72
	TLSIOResultV1Size       uint32 = 8
	TLSConnectionInfoV1Size uint32 = 144
	TLSConnectionInfoV2Size uint32 = 144
	TLSMaxALPNV1Bytes       uint32 = 32

	TLSConnectionInfoV2FlagResumed           uint32 = 1 << 0
	TLSConnectionInfoV2FlagServerRole        uint32 = 1 << 1
	TLSConnectionInfoV2FlagPeerAuthenticated uint32 = 1 << 2
	DNSNameV1Size                            uint32 = 260
	DNSQueryV1Size                           uint32 = 268
	DNSRecordV1Size                          uint32 = 560
	ICMPv4EchoRequestV1Size                  uint32 = 48
	ICMPv4EchoResultV1Size                   uint32 = 48
	ICMPv6EchoRequestV1Size                  uint32 = 48
	ICMPv6EchoResultV1Size                   uint32 = 48
	ICMPv6NeighborKeyV1Size                  uint32 = 32
	ICMPv6NeighborV1Size                     uint32 = 40
	ICMPv6OperationsV1Size                   uint32 = 4
	DHCPv6OperationsV1Size                   uint32 = 4
	DHCPv6ConfigurationV1Size                uint32 = 3368
	NTPSampleV1Size                          uint32 = 72
	MDNSNameV1Size                           uint32 = 260
	MDNSQueryV1Size                          uint32 = 268
	MDNSRecordV1Size                         uint32 = 832
	MDNSAnnouncementV1Size                   uint32 = 8
	PollBudgetV1Size                         uint32 = 24
	PollEventV1Size                          uint32 = 16
	PollResultV1Size                         uint32 = 24

	UDPReceiveFlagTruncated uint32 = 1

	DNSRecordTypesA    uint32 = 1
	DNSRecordTypesAAAA uint32 = 2
	DNSRecordTypeA     uint32 = 1
	DNSRecordTypeAAAA  uint32 = 2
	DNSRecordTypeCNAME uint32 = 3

	MDNSRecordTypesA         uint32 = 1
	MDNSRecordTypesPTR       uint32 = 2
	MDNSRecordTypesSRV       uint32 = 4
	MDNSRecordTypesTXT       uint32 = 8
	MDNSRecordTypeA          uint32 = 1
	MDNSRecordTypePTR        uint32 = 2
	MDNSRecordTypeSRV        uint32 = 3
	MDNSRecordTypeTXT        uint32 = 4
	MDNSRecordFlagCacheFlush uint32 = 1

	ICMPv6OperationEcho            uint32 = 1
	ICMPv6OperationNeighborResolve uint32 = 2
	ICMPv6OperationNeighborLookup  uint32 = 4
	ICMPv6OperationNeighborSeed    uint32 = 8
	ICMPv6OperationNeighborRemove  uint32 = 16

	DHCPv6OperationAcquire uint32 = 1

	DHCPv6StartAcquire            uint32 = 1
	DHCPv6StartRenew              uint32 = 2
	DHCPv6StartRebind             uint32 = 3
	DHCPv6StartRelease            uint32 = 4
	DHCPv6StartDecline            uint32 = 5
	DHCPv6StartConfirm            uint32 = 6
	DHCPv6StartInformationRequest uint32 = 7
	DHCPv6StartReconfigure        uint32 = 8
	DHCPv6StartRapidCommit        uint32 = 9
	DHCPv6StartRelayAgent         uint32 = 10
	DHCPv6StartServer             uint32 = 11
	DHCPv6StartApplyIdentity      uint32 = 12
	DHCPv6StartRawPacket          uint32 = 13
)
