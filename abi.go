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
	DNSNameV1Size           uint32 = 260
	DNSQueryV1Size          uint32 = 268
	DNSRecordV1Size         uint32 = 560
	ICMPv4EchoRequestV1Size uint32 = 48
	ICMPv4EchoResultV1Size  uint32 = 48
	NTPSampleV1Size         uint32 = 72
	MDNSNameV1Size          uint32 = 260
	MDNSQueryV1Size         uint32 = 268
	MDNSRecordV1Size        uint32 = 832
	MDNSAnnouncementV1Size  uint32 = 8
	PollBudgetV1Size        uint32 = 24
	PollEventV1Size         uint32 = 16
	PollResultV1Size        uint32 = 24

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
)
