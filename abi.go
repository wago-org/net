package net

import "github.com/wago-org/net/internal/abi"

// Stable ABI v1 fixed-width layout sizes. Guest structures use little-endian
// integers and network-order address bytes as documented in docs/abi-v1.md.
const (
	AddressV1Size          = abi.AddressV1Size
	HandleV1Size           = abi.HandleV1Size
	UDPReceiveResultV1Size = abi.UDPReceiveResultV1Size
	TCPStreamV1Size        = abi.TCPStreamV1Size
	TCPIOResultV1Size      = abi.TCPIOResultV1Size
	PollBudgetV1Size       = abi.PollBudgetV1Size
	PollEventV1Size        = abi.PollEventV1Size
	PollResultV1Size       = abi.PollResultV1Size

	UDPReceiveFlagTruncated = abi.UDPReceiveFlagTruncated
)
