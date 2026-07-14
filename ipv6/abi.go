package ipv6

import ipv6abi "github.com/wago-org/net/internal/abi/ipv6"

const (
	ConfigurationV1Size        = ipv6abi.ConfigurationV1Size
	ConfigurationFlagEnabled   = ipv6abi.ConfigurationFlagEnabled
	ConfigurationFlagLinkLocal = ipv6abi.ConfigurationFlagLinkLocal
	TransportFlagTCPConnect    = uint32(1 << 0)
	TransportFlagTCPListen     = uint32(1 << 1)
)
