// Package dhcpv6 contains fixed-width checked DHCPv6 guest ABI codecs.
package dhcpv6

import (
	"encoding/binary"

	abicore "github.com/wago-org/net/internal/abi/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv6"
)

const (
	OperationsV1Size    uint32 = 4
	ConfigurationV1Size uint32 = 3368
	NameV1Size          uint32 = 260
	PrefixV1Size        uint32 = 48

	offsetTransaction       = 0
	offsetIAID              = 4
	offsetAssigned          = 8
	offsetServer            = 40
	offsetServerDUIDLength  = 72
	offsetDNSCount          = 76
	offsetDomainCount       = 80
	offsetNTPCount          = 84
	offsetNTPMulticastCount = 88
	offsetNTPNameCount      = 92
	offsetPrefixCount       = 96
	offsetReserved          = 100
	offsetRenewal           = 104
	offsetRebinding         = 108
	offsetPreferred         = 112
	offsetValid             = 116
	offsetPrefixRenewal     = 120
	offsetPrefixRebinding   = 124
	offsetServerDUID        = 128
	offsetDNS               = 256
	offsetDomains           = 384
	offsetNTP               = 1944
	offsetNTPMulticast      = 2072
	offsetNTPNames          = 2136
	offsetPrefixes          = 3176
)

func EncodeOperationsV1(memory []byte, ptr uint32, operations dhcpns.Operations) bool {
	if operations&^dhcpns.SupportedOperations != 0 {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, OperationsV1Size)
	if !ok {
		return false
	}
	binary.LittleEndian.PutUint32(output, uint32(operations))
	return true
}

func EncodeConfigurationV1(memory []byte, ptr uint32, configuration dhcpns.Configuration) bool {
	if !configuration.Valid() {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, ConfigurationV1Size)
	if !ok {
		return false
	}
	var encoded [ConfigurationV1Size]byte
	binary.LittleEndian.PutUint32(encoded[offsetTransaction:offsetTransaction+4], configuration.TransactionID)
	copy(encoded[offsetIAID:offsetIAID+4], configuration.IAID[:])
	if !abicore.EncodeEndpointV1(encoded[:], offsetAssigned, nscore.Endpoint{Address: configuration.AssignedAddr}) ||
		!abicore.EncodeEndpointV1(encoded[:], offsetServer, nscore.Endpoint{Address: configuration.ServerAddr, ScopeID: configuration.ServerScopeID}) {
		return false
	}
	binary.LittleEndian.PutUint32(encoded[offsetServerDUIDLength:offsetServerDUIDLength+4], uint32(configuration.ServerDUIDLength))
	binary.LittleEndian.PutUint32(encoded[offsetDNSCount:offsetDNSCount+4], uint32(configuration.DNSCount))
	binary.LittleEndian.PutUint32(encoded[offsetDomainCount:offsetDomainCount+4], uint32(configuration.DomainCount))
	binary.LittleEndian.PutUint32(encoded[offsetNTPCount:offsetNTPCount+4], uint32(configuration.NTPCount))
	binary.LittleEndian.PutUint32(encoded[offsetNTPMulticastCount:offsetNTPMulticastCount+4], uint32(configuration.NTPMulticastCount))
	binary.LittleEndian.PutUint32(encoded[offsetNTPNameCount:offsetNTPNameCount+4], uint32(configuration.NTPNameCount))
	binary.LittleEndian.PutUint32(encoded[offsetPrefixCount:offsetPrefixCount+4], uint32(configuration.PrefixCount))
	binary.LittleEndian.PutUint32(encoded[offsetRenewal:offsetRenewal+4], configuration.RenewalSeconds)
	binary.LittleEndian.PutUint32(encoded[offsetRebinding:offsetRebinding+4], configuration.RebindingSeconds)
	binary.LittleEndian.PutUint32(encoded[offsetPreferred:offsetPreferred+4], configuration.PreferredLifetimeSeconds)
	binary.LittleEndian.PutUint32(encoded[offsetValid:offsetValid+4], configuration.ValidLifetimeSeconds)
	binary.LittleEndian.PutUint32(encoded[offsetPrefixRenewal:offsetPrefixRenewal+4], configuration.PrefixRenewalSeconds)
	binary.LittleEndian.PutUint32(encoded[offsetPrefixRebinding:offsetPrefixRebinding+4], configuration.PrefixRebindingSeconds)
	copy(encoded[offsetServerDUID:offsetServerDUID+dhcpns.MaxServerDUIDBytes], configuration.ServerDUID[:])
	for i := range configuration.DNSServers {
		if configuration.DNSServers[i].IsValid() && !abicore.EncodeEndpointV1(encoded[:], offsetDNS+uint32(i)*abicore.AddressV1Size, nscore.Endpoint{Address: configuration.DNSServers[i]}) {
			return false
		}
	}
	for i := range configuration.DomainSearch {
		if configuration.DomainSearch[i] != (dhcpns.Name{}) && !encodeName(encoded[:], offsetDomains+uint32(i)*NameV1Size, configuration.DomainSearch[i]) {
			return false
		}
	}
	for i := range configuration.NTPServers {
		if configuration.NTPServers[i].IsValid() && !abicore.EncodeEndpointV1(encoded[:], offsetNTP+uint32(i)*abicore.AddressV1Size, nscore.Endpoint{Address: configuration.NTPServers[i]}) {
			return false
		}
	}
	for i := range configuration.NTPMulticastServers {
		if configuration.NTPMulticastServers[i].IsValid() && !abicore.EncodeEndpointV1(encoded[:], offsetNTPMulticast+uint32(i)*abicore.AddressV1Size, nscore.Endpoint{Address: configuration.NTPMulticastServers[i]}) {
			return false
		}
	}
	for i := range configuration.NTPServerNames {
		if configuration.NTPServerNames[i] != (dhcpns.Name{}) && !encodeName(encoded[:], offsetNTPNames+uint32(i)*NameV1Size, configuration.NTPServerNames[i]) {
			return false
		}
	}
	for i, prefix := range configuration.DelegatedPrefixes {
		if prefix == (dhcpns.DelegatedPrefix{}) {
			continue
		}
		offset := offsetPrefixes + uint32(i)*PrefixV1Size
		if !abicore.EncodeEndpointV1(encoded[:], offset, nscore.Endpoint{Address: prefix.Prefix.Addr()}) {
			return false
		}
		binary.LittleEndian.PutUint32(encoded[offset+32:offset+36], uint32(prefix.Prefix.Bits()))
		binary.LittleEndian.PutUint32(encoded[offset+36:offset+40], prefix.PreferredLifetime)
		binary.LittleEndian.PutUint32(encoded[offset+40:offset+44], prefix.ValidLifetime)
	}
	copy(output, encoded[:])
	return true
}

func encodeName(output []byte, ptr uint32, name dhcpns.Name) bool {
	if !name.Valid() {
		return false
	}
	encoded, ok := abicore.Slice(output, ptr, NameV1Size)
	if !ok {
		return false
	}
	binary.LittleEndian.PutUint16(encoded[:2], name.Length)
	copy(encoded[4:4+dhcpns.MaxNameBytes], name.Bytes[:])
	return true
}
