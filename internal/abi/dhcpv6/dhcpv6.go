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

func EncodeConfigurationV1(memory []byte, ptr uint32, configuration *dhcpns.Configuration) bool {
	if configuration == nil || !configuration.Valid() {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, ConfigurationV1Size)
	if !ok {
		return false
	}
	clear(output)
	binary.LittleEndian.PutUint32(output[offsetTransaction:offsetTransaction+4], configuration.TransactionID)
	copy(output[offsetIAID:offsetIAID+4], configuration.IAID[:])
	if !abicore.EncodeEndpointV1(output[:], offsetAssigned, nscore.Endpoint{Address: configuration.AssignedAddr}) ||
		!abicore.EncodeEndpointV1(output[:], offsetServer, nscore.Endpoint{Address: configuration.ServerAddr, ScopeID: configuration.ServerScopeID}) {
		return false
	}
	binary.LittleEndian.PutUint32(output[offsetServerDUIDLength:offsetServerDUIDLength+4], uint32(configuration.ServerDUIDLength))
	binary.LittleEndian.PutUint32(output[offsetDNSCount:offsetDNSCount+4], uint32(configuration.DNSCount))
	binary.LittleEndian.PutUint32(output[offsetDomainCount:offsetDomainCount+4], uint32(configuration.DomainCount))
	binary.LittleEndian.PutUint32(output[offsetNTPCount:offsetNTPCount+4], uint32(configuration.NTPCount))
	binary.LittleEndian.PutUint32(output[offsetNTPMulticastCount:offsetNTPMulticastCount+4], uint32(configuration.NTPMulticastCount))
	binary.LittleEndian.PutUint32(output[offsetNTPNameCount:offsetNTPNameCount+4], uint32(configuration.NTPNameCount))
	binary.LittleEndian.PutUint32(output[offsetPrefixCount:offsetPrefixCount+4], uint32(configuration.PrefixCount))
	binary.LittleEndian.PutUint32(output[offsetRenewal:offsetRenewal+4], configuration.RenewalSeconds)
	binary.LittleEndian.PutUint32(output[offsetRebinding:offsetRebinding+4], configuration.RebindingSeconds)
	binary.LittleEndian.PutUint32(output[offsetPreferred:offsetPreferred+4], configuration.PreferredLifetimeSeconds)
	binary.LittleEndian.PutUint32(output[offsetValid:offsetValid+4], configuration.ValidLifetimeSeconds)
	binary.LittleEndian.PutUint32(output[offsetPrefixRenewal:offsetPrefixRenewal+4], configuration.PrefixRenewalSeconds)
	binary.LittleEndian.PutUint32(output[offsetPrefixRebinding:offsetPrefixRebinding+4], configuration.PrefixRebindingSeconds)
	copy(output[offsetServerDUID:offsetServerDUID+dhcpns.MaxServerDUIDBytes], configuration.ServerDUID[:])
	// Configuration.Valid and the full-range Slice above make every fixed
	// subrange and endpoint below infallible; encode directly into guest memory
	// to avoid a second 3368-byte scratch buffer and copy.
	for i := 0; i < int(configuration.DNSCount); i++ {
		_ = abicore.EncodeEndpointV1(output, offsetDNS+uint32(i)*abicore.AddressV1Size, nscore.Endpoint{Address: configuration.DNSServers[i]})
	}
	for i := 0; i < int(configuration.DomainCount); i++ {
		encodeName(output, offsetDomains+uint32(i)*NameV1Size, configuration.DomainSearch[i])
	}
	for i := 0; i < int(configuration.NTPCount); i++ {
		_ = abicore.EncodeEndpointV1(output, offsetNTP+uint32(i)*abicore.AddressV1Size, nscore.Endpoint{Address: configuration.NTPServers[i]})
	}
	for i := 0; i < int(configuration.NTPMulticastCount); i++ {
		_ = abicore.EncodeEndpointV1(output, offsetNTPMulticast+uint32(i)*abicore.AddressV1Size, nscore.Endpoint{Address: configuration.NTPMulticastServers[i]})
	}
	for i := 0; i < int(configuration.NTPNameCount); i++ {
		encodeName(output, offsetNTPNames+uint32(i)*NameV1Size, configuration.NTPServerNames[i])
	}
	for i := 0; i < int(configuration.PrefixCount); i++ {
		prefix := configuration.DelegatedPrefixes[i]
		offset := offsetPrefixes + uint32(i)*PrefixV1Size
		_ = abicore.EncodeEndpointV1(output, offset, nscore.Endpoint{Address: prefix.Prefix.Addr()})
		binary.LittleEndian.PutUint32(output[offset+32:offset+36], uint32(prefix.Prefix.Bits()))
		binary.LittleEndian.PutUint32(output[offset+36:offset+40], prefix.PreferredLifetime)
		binary.LittleEndian.PutUint32(output[offset+40:offset+44], prefix.ValidLifetime)
	}
	return true
}

func encodeName(output []byte, ptr uint32, name dhcpns.Name) {
	encoded, _ := abicore.Slice(output, ptr, NameV1Size)
	binary.LittleEndian.PutUint16(encoded[:2], name.Length)
	copy(encoded[4:4+dhcpns.MaxNameBytes], name.Bytes[:])
}
