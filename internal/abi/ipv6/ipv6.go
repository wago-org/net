// Package ipv6 owns the fixed checked IPv6 namespace configuration ABI.
package ipv6

import (
	"encoding/binary"

	abicore "github.com/wago-org/net/internal/abi/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	ipv6ns "github.com/wago-org/net/internal/namespace/ipv6"
)

const (
	ConfigurationV1Size uint32 = 64

	ConfigurationFlagEnabled   uint32 = 1 << 0
	ConfigurationFlagLinkLocal uint32 = 1 << 1
)

// EncodeConfigurationV1 validates the entire configuration and output range,
// builds one zeroed fixed result, and copies it atomically.
func EncodeConfigurationV1(memory []byte, ptr uint32, configuration ipv6ns.Configuration) bool {
	if !configuration.Valid() {
		return false
	}
	if _, ok := abicore.Slice(memory, ptr, ConfigurationV1Size); !ok {
		return false
	}
	var encoded [ConfigurationV1Size]byte
	endpoint := nscore.Endpoint{Address: configuration.Address, ScopeID: configuration.ScopeID}
	if !abicore.EncodeEndpointV1(encoded[:], 0, endpoint) {
		return false
	}
	binary.LittleEndian.PutUint32(encoded[32:36], uint32(configuration.PrefixBits))
	flags := ConfigurationFlagEnabled
	if configuration.Address.IsLinkLocalUnicast() {
		flags |= ConfigurationFlagLinkLocal
	}
	binary.LittleEndian.PutUint32(encoded[36:40], flags)
	binary.LittleEndian.PutUint32(encoded[40:44], uint32(configuration.Transports))
	binary.LittleEndian.PutUint32(encoded[44:48], uint32(configuration.MTU))
	binary.LittleEndian.PutUint32(encoded[48:52], uint32(configuration.MaxExtensionHeaders))
	copy(memory[ptr:ptr+ConfigurationV1Size], encoded[:])
	return true
}
