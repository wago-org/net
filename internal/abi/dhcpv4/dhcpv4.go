// Package dhcpv4 contains fixed-width checked DHCPv4 guest ABI codecs.
package dhcpv4

import (
	"encoding/binary"
	"net/netip"

	abicore "github.com/wago-org/net/internal/abi/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv4"
)

const (
	RequestV1Size uint32 = 112
	LeaseV1Size   uint32 = 280

	LeaseFlagApplied uint32 = 1

	requestHostnameLength = 32
	requestClientIDLength = 34
	requestHostname       = 36
	requestClientID       = 72
	requestReserved       = 104

	leaseServer     = 32
	leaseRouter     = 64
	leaseBroadcast  = 96
	leaseSubnetBits = 128
	leaseSeconds    = 132
	leaseRenewal    = 136
	leaseRebind     = 140
	leaseDNSCount   = 144
	leaseFlags      = 148
	leaseDNS        = 152
)

func CheckRequestV1(memory []byte, requestPtr, handlePtr uint32) bool {
	return abicore.CheckRanges(memory, true, abicore.Range{Ptr: requestPtr, Length: RequestV1Size}, abicore.Range{Ptr: handlePtr, Length: abicore.HandleV1Size})
}

func DecodeRequestV1(memory []byte, ptr uint32) (dhcpns.Request, bool) {
	encoded, ok := abicore.Slice(memory, ptr, RequestV1Size)
	if !ok || binary.LittleEndian.Uint64(encoded[requestReserved:requestReserved+8]) != 0 {
		return dhcpns.Request{}, false
	}
	endpoint, ok := abicore.DecodeEndpointV1(encoded, 0)
	if !ok || endpoint.Port != 0 || endpoint.ScopeID != 0 || endpoint.FlowInfo != 0 || !endpoint.Address.Is4() {
		return dhcpns.Request{}, false
	}
	request := dhcpns.Request{HostnameLength: uint8(binary.LittleEndian.Uint16(encoded[requestHostnameLength : requestHostnameLength+2])), ClientIDLength: uint8(binary.LittleEndian.Uint16(encoded[requestClientIDLength : requestClientIDLength+2]))}
	if binary.LittleEndian.Uint16(encoded[requestHostnameLength:requestHostnameLength+2]) > dhcpns.MaxHostnameBytes || binary.LittleEndian.Uint16(encoded[requestClientIDLength:requestClientIDLength+2]) > dhcpns.MaxClientIDBytes {
		return dhcpns.Request{}, false
	}
	copy(request.Hostname[:], encoded[requestHostname:requestHostname+dhcpns.MaxHostnameBytes])
	copy(request.ClientID[:], encoded[requestClientID:requestClientID+dhcpns.MaxClientIDBytes])
	if !endpoint.Address.IsUnspecified() {
		request.RequestedAddr = endpoint.Address
	}
	return request, request.Valid()
}

func EncodeRequestV1(memory []byte, ptr uint32, request dhcpns.Request) bool {
	if !request.Valid() {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, RequestV1Size)
	if !ok {
		return false
	}
	var encoded [RequestV1Size]byte
	address := request.RequestedAddr
	if !address.IsValid() {
		address = netip.IPv4Unspecified()
	}
	if !abicore.EncodeEndpointV1(encoded[:], 0, nscore.Endpoint{Address: address}) {
		return false
	}
	binary.LittleEndian.PutUint16(encoded[requestHostnameLength:requestHostnameLength+2], uint16(request.HostnameLength))
	binary.LittleEndian.PutUint16(encoded[requestClientIDLength:requestClientIDLength+2], uint16(request.ClientIDLength))
	copy(encoded[requestHostname:requestHostname+dhcpns.MaxHostnameBytes], request.Hostname[:])
	copy(encoded[requestClientID:requestClientID+dhcpns.MaxClientIDBytes], request.ClientID[:])
	copy(output, encoded[:])
	return true
}

func EncodeLeaseV1(memory []byte, ptr uint32, lease dhcpns.Lease) bool {
	if !lease.Valid() {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, LeaseV1Size)
	if !ok {
		return false
	}
	var encoded [LeaseV1Size]byte
	if !encodeAddress(encoded[:], 0, lease.AssignedAddr) || !encodeAddress(encoded[:], leaseServer, lease.ServerAddr) || !encodeOptionalAddress(encoded[:], leaseRouter, lease.RouterAddr) || !encodeOptionalAddress(encoded[:], leaseBroadcast, lease.BroadcastAddr) {
		return false
	}
	binary.LittleEndian.PutUint32(encoded[leaseSubnetBits:leaseSubnetBits+4], uint32(lease.Subnet.Bits()))
	binary.LittleEndian.PutUint32(encoded[leaseSeconds:leaseSeconds+4], lease.LeaseSeconds)
	binary.LittleEndian.PutUint32(encoded[leaseRenewal:leaseRenewal+4], lease.RenewalSeconds)
	binary.LittleEndian.PutUint32(encoded[leaseRebind:leaseRebind+4], lease.RebindSeconds)
	binary.LittleEndian.PutUint32(encoded[leaseDNSCount:leaseDNSCount+4], uint32(lease.DNSCount))
	if lease.Applied {
		binary.LittleEndian.PutUint32(encoded[leaseFlags:leaseFlags+4], LeaseFlagApplied)
	}
	for i := 0; i < dhcpns.MaxDNSServers; i++ {
		if !encodeOptionalAddress(encoded[:], leaseDNS+uint32(i)*abicore.AddressV1Size, lease.DNSServers[i]) {
			return false
		}
	}
	copy(output, encoded[:])
	return true
}

func encodeAddress(output []byte, ptr uint32, address netip.Addr) bool {
	return abicore.EncodeEndpointV1(output, ptr, nscore.Endpoint{Address: address})
}

func encodeOptionalAddress(output []byte, ptr uint32, address netip.Addr) bool {
	if !address.IsValid() {
		return true
	}
	return encodeAddress(output, ptr, address)
}
