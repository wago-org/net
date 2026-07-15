// Package dhcpv4 defines bounded backend-neutral DHCPv4 client lease and
// explicitly configured server contracts.
package dhcpv4

import (
	"net/netip"

	nscore "github.com/wago-org/net/internal/namespace/core"
)

// ServiceKey attaches the DHCPv4 adapter to one shared composed namespace.
const ServiceKey nscore.ServiceKey = "dhcpv4"

const (
	MaxHostnameBytes        = 36
	MaxClientIDBytes        = 32
	MaxDNSServers           = 4
	ClientPort       uint16 = 68
	ServerPort       uint16 = 67
)

var limitedBroadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// Namespace starts at most the configured finite number of immediate DORA
// transactions. Server operation, when configured, is serviced automatically.
type Namespace interface {
	TryAcquire(Request) (nscore.Resource, nscore.Progress, error)
}

// Request owns only inline values. Empty requested address, hostname, and
// client identifier fields are valid and select normal DHCP defaults.
type Request struct {
	RequestedAddr  netip.Addr
	HostnameLength uint8
	Hostname       [MaxHostnameBytes]byte
	ClientIDLength uint8
	ClientID       [MaxClientIDBytes]byte
}

func (r Request) Valid() bool {
	if r.HostnameLength > MaxHostnameBytes || r.ClientIDLength > MaxClientIDBytes {
		return false
	}
	if r.RequestedAddr.IsValid() && (!r.RequestedAddr.Is4() || r.RequestedAddr.Is4In6() || r.RequestedAddr.Zone() != "" || r.RequestedAddr.IsUnspecified() || r.RequestedAddr.IsLoopback() || r.RequestedAddr.IsMulticast() || r.RequestedAddr == limitedBroadcast) {
		return false
	}
	for _, value := range r.Hostname[r.HostnameLength:] {
		if value != 0 {
			return false
		}
	}
	for _, value := range r.ClientID[r.ClientIDLength:] {
		if value != 0 {
			return false
		}
	}
	for _, value := range r.Hostname[:r.HostnameLength] {
		if value < 0x21 || value > 0x7e {
			return false
		}
	}
	return true
}

func (r Request) HostnameString() string { return string(r.Hostname[:r.HostnameLength]) }
func (r Request) ClientIDString() string { return string(r.ClientID[:r.ClientIDLength]) }

// Lease is one completely copied accepted DHCPv4 configuration. DNS storage is
// inline and bounded; zero-valued optional addresses are represented as invalid.
type Lease struct {
	AssignedAddr   netip.Addr
	ServerAddr     netip.Addr
	RouterAddr     netip.Addr
	BroadcastAddr  netip.Addr
	Subnet         netip.Prefix
	LeaseSeconds   uint32
	RenewalSeconds uint32
	RebindSeconds  uint32
	DNSCount       uint8
	DNSServers     [MaxDNSServers]netip.Addr
	Applied        bool
}

func (l Lease) Valid() bool {
	if !validRequiredIPv4(l.AssignedAddr) || !validRequiredIPv4(l.ServerAddr) || !l.Subnet.IsValid() || !l.Subnet.Addr().Is4() || !l.Subnet.Contains(l.AssignedAddr) || l.DNSCount > MaxDNSServers || l.LeaseSeconds == 0 {
		return false
	}
	if l.RenewalSeconds > l.LeaseSeconds || l.RebindSeconds > l.LeaseSeconds || (l.RebindSeconds != 0 && l.RenewalSeconds > l.RebindSeconds) {
		return false
	}
	if !validOptionalIPv4(l.RouterAddr) || !validOptionalIPv4(l.BroadcastAddr) {
		return false
	}
	for i, address := range l.DNSServers {
		if i < int(l.DNSCount) {
			if !validRequiredIPv4(address) {
				return false
			}
		} else if address.IsValid() {
			return false
		}
	}
	return true
}

// ResultState is the immediate state of one lease result operation.
type ResultState uint8

const (
	ResultReady ResultState = iota + 1
	ResultWouldBlock
)

// Resource owns one exact DORA transaction and, after success, its optional
// transactional namespace identity contribution until Release or Close.
type Resource interface {
	nscore.Resource
	TryResult() (Lease, ResultState, error)
	Cancel() error
	Release() error
}

func validRequiredIPv4(address netip.Addr) bool {
	return address.Is4() && !address.Is4In6() && address.Zone() == "" && !address.IsUnspecified() && !address.IsLoopback() && !address.IsMulticast() && address != limitedBroadcast
}

func validOptionalIPv4(address netip.Addr) bool {
	return !address.IsValid() || validRequiredIPv4(address)
}
