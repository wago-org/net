package core

const (
	// FirstEphemeralTCPPort is the beginning of the IANA dynamic/private port
	// range used for namespace-local outbound TCP allocation.
	FirstEphemeralTCPPort uint16 = 49152
	ephemeralTCPPortCount        = 1 << 14
)

// TCPPortOwner is an opaque namespace-local identity for one TCP consumer.
// Raw TCP adapters and private TCP-based protocol adapters receive distinct
// owners while sharing one namespace-wide lease domain.
type TCPPortOwner struct {
	namespace *Namespace
	identity  uint64
}

// TCPPortLease reserves one live local TCP port for exactly one owner. Leases
// are caller-owned and must not be copied while active. Methods ending in
// Locked require the shared namespace lock.
type TCPPortLease struct {
	owner     *Namespace
	portOwner *TCPPortOwner
	port      uint16
	active    bool
}

// TCPPort returns the leased port, or zero after release or namespace teardown.
func (lease *TCPPortLease) TCPPort() uint16 {
	if lease == nil || !lease.active {
		return 0
	}
	return lease.port
}

// NewTCPPortOwnerLocked creates an opaque owner identity for one adapter. The
// caller must hold the namespace lock. Closed namespaces return nil.
func (n *Namespace) NewTCPPortOwnerLocked() *TCPPortOwner {
	if n == nil || n.closed {
		return nil
	}
	n.tcpPortOwnerSequence++
	if n.tcpPortOwnerSequence == 0 {
		n.tcpPortOwnerSequence++
	}
	return &TCPPortOwner{namespace: n, identity: n.tcpPortOwnerSequence}
}

// AcquireTCPPortIntoLocked reserves preferred exactly when it is nonzero. A
// zero preferred port selects the next free ephemeral port with bounded wrap.
// The caller must hold the namespace lock and supply an inactive lease.
func (n *Namespace) AcquireTCPPortIntoLocked(lease *TCPPortLease, portOwner *TCPPortOwner, preferred uint16) bool {
	if n == nil || n.closed || lease == nil || lease.active || portOwner == nil ||
		portOwner.namespace != n || portOwner.identity == 0 || n.maxActiveTCPPorts == 0 ||
		len(n.tcpPorts) >= int(n.maxActiveTCPPorts) {
		return false
	}
	if n.tcpPorts == nil {
		n.tcpPorts = make(map[uint16]*TCPPortLease)
	}
	if preferred != 0 {
		return n.acquireExactTCPPortIntoLocked(lease, portOwner, preferred)
	}

	port := n.nextTCPPort
	if port < FirstEphemeralTCPPort {
		port = FirstEphemeralTCPPort
	}
	attempts := int(n.maxActiveTCPPorts) + 1
	if attempts > ephemeralTCPPortCount {
		attempts = ephemeralTCPPortCount
	}
	for range attempts {
		if n.acquireExactTCPPortIntoLocked(lease, portOwner, port) {
			next := port + 1
			if next < FirstEphemeralTCPPort {
				next = FirstEphemeralTCPPort
			}
			n.nextTCPPort = next
			return true
		}
		port++
		if port < FirstEphemeralTCPPort {
			port = FirstEphemeralTCPPort
		}
	}
	return false
}

func (n *Namespace) acquireExactTCPPortIntoLocked(lease *TCPPortLease, portOwner *TCPPortOwner, port uint16) bool {
	if port == 0 || n.tcpPorts[port] != nil {
		return false
	}
	lease.owner = n
	lease.portOwner = portOwner
	lease.port = port
	lease.active = true
	n.tcpPorts[port] = lease
	return true
}

// OwnsTCPPortLocked reports whether port is currently leased by portOwner. It
// lets each TCP ingress participant ignore traffic owned by another adapter.
func (n *Namespace) OwnsTCPPortLocked(port uint16, portOwner *TCPPortOwner) bool {
	if n == nil || portOwner == nil || portOwner.namespace != n {
		return false
	}
	lease := n.tcpPorts[port]
	return lease != nil && lease.active && lease.portOwner == portOwner
}

// ReleaseLocked relinquishes a TCP port exactly once. Stale, copied, or
// foreign leases cannot remove another lease because map identity must match.
func (lease *TCPPortLease) ReleaseLocked() {
	if lease == nil || !lease.active {
		return
	}
	if lease.owner != nil && lease.owner.tcpPorts != nil && lease.owner.tcpPorts[lease.port] == lease {
		delete(lease.owner.tcpPorts, lease.port)
	}
	lease.owner = nil
	lease.portOwner = nil
	lease.port = 0
	lease.active = false
}

// TCPPortLeasedLocked reports whether any owner currently holds port.
func (n *Namespace) TCPPortLeasedLocked(port uint16) bool {
	return n != nil && port != 0 && n.tcpPorts[port] != nil
}

// TCPPortLeaseCapacityExhaustedLocked reports whether the namespace-wide live
// TCP port limit is full. Exact collisions remain distinguishable from bounded
// resource exhaustion.
func (n *Namespace) TCPPortLeaseCapacityExhaustedLocked() bool {
	return n == nil || n.closed || n.maxActiveTCPPorts == 0 || len(n.tcpPorts) >= int(n.maxActiveTCPPorts)
}

// TCPPortLeaseCountLocked reports the live shared TCP lease count for focused
// lifecycle and mixed-protocol tests.
func (n *Namespace) TCPPortLeaseCountLocked() int {
	if n == nil {
		return 0
	}
	return len(n.tcpPorts)
}
