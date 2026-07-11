package core

// UDPPortLease reserves one local UDP port in the shared namespace transport
// domain. DNS query source ports and public UDP sockets use the same domain.
// Lease methods whose names end in Locked require the namespace lock.
type UDPPortLease struct {
	owner  *Namespace
	port   uint16
	active bool
}

// UDPPort returns the reserved local port, or zero after release.
func (l *UDPPortLease) UDPPort() uint16 {
	if l == nil || !l.active {
		return 0
	}
	return l.port
}

// TryLeaseUDPPortLocked reserves an exact nonzero port. The caller must hold
// the namespace lock. A false result means the port is already owned or the
// namespace is closed.
func (n *Namespace) TryLeaseUDPPortLocked(port uint16) (*UDPPortLease, bool) {
	if n == nil || n.closed || port == 0 {
		return nil, false
	}
	if n.udpPorts == nil {
		n.udpPorts = make(map[uint16]*UDPPortLease)
	}
	if n.udpPorts[port] != nil {
		return nil, false
	}
	lease := &UDPPortLease{owner: n, port: port, active: true}
	n.udpPorts[port] = lease
	return lease, true
}

// TryLeaseUDPPortRangeLocked deterministically searches at most attempts ports
// beginning at start and wrapping to first when uint16 overflows or the cursor
// falls below first. It returns the lease and the next cursor on success.
func (n *Namespace) TryLeaseUDPPortRangeLocked(start, first uint16, attempts int) (*UDPPortLease, uint16, bool) {
	if n == nil || n.closed || first == 0 || attempts <= 0 {
		return nil, start, false
	}
	port := start
	if port < first {
		port = first
	}
	for range attempts {
		if lease, ok := n.TryLeaseUDPPortLocked(port); ok {
			next := port + 1
			if next < first {
				next = first
			}
			return lease, next, true
		}
		port++
		if port < first {
			port = first
		}
	}
	return nil, start, false
}

// ReleaseLocked relinquishes the port exactly once. The caller must hold the
// owner namespace lock.
func (l *UDPPortLease) ReleaseLocked() {
	if l == nil || !l.active {
		return
	}
	if l.owner != nil && l.owner.udpPorts != nil && l.owner.udpPorts[l.port] == l {
		delete(l.owner.udpPorts, l.port)
	}
	l.owner = nil
	l.port = 0
	l.active = false
}

// UDPPortLeaseCountLocked reports live shared UDP-port ownership for focused
// lifecycle tests. The caller must hold the namespace lock.
func (n *Namespace) UDPPortLeaseCountLocked() int {
	if n == nil {
		return 0
	}
	return len(n.udpPorts)
}
