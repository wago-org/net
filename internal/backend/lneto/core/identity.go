package core

import "net/netip"

// IPv4IdentityLease is one exact transactional dynamic IPv4 contribution. All
// methods ending in Locked require the namespace lifecycle lock.
type IPv4IdentityLease struct {
	owner  *Namespace
	active bool
}

// TryApplyIPv4IdentityLocked atomically updates the lneto stack address/subnet
// and shared namespace identity. Only one dynamic contributor may be active.
func (n *Namespace) TryApplyIPv4IdentityLocked(lease *IPv4IdentityLease, address netip.Addr, subnet netip.Prefix) bool {
	if n == nil || n.closed || n.stack == nil || lease == nil || lease.active || n.ipv4IdentityLease != nil ||
		!validIPv4Identity(address) || address.IsUnspecified() ||
		!subnet.IsValid() || !subnet.Addr().Is4() || !subnet.Contains(address) {
		return false
	}
	address4 := address.As4()
	if err := n.stack.SetAddr4(address4); err != nil {
		return false
	}
	n.stack.SetSubnet4(address4, uint8(subnet.Bits()))
	n.ipv4Address = address
	lease.owner = n
	lease.active = true
	n.ipv4IdentityLease = lease
	return true
}

// ReleaseLocked rolls the exact active contribution back to the configured
// static address. It is deterministic and idempotent.
func (lease *IPv4IdentityLease) ReleaseLocked() bool {
	if lease == nil || !lease.active || lease.owner == nil {
		return false
	}
	n := lease.owner
	if n.ipv4IdentityLease != lease || n.closed || n.stack == nil {
		lease.owner = nil
		lease.active = false
		return false
	}
	static := n.staticIPv4Address
	if !static.Is4() || static.Is4In6() {
		return false
	}
	static4 := static.As4()
	if err := n.stack.SetAddr4(static4); err != nil {
		return false
	}
	n.stack.SetSubnet4(static4, 32)
	n.ipv4Address = static
	n.ipv4IdentityLease = nil
	lease.owner = nil
	lease.active = false
	return true
}

// Active reports whether this exact lease currently owns namespace identity.
func (lease *IPv4IdentityLease) Active() bool {
	return lease != nil && lease.active && lease.owner != nil
}
