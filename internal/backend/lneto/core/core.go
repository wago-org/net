// Package core owns the protocol-neutral lneto stack, packet link, lifecycle
// lock, shared IPv4 identity, and bounded service scheduler.
package core

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/x/xnet"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

var _ nscore.Namespace = (*Namespace)(nil)

// Config fixes the shared stack, link, IPv4 identity, and protocol-neutral
// authority/account references for one namespace.
type Config struct {
	Hostname               string
	RandSeed               int64
	HardwareAddress        [6]byte
	GatewayHardwareAddress [6]byte
	IPv4Address            netip.Addr
	IPv6Address            netip.Addr
	IPv6PrefixBits         uint8
	IPv6ScopeID            uint32
	MTU                    uint16
	Link                   packetlink.Config
	MaxActiveTCPPorts      uint16
	Policy                 *policy.Policy
	Quotas                 *quota.Account
}

// Participant contributes bounded protocol work and deterministic teardown.
// All callbacks run while the namespace lifecycle lock is held. Zero callbacks
// are ignored. Lower order values run first; equal values preserve install order.
type Participant struct {
	IngressOrder int
	Ingress      func([]byte) (bool, error)
	EgressOrder  int
	HasEgress    func() bool
	Egress       func([]byte) (written int, worked bool, err error)
	CloseOrder   int
	Close        func()
}

type ingressParticipant struct {
	order    int
	sequence uint64
	try      func([]byte) (bool, error)
}

type egressParticipant struct {
	order    int
	sequence uint64
	has      func() bool
	try      func([]byte) (int, bool, error)
}

type closeParticipant struct {
	order    int
	sequence uint64
	close    func()
}

// Namespace owns exactly one lifecycle lock, lneto stack, packet link, frame
// scratch buffer, service scheduler, and installed participant set.
type Namespace struct {
	mu sync.Mutex

	stack                  *xnet.StackAsync
	link                   *packetlink.Link
	scratch                []byte
	requiredFrameBytes     int
	nextIngress            bool
	randSeed               int64
	nextIPv4ID             uint16
	ipv4Address            netip.Addr
	staticIPv4Address      netip.Addr
	ipv4IdentityLease      *IPv4IdentityLease
	ipv6Address            netip.Addr
	ipv6PrefixBits         uint8
	ipv6ScopeID            uint32
	hardwareAddress        [6]byte
	gatewayHardwareAddress [6]byte
	policy                 *policy.Policy
	quotas                 *quota.Account
	maintenanceEpoch       uint64
	sequence               uint64
	ingress                []ingressParticipant
	egress                 []egressParticipant
	egressActive           []bool
	nextEgress             int
	closers                []closeParticipant
	udpPorts               map[uint16]*UDPPortLease
	closed                 bool
}

// ValidateConfig reports whether config can construct the shared static IPv4
// stack and packet link without allocating backend state.
func ValidateConfig(config Config) error {
	if !validConfig(config) {
		return nscore.Fail(nscore.FailureInvalidArgument, packetlink.ErrInvalidConfig)
	}
	return nil
}

// New constructs the shared stack/link owner. Protocol adapters are installed
// separately before the namespace becomes visible to an instance.
func New(config Config) (*Namespace, error) {
	if err := ValidateConfig(config); err != nil {
		return nil, err
	}
	link, err := packetlink.New(config.Link)
	if err != nil {
		return nil, nscore.Fail(nscore.FailureInvalidArgument, err)
	}
	stack := new(xnet.StackAsync)
	stackConfig := xnet.StackConfig{
		HardwareAddress:   config.HardwareAddress,
		StaticAddress4:    config.IPv4Address.As4(),
		RandSeed:          config.RandSeed,
		Hostname:          config.Hostname,
		MTU:               config.MTU,
		MaxActiveTCPPorts: config.MaxActiveTCPPorts,
	}
	if config.IPv6Address.IsValid() {
		stackConfig.StaticAddress6 = config.IPv6Address.As16()
		stackConfig.IPv6Stack = xnet.DefaultStack6()
	}
	if err := stack.Reset(stackConfig); err != nil {
		_ = link.Close()
		return nil, MapError(err)
	}
	stack.SetGatewayHardwareAddr(config.GatewayHardwareAddress)
	return &Namespace{
		stack:                  stack,
		link:                   link,
		scratch:                make([]byte, config.Link.MaxFrameBytes),
		requiredFrameBytes:     int(config.MTU) + 14,
		nextIngress:            true,
		randSeed:               config.RandSeed,
		nextIPv4ID:             uint16(config.RandSeed),
		ipv4Address:            config.IPv4Address,
		staticIPv4Address:      config.IPv4Address,
		ipv6Address:            config.IPv6Address,
		ipv6PrefixBits:         config.IPv6PrefixBits,
		ipv6ScopeID:            config.IPv6ScopeID,
		hardwareAddress:        config.HardwareAddress,
		gatewayHardwareAddress: config.GatewayHardwareAddress,
		policy:                 config.Policy,
		quotas:                 config.Quotas,
	}, nil
}

// Install adds one protocol participant. Installation is intended only during
// namespace assembly and fails after close.
func (n *Namespace) Install(participant Participant) error {
	if n == nil {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if (participant.HasEgress == nil) != (participant.Egress == nil) {
		return nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	n.sequence++
	sequence := n.sequence
	if participant.Ingress != nil {
		n.ingress = append(n.ingress, ingressParticipant{order: participant.IngressOrder, sequence: sequence, try: participant.Ingress})
		sort.SliceStable(n.ingress, func(i, j int) bool {
			if n.ingress[i].order != n.ingress[j].order {
				return n.ingress[i].order < n.ingress[j].order
			}
			return n.ingress[i].sequence < n.ingress[j].sequence
		})
	}
	if participant.HasEgress != nil {
		n.egress = append(n.egress, egressParticipant{
			order: participant.EgressOrder, sequence: sequence,
			has: participant.HasEgress, try: participant.Egress,
		})
		sort.SliceStable(n.egress, func(i, j int) bool {
			if n.egress[i].order != n.egress[j].order {
				return n.egress[i].order < n.egress[j].order
			}
			return n.egress[i].sequence < n.egress[j].sequence
		})
		n.egressActive = make([]bool, len(n.egress))
	}
	if participant.Close != nil {
		n.closers = append(n.closers, closeParticipant{order: participant.CloseOrder, sequence: sequence, close: participant.Close})
		sort.SliceStable(n.closers, func(i, j int) bool {
			if n.closers[i].order != n.closers[j].order {
				return n.closers[i].order < n.closers[j].order
			}
			return n.closers[i].sequence < n.closers[j].sequence
		})
	}
	return nil
}

// Lock and Unlock serialize protocol operations with service and teardown.
func (n *Namespace) Lock()   { n.mu.Lock() }
func (n *Namespace) Unlock() { n.mu.Unlock() }

// The Locked accessors below require the caller to hold the namespace lock.
func (n *Namespace) ClosedLocked() bool                    { return n == nil || n.closed }
func (n *Namespace) StackLocked() *xnet.StackAsync         { return n.stack }
func (n *Namespace) PolicyLocked() *policy.Policy          { return n.policy }
func (n *Namespace) QuotasLocked() *quota.Account          { return n.quotas }
func (n *Namespace) IPv4AddressLocked() netip.Addr         { return n.ipv4Address }
func (n *Namespace) IPv6AddressLocked() netip.Addr         { return n.ipv6Address }
func (n *Namespace) IPv6PrefixBitsLocked() uint8           { return n.ipv6PrefixBits }
func (n *Namespace) IPv6ScopeIDLocked() uint32             { return n.ipv6ScopeID }
func (n *Namespace) IPv6EnabledLocked() bool               { return n.ipv6Address.IsValid() }
func (n *Namespace) RandSeedLocked() int64                 { return n.randSeed }
func (n *Namespace) HardwareAddressLocked() [6]byte        { return n.hardwareAddress }
func (n *Namespace) GatewayHardwareAddressLocked() [6]byte { return n.gatewayHardwareAddress }
func (n *Namespace) GatewayHardwareAddressUsableLocked() bool {
	return n != nil && validUnicastHardwareAddress(n.gatewayHardwareAddress)
}
func (n *Namespace) RequiredFrameBytesLocked() int         { return n.requiredFrameBytes }
func (n *Namespace) MarkMaintenanceLocked()                { n.maintenanceEpoch++ }
func (n *Namespace) SetNextIngressLocked(nextIngress bool) { n.nextIngress = nextIngress }
func (n *Namespace) NextIPv4IDLocked() uint16 {
	id := n.nextIPv4ID
	n.nextIPv4ID++
	return id
}

// Link returns the namespace-owned packet link. It remains inspectable after
// close, while operations return packetlink.ErrClosed.
func (n *Namespace) Link() *packetlink.Link {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.link
}

func (n *Namespace) Readiness() nscore.Readiness {
	if n == nil {
		return nscore.ReadyClosed
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.link == nil {
		return nscore.ReadyClosed
	}
	snapshot := n.link.Snapshot()
	if snapshot.Closed {
		return nscore.ReadyClosed
	}
	var ready nscore.Readiness
	if snapshot.EgressFrames > 0 {
		ready |= nscore.ReadyReadable
	}
	if snapshot.IngressFrames < snapshot.IngressCapacity {
		ready |= nscore.ReadyWritable
	}
	return ready
}

// Close runs installed participant cleanup in explicit order, then detaches the
// stack, clears frame scratch, and closes the link. It is synchronous and
// idempotent.
func (n *Namespace) Close() error {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	n.closed = true
	for _, closer := range n.closers {
		closer.close()
	}
	n.closers = nil
	if n.ipv4IdentityLease != nil {
		n.ipv4IdentityLease.owner = nil
		n.ipv4IdentityLease.active = false
		n.ipv4IdentityLease = nil
	}
	for _, lease := range n.udpPorts {
		lease.owner = nil
		lease.port = 0
		lease.active = false
	}
	clear(n.udpPorts)
	n.udpPorts = nil
	n.ingress = nil
	n.egress = nil
	n.egressActive = nil
	n.stack = nil
	clear(n.scratch)
	n.scratch = nil
	if n.link != nil {
		return n.link.Close()
	}
	return nil
}

func (n *Namespace) TryService(budget nscore.ServiceBudget) (nscore.ServiceReport, nscore.Progress, error) {
	if n == nil {
		return nscore.ServiceReport{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.stack == nil || n.link == nil {
		return nscore.ServiceReport{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if !budget.Valid() {
		return nscore.ServiceReport{}, 0, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}

	var report nscore.ServiceReport
	var attempts uint32
	for report.Packets < budget.Packets && attempts < budget.Operations && report.Bytes <= budget.Bytes {
		remainingBytes := budget.Bytes - report.Bytes
		ingress := n.nextIngress
		n.nextIngress = !n.nextIngress
		attempts++
		var worked, packet bool
		var frameBytes int
		var err error
		if ingress {
			worked, packet, frameBytes, err = n.tryIngress(remainingBytes)
		} else {
			worked, packet, frameBytes, err = n.tryEgress(remainingBytes)
		}
		if worked {
			report.Operations++
			if packet {
				report.Packets++
				report.Bytes += uint32(frameBytes)
			}
		}
		if err != nil {
			progress := nscore.ProgressWouldBlock
			if report != (nscore.ServiceReport{}) {
				progress = nscore.ProgressDone
			}
			return report, progress, err
		}
	}
	if report == (nscore.ServiceReport{}) {
		return report, nscore.ProgressWouldBlock, nil
	}
	return report, nscore.ProgressDone, nil
}

func (n *Namespace) tryIngress(remainingBytes uint32) (bool, bool, int, error) {
	result, err := n.link.TryDequeueWithin(packetlink.Ingress, n.scratch, int(remainingBytes))
	if errors.Is(err, packetlink.ErrFrameBudget) {
		return false, false, 0, nil
	}
	if err != nil {
		return false, false, 0, MapError(err)
	}
	if !result.Ready {
		return false, false, 0, nil
	}
	frame := n.scratch[:result.FrameBytes]
	handled := false
	for _, participant := range n.ingress {
		handled, err = participant.try(frame)
		if handled || err != nil {
			break
		}
	}
	if !handled && err == nil {
		err = n.stack.IngressEthernet(frame)
	}
	clear(frame)
	if errors.Is(err, lneto.ErrPacketDrop) {
		err = nil
	}
	if err != nil {
		return true, true, result.FrameBytes, MapError(err)
	}
	return true, true, result.FrameBytes, nil
}

func (n *Namespace) tryEgress(remainingBytes uint32) (bool, bool, int, error) {
	if remainingBytes < uint32(n.requiredFrameBytes) {
		return false, false, 0, nil
	}
	workedWithoutFrame := false
	originalNextEgress := n.nextEgress
	result, err := n.link.TryFill(packetlink.Egress, func(dst []byte) (int, error) {
		frame := dst[:n.requiredFrameBytes]
		active := n.egressActive
		for i := range n.egress {
			active[i] = n.egress[i].has()
		}

		// Treat the shared stack as one source in the same round-robin as
		// protocol participants. This bounds every continuously active source's
		// wait to one pass without consuming inactive participants.
		sources := len(n.egress) + 1
		if n.nextEgress >= sources {
			n.nextEgress = 0
		}
		for offset := 0; offset < sources; offset++ {
			source := n.nextEgress + offset
			if source >= sources {
				source -= sources
			}
			if source == len(n.egress) {
				maintenanceEpoch := n.maintenanceEpoch
				written, stackErr := n.stack.EgressEthernet(frame)
				worked := n.maintenanceEpoch != maintenanceEpoch
				workedWithoutFrame = workedWithoutFrame || worked
				if written != 0 || worked || stackErr != nil {
					n.nextEgress = 0
					return written, stackErr
				}
				continue
			}
			if !active[source] {
				continue
			}
			written, worked, participantErr := n.egress[source].try(frame)
			workedWithoutFrame = workedWithoutFrame || worked
			if written != 0 || worked || participantErr != nil {
				n.nextEgress = source + 1
				return written, participantErr
			}
		}
		return 0, nil
	})
	if err != nil {
		n.nextEgress = originalNextEgress
		if errors.Is(err, packetlink.ErrQueueFull) {
			return false, false, 0, nil
		}
		if errors.Is(err, packetlink.ErrInvalidFill) || errors.Is(err, packetlink.ErrFrameTooLarge) {
			return workedWithoutFrame, false, 0, nscore.Fail(nscore.FailureIO, err)
		}
		return workedWithoutFrame, false, 0, MapError(err)
	}
	if !result.Ready {
		return workedWithoutFrame, false, 0, nil
	}
	return true, true, result.FrameBytes, nil
}

func validConfig(config Config) bool {
	if config.Hostname == "" || config.RandSeed == 0 || !validUnicastHardwareAddress(config.HardwareAddress) || !validIPv4Identity(config.IPv4Address) {
		return false
	}
	ipv6Configured := config.IPv6Address.IsValid() || config.IPv6PrefixBits != 0 || config.IPv6ScopeID != 0
	if ipv6Configured && !validIPv6Config(config.IPv6Address, config.IPv6PrefixBits, config.IPv6ScopeID) {
		return false
	}
	if config.MTU < ethernet.MinimumMTU || config.MTU > ethernet.MaxMTU || (ipv6Configured && config.MTU < 1280) {
		return false
	}
	requiredFrameBytes := int(config.MTU) + 14
	return config.Link.MaxFrameBytes >= requiredFrameBytes && config.Link.IngressFrames > 0 && config.Link.EgressFrames > 0
}

func validUnicastHardwareAddress(address [6]byte) bool {
	return address != ([6]byte{}) && address[0]&1 == 0
}

func validIPv4Identity(address netip.Addr) bool {
	return address.Is4() && !address.Is4In6() && address.Zone() == "" &&
		(address.IsUnspecified() || (!address.IsLoopback() && !address.IsMulticast() && address != netip.AddrFrom4([4]byte{255, 255, 255, 255})))
}

func validIPv6Config(address netip.Addr, prefixBits uint8, scopeID uint32) bool {
	if !address.IsValid() || !address.Is6() || address.Is4In6() || address.Zone() != "" || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || prefixBits == 0 || prefixBits > 128 {
		return false
	}
	if address.IsLinkLocalUnicast() {
		return scopeID != 0
	}
	return scopeID == 0
}

// MapError maps lneto, packet-link, quota, and standard errors to the stable
// backend-neutral failure categories.
func MapError(err error) error {
	if err == nil {
		return nil
	}
	failure := nscore.FailureIO
	switch {
	case errors.Is(err, net.ErrClosed), errors.Is(err, packetlink.ErrClosed), errors.Is(err, quota.ErrClosed):
		failure = nscore.FailureClosed
	case errors.Is(err, context.Canceled):
		failure = nscore.FailureCanceled
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		failure = nscore.FailureTimedOut
	case errors.Is(err, lneto.ErrUnsupported):
		failure = nscore.FailureNotSupported
	case errors.Is(err, lneto.ErrExhausted), errors.Is(err, lneto.ErrBufferFull), errors.Is(err, packetlink.ErrQueueFull), errors.Is(err, quota.ErrLimit):
		failure = nscore.FailureResourceLimit
	case errors.Is(err, lneto.ErrAlreadyRegistered):
		failure = nscore.FailureAddressInUse
	case errors.Is(err, lneto.ErrBadState):
		failure = nscore.FailureInvalidState
	case errors.Is(err, lneto.ErrShortBuffer), errors.Is(err, io.ErrShortBuffer), errors.Is(err, packetlink.ErrFrameTooLarge):
		failure = nscore.FailureMessageTooLarge
	case errors.Is(err, lneto.ErrInvalidAddr), errors.Is(err, lneto.ErrInvalidConfig),
		errors.Is(err, lneto.ErrInvalidField), errors.Is(err, lneto.ErrInvalidLengthField),
		errors.Is(err, lneto.ErrMismatchLen), errors.Is(err, lneto.ErrTruncatedFrame),
		errors.Is(err, lneto.ErrZeroSource), errors.Is(err, lneto.ErrZeroDestination),
		errors.Is(err, lneto.ErrBadCRC), errors.Is(err, packetlink.ErrInvalidQueue),
		errors.Is(err, packetlink.ErrInvalidFill), errors.Is(err, packetlink.ErrFrameBudget), errors.Is(err, quota.ErrInvalidUnits):
		failure = nscore.FailureInvalidArgument
	case errors.Is(err, lneto.ErrPacketDrop), errors.Is(err, lneto.ErrMismatch):
		failure = nscore.FailureTemporary
	}
	return nscore.Fail(failure, err)
}
