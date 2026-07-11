// Package policy compiles immutable, fail-closed networking authority rules.
package policy

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
)

var ErrInvalidRule = errors.New("net: invalid policy rule")

// Action is the result assigned by a matching rule. Deny always takes
// precedence over allow, independent of rule order.
type Action uint8

const (
	ActionDeny Action = iota + 1
	ActionAllow
)

// Transport identifies the authority being requested.
type Transport uint8

const (
	TransportUDP Transport = iota + 1
	TransportTCP
	TransportDNS
)

// Direction identifies whether authority accepts local inbound traffic or
// initiates traffic toward a remote authority.
type Direction uint8

const (
	DirectionInbound Direction = iota + 1
	DirectionOutbound
)

// Operation identifies an authority-changing operation. Policy must be checked
// again whenever an operation changes the local or remote endpoint.
type Operation uint8

const (
	OperationUDPBind Operation = iota + 1
	OperationUDPSend
	OperationTCPListen
	OperationTCPConnect
	OperationDNSResolve
)

// PortRange is an inclusive port selector.
type PortRange struct {
	First uint16
	Last  uint16
}

// Rule is copied and normalized by Compile. Empty selector slices match every
// value in that dimension. DNS suffixes match the exact name and subdomains.
type Rule struct {
	Action      Action
	Transports  []Transport
	Directions  []Direction
	Prefixes    []netip.Prefix
	Ports       []PortRange
	DNSSuffixes []string
}

// Config controls privileged endpoint classes. These gates are deliberately
// separate from rules so broad prefix rules cannot accidentally grant special
// authority. AllowPrivilegedBind applies only to local bind/listen ports 1..1023;
// remote destination ports are ordinary rule selectors.
type Config struct {
	Rules []Rule

	AllowWildcardBind   bool
	AllowLoopback       bool
	AllowMulticast      bool
	AllowBroadcast      bool
	AllowPrivilegedBind bool
}

// Merge returns one independently owned policy configuration. Rules retain
// their original order, special-class grants compose monotonically, and deny
// precedence remains a property of the compiled policy rather than merge order.
func Merge(configs ...Config) Config {
	var merged Config
	for _, config := range configs {
		for _, input := range config.Rules {
			rule := input
			rule.Transports = append([]Transport(nil), input.Transports...)
			rule.Directions = append([]Direction(nil), input.Directions...)
			rule.Prefixes = append([]netip.Prefix(nil), input.Prefixes...)
			rule.Ports = append([]PortRange(nil), input.Ports...)
			rule.DNSSuffixes = append([]string(nil), input.DNSSuffixes...)
			merged.Rules = append(merged.Rules, rule)
		}
		merged.AllowWildcardBind = merged.AllowWildcardBind || config.AllowWildcardBind
		merged.AllowLoopback = merged.AllowLoopback || config.AllowLoopback
		merged.AllowMulticast = merged.AllowMulticast || config.AllowMulticast
		merged.AllowBroadcast = merged.AllowBroadcast || config.AllowBroadcast
		merged.AllowPrivilegedBind = merged.AllowPrivilegedBind || config.AllowPrivilegedBind
	}
	return merged
}

// Policy is an immutable, concurrently safe compiled policy.
type Policy struct {
	rules []compiledRule

	allowWildcardBind   bool
	allowLoopback       bool
	allowMulticast      bool
	allowBroadcast      bool
	allowPrivilegedBind bool
}

type compiledRule struct {
	action      Action
	transports  []Transport
	directions  []Direction
	prefixes    []netip.Prefix
	ports       []PortRange
	dnsSuffixes []string
}

// Compile validates, normalizes, and deep-copies config. The returned policy
// does not retain caller-owned slices.
func Compile(config Config) (*Policy, error) {
	p := &Policy{
		rules:               make([]compiledRule, 0, len(config.Rules)),
		allowWildcardBind:   config.AllowWildcardBind,
		allowLoopback:       config.AllowLoopback,
		allowMulticast:      config.AllowMulticast,
		allowBroadcast:      config.AllowBroadcast,
		allowPrivilegedBind: config.AllowPrivilegedBind,
	}
	for _, input := range config.Rules {
		rule, err := compileRule(input)
		if err != nil {
			return nil, err
		}
		p.rules = append(p.rules, rule)
	}
	return p, nil
}

// CheckEndpoint decides endpoint authority for UDP and TCP operations. Invalid,
// unspecified outbound, IPv4-mapped, or disabled privileged endpoints fail
// closed before ordinary rules are evaluated.
func (p *Policy) CheckEndpoint(operation Operation, address netip.Addr, port uint16) bool {
	transport, direction, ok := operationEndpoint(operation)
	if p == nil || !ok || !address.IsValid() || address.Is4In6() {
		return false
	}
	if address.IsUnspecified() {
		if direction != DirectionInbound || !p.allowWildcardBind {
			return false
		}
	}
	if address.IsLoopback() && !p.allowLoopback {
		return false
	}
	if address.IsMulticast() && !p.allowMulticast {
		return false
	}
	if isLimitedBroadcast(address) && !p.allowBroadcast {
		return false
	}
	if direction == DirectionInbound && port > 0 && port < 1024 && !p.allowPrivilegedBind {
		return false
	}
	return p.decide(query{transport: transport, direction: direction, address: address, port: port})
}

// CheckDNS decides authority to resolve a normalized DNS name. Empty names,
// wildcard labels, IP literals, and malformed names fail closed.
func (p *Policy) CheckDNS(operation Operation, name string) bool {
	transport, direction, ok := operationDNS(operation)
	if p == nil || !ok {
		return false
	}
	name, ok = normalizeDNSName(name)
	if !ok {
		return false
	}
	return p.decide(query{transport: transport, direction: direction, dnsName: name})
}

type query struct {
	transport Transport
	direction Direction
	address   netip.Addr
	port      uint16
	dnsName   string
}

func (p *Policy) decide(q query) bool {
	allowed := false
	for _, rule := range p.rules {
		if !rule.matches(q) {
			continue
		}
		if rule.action == ActionDeny {
			return false
		}
		allowed = true
	}
	return allowed
}

func compileRule(input Rule) (compiledRule, error) {
	if input.Action != ActionAllow && input.Action != ActionDeny {
		return compiledRule{}, ErrInvalidRule
	}
	rule := compiledRule{action: input.Action}
	var ok bool
	if rule.transports, ok = normalizeTransports(input.Transports); !ok {
		return compiledRule{}, ErrInvalidRule
	}
	if rule.directions, ok = normalizeDirections(input.Directions); !ok {
		return compiledRule{}, ErrInvalidRule
	}
	if rule.prefixes, ok = normalizePrefixes(input.Prefixes); !ok {
		return compiledRule{}, ErrInvalidRule
	}
	if rule.ports, ok = normalizePorts(input.Ports); !ok {
		return compiledRule{}, ErrInvalidRule
	}
	if rule.dnsSuffixes, ok = normalizeDNSSuffixes(input.DNSSuffixes); !ok {
		return compiledRule{}, ErrInvalidRule
	}
	return rule, nil
}

func (r compiledRule) matches(q query) bool {
	if len(r.transports) != 0 && !slices.Contains(r.transports, q.transport) {
		return false
	}
	if len(r.directions) != 0 && !slices.Contains(r.directions, q.direction) {
		return false
	}
	if q.transport == TransportDNS {
		if len(r.prefixes) != 0 || len(r.ports) != 0 {
			return false
		}
		if len(r.dnsSuffixes) == 0 {
			return true
		}
		for _, suffix := range r.dnsSuffixes {
			if q.dnsName == suffix || strings.HasSuffix(q.dnsName, "."+suffix) {
				return true
			}
		}
		return false
	}
	if len(r.dnsSuffixes) != 0 {
		return false
	}
	if len(r.prefixes) != 0 {
		matched := false
		for _, prefix := range r.prefixes {
			if prefix.Contains(q.address) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(r.ports) != 0 {
		matched := false
		for _, ports := range r.ports {
			if q.port >= ports.First && q.port <= ports.Last {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func normalizeTransports(input []Transport) ([]Transport, bool) {
	out := append([]Transport(nil), input...)
	for _, value := range out {
		if value < TransportUDP || value > TransportDNS {
			return nil, false
		}
	}
	slices.Sort(out)
	return slices.Compact(out), true
}

func normalizeDirections(input []Direction) ([]Direction, bool) {
	out := append([]Direction(nil), input...)
	for _, value := range out {
		if value < DirectionInbound || value > DirectionOutbound {
			return nil, false
		}
	}
	slices.Sort(out)
	return slices.Compact(out), true
}

func normalizePrefixes(input []netip.Prefix) ([]netip.Prefix, bool) {
	out := make([]netip.Prefix, 0, len(input))
	for _, prefix := range input {
		if !prefix.IsValid() || prefix.Addr().Is4In6() {
			return nil, false
		}
		out = append(out, prefix.Masked())
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if order := a.Addr().Compare(b.Addr()); order != 0 {
			return order
		}
		return a.Bits() - b.Bits()
	})
	return slices.Compact(out), true
}

func normalizePorts(input []PortRange) ([]PortRange, bool) {
	out := append([]PortRange(nil), input...)
	for _, ports := range out {
		if ports.First > ports.Last {
			return nil, false
		}
	}
	slices.SortFunc(out, func(a, b PortRange) int {
		if a.First != b.First {
			return int(a.First) - int(b.First)
		}
		return int(a.Last) - int(b.Last)
	})
	return slices.Compact(out), true
}

func normalizeDNSSuffixes(input []string) ([]string, bool) {
	out := make([]string, 0, len(input))
	for _, suffix := range input {
		normalized, ok := normalizeDNSName(suffix)
		if !ok {
			return nil, false
		}
		out = append(out, normalized)
	}
	slices.Sort(out)
	return slices.Compact(out), true
}

func normalizeDNSName(name string) (string, bool) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" || len(name) > 253 {
		return "", false
	}
	if address, err := netip.ParseAddr(name); err == nil && address.IsValid() {
		return "", false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, c := range []byte(label) {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", false
			}
		}
	}
	return name, true
}

func operationEndpoint(operation Operation) (Transport, Direction, bool) {
	switch operation {
	case OperationUDPBind:
		return TransportUDP, DirectionInbound, true
	case OperationUDPSend:
		return TransportUDP, DirectionOutbound, true
	case OperationTCPListen:
		return TransportTCP, DirectionInbound, true
	case OperationTCPConnect:
		return TransportTCP, DirectionOutbound, true
	default:
		return 0, 0, false
	}
}

func operationDNS(operation Operation) (Transport, Direction, bool) {
	if operation == OperationDNSResolve {
		return TransportDNS, DirectionOutbound, true
	}
	return 0, 0, false
}

func isLimitedBroadcast(address netip.Addr) bool {
	return address.Is4() && address == netip.AddrFrom4([4]byte{255, 255, 255, 255})
}
