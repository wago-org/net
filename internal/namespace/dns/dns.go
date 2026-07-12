// Package dns defines the narrow backend-neutral DNS namespace facet, request
// and record values, and asynchronous query contract.
package dns

import (
	"net/netip"

	"github.com/wago-org/net/internal/dnsname"
	nscore "github.com/wago-org/net/internal/namespace/core"
)

// ServiceKey is the protocol-local key used to attach a DNS adapter to one
// shared composed namespace.
const ServiceKey nscore.ServiceKey = "dns"

// Namespace starts bounded asynchronous DNS queries on the shared namespace
// object. The returned shared resource must satisfy Query before publication.
type Namespace interface {
	TryResolve(request Request) (nscore.Resource, nscore.Progress, error)
}

// RecordType is independent of any backend DNS package.
type RecordType uint8

const (
	RecordA RecordType = iota + 1
	RecordAAAA
	RecordCNAME
)

// RecordTypes is a request bitset.
type RecordTypes uint8

const (
	RecordsA RecordTypes = 1 << iota
	RecordsAAAA

	recordTypesMask = RecordsA | RecordsAAAA
)

// Request starts one bounded asynchronous lookup. Name must already be a
// normalized absolute-or-relative ASCII DNS name without a trailing dot.
type Request struct {
	Name  string
	Types RecordTypes
}

// Valid reports whether a request has at least one known query type.
func (r Request) Valid() bool {
	return validName(r.Name) && r.Types != 0 && r.Types&^recordTypesMask == 0
}

// Record is a backend-neutral result. Address is set only for A and AAAA;
// CanonicalName is set only for CNAME.
type Record struct {
	Name          string
	Type          RecordType
	TTLSeconds    uint32
	Address       netip.Addr
	CanonicalName string
}

// Valid reports whether type-specific fields are consistent and mapped
// addresses cannot cross family policy.
func (r Record) Valid() bool {
	if !validName(r.Name) {
		return false
	}
	switch r.Type {
	case RecordA:
		return r.Address.Is4() && !r.Address.Is4In6() && r.CanonicalName == ""
	case RecordAAAA:
		return r.Address.Is6() && !r.Address.Is4In6() && r.Address.Zone() == "" && r.CanonicalName == ""
	case RecordCNAME:
		return !r.Address.IsValid() && validName(r.CanonicalName)
	default:
		return false
	}
}

// Next is the result of one TryNext call.
type Next uint8

const (
	NextReady Next = iota + 1
	NextWouldBlock
	NextEOF
)

// Query streams bounded records without returning backend-owned slices. Cancel
// immediately makes an unfinished query terminal; Close retires retained state.
type Query interface {
	nscore.Resource
	TryNext() (Record, Next, error)
	Cancel() error
}

func validName(name string) bool {
	return dnsname.ValidCanonical(name)
}
