// Package mdns defines bounded backend-neutral multicast DNS query,
// service-response, and announcement contracts.
package mdns

import (
	"net/netip"

	"github.com/wago-org/net/internal/mdnsname"
	nscore "github.com/wago-org/net/internal/namespace/core"
)

// ServiceKey attaches the mDNS adapter to one shared composed namespace.
const ServiceKey nscore.ServiceKey = "mdns"

const MaxTXTBytes = 255

// Namespace starts bounded queries and announcements. Responses to incoming
// questions are serviced automatically from the adapter's copied service set.
type Namespace interface {
	TryQuery(Request) (nscore.Resource, nscore.Progress, error)
	TryAnnounce(service uint16) (nscore.Resource, nscore.Progress, error)
}

// RecordType is independent of lneto's DNS codec types.
type RecordType uint8

const (
	RecordA RecordType = iota + 1
	RecordPTR
	RecordSRV
	RecordTXT
)

// RecordTypes is a finite query bitset.
type RecordTypes uint8

const (
	RecordsA RecordTypes = 1 << iota
	RecordsPTR
	RecordsSRV
	RecordsTXT

	recordTypesMask = RecordsA | RecordsPTR | RecordsSRV | RecordsTXT
)

// Request asks for one canonical .local name and one or more record types.
type Request struct {
	Name  string
	Types RecordTypes
}

func (r Request) Valid() bool {
	return validLocalName(r.Name) && r.Types != 0 && r.Types&^recordTypesMask == 0
}

// Service is one completely copied host-configured service. TXT bytes are
// inline so no caller or guest slice can be retained.
type Service struct {
	Name       string
	Host       string
	Address    netip.Addr
	TTLSeconds uint32
	Port       uint16
	TXTLength  uint16
	TXT        [MaxTXTBytes]byte
}

func (s Service) Valid() bool {
	return validLocalName(s.Name) && validLocalName(s.Host) && s.Address.Is4() &&
		!s.Address.Is4In6() && !s.Address.IsUnspecified() && !s.Address.IsMulticast() &&
		s.Address.Zone() == "" && s.TTLSeconds > 0 && s.Port > 0 && s.TXTLength <= MaxTXTBytes
}

// Record is one copied mDNS result. Type-specific unused fields are zero.
type Record struct {
	Name       string
	Type       RecordType
	TTLSeconds uint32
	Address    netip.Addr
	Target     string
	Port       uint16
	Priority   uint16
	Weight     uint16
	TXTLength  uint16
	TXT        [MaxTXTBytes]byte
	CacheFlush bool
}

func (r Record) Valid() bool {
	if !validLocalName(r.Name) || r.TTLSeconds == 0 || r.TXTLength > MaxTXTBytes {
		return false
	}
	switch r.Type {
	case RecordA:
		return r.Address.Is4() && !r.Address.Is4In6() && r.Address.Zone() == "" && r.Target == "" &&
			r.Port == 0 && r.Priority == 0 && r.Weight == 0 && r.TXTLength == 0
	case RecordPTR:
		return !r.Address.IsValid() && validLocalName(r.Target) && r.Port == 0 && r.Priority == 0 && r.Weight == 0 && r.TXTLength == 0
	case RecordSRV:
		return !r.Address.IsValid() && validLocalName(r.Target) && r.Port > 0 && r.TXTLength == 0
	case RecordTXT:
		return !r.Address.IsValid() && r.Target == "" && r.Port == 0 && r.Priority == 0 && r.Weight == 0
	default:
		return false
	}
}

// Next is shared by nonblocking result and completion calls.
type Next uint8

const (
	NextReady Next = iota + 1
	NextWouldBlock
	NextEOF
)

// Query owns copied request and result storage until exact-handle close.
type Query interface {
	nscore.Resource
	TryNext() (Record, Next, error)
	Cancel() error
}

// Announcement owns one finite retry sequence for one configured service.
type Announcement interface {
	nscore.Resource
	TryFinish() (Next, error)
	Cancel() error
}

func validLocalName(name string) bool {
	if !mdnsname.ValidCanonical(name) || len(name) < len("x.local") {
		return false
	}
	return name == "local" || (len(name) > len(".local") && name[len(name)-len(".local"):] == ".local")
}
