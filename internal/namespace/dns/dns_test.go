package dns

import (
	"net/netip"
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
)

var (
	_ Namespace = (*fakeNamespace)(nil)
	_ Query     = (*fakeQuery)(nil)
)

type fakeNamespace struct{ query nscore.Resource }

func (n *fakeNamespace) TryResolve(Request) (nscore.Resource, nscore.Progress, error) {
	return n.query, nscore.ProgressInProgress, nil
}

type fakeQuery struct{ record Record }

func (*fakeQuery) Close() error                { return nil }
func (*fakeQuery) Readiness() nscore.Readiness { return nscore.ReadyDNSResult }
func (*fakeQuery) Cancel() error               { return nil }
func (q *fakeQuery) TryNext() (Record, Next, error) {
	return q.record, NextReady, nil
}

func TestNarrowDNSFacetAndValueValidation(t *testing.T) {
	request := Request{Name: "example.com", Types: RecordsA | RecordsAAAA}
	if !request.Valid() {
		t.Fatal("valid request rejected")
	}
	for _, invalid := range []Request{
		{Name: "", Types: RecordsA},
		{Name: "Example.com", Types: RecordsA},
		{Name: "example.com.", Types: RecordsA},
		{Name: "192.0.2.1", Types: RecordsA},
		{Name: "example.com", Types: 0x80},
	} {
		if invalid.Valid() {
			t.Fatalf("invalid request accepted: %+v", invalid)
		}
	}

	record := Record{Name: "example.com", Type: RecordA, Address: netip.MustParseAddr("192.0.2.1")}
	backend := &fakeNamespace{query: &fakeQuery{record: record}}
	resource, progress, err := backend.TryResolve(request)
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("TryResolve = %v, %v", progress, err)
	}
	query, ok := resource.(Query)
	if !ok {
		t.Fatalf("query resource type = %T", resource)
	}
	got, next, err := query.TryNext()
	if err != nil || next != NextReady || got != record || !got.Valid() {
		t.Fatalf("TryNext = %+v, %v, %v", got, next, err)
	}
	if (Record{Name: "example.com", Type: RecordAAAA, Address: netip.MustParseAddr("::ffff:192.0.2.1")}).Valid() {
		t.Fatal("mapped AAAA record accepted")
	}
}
