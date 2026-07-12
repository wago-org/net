package dns

import (
	"fmt"
	"net/netip"
	"testing"

	lnetodns "github.com/soypat/lneto/dns"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dnsns "github.com/wago-org/net/internal/namespace/dns"
)

var (
	benchmarkPacket   []byte
	benchmarkRecords  []dnsns.Record
	benchmarkResponse bool
	benchmarkFailure  nscore.Failure
	benchmarkErr      error
	benchmarkRecord   dnsns.Record
	benchmarkNext     dnsns.Next
	benchmarkReady    nscore.Readiness
)

func BenchmarkBuildDNSQueryPacket(b *testing.B) {
	request := dnsns.Request{Name: "service.api.example.com", Types: dnsns.RecordsA | dnsns.RecordsAAAA}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkPacket, benchmarkErr = buildDNSQueryPacket(request, 17, 1232)
		if benchmarkErr != nil {
			b.Fatal(benchmarkErr)
		}
	}
}

func BenchmarkBuildDNSQueryPacketInto(b *testing.B) {
	request := dnsns.Request{Name: "service.api.example.com", Types: dnsns.RecordsA | dnsns.RecordsAAAA}
	var storage [dnsQueryPacketCapacity]byte
	b.ReportAllocs()
	for b.Loop() {
		benchmarkPacket, benchmarkErr = buildDNSQueryPacketInto(storage[:], request, 17, 1232)
		if benchmarkErr != nil {
			b.Fatal(benchmarkErr)
		}
	}
}

func BenchmarkDecodeDNSName(b *testing.B) {
	name := lnetodns.MustNewName("service.api.example.com")
	message, err := name.AppendTo(nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		var next int
		var decoded string
		decoded, next, benchmarkErr = decodeDNSName(message, 0)
		if benchmarkErr != nil || next != len(message) || decoded == "" {
			b.Fatalf("decode = %q, %d, %v", decoded, next, benchmarkErr)
		}
	}
}

func BenchmarkDecodeDNSNameInto(b *testing.B) {
	name := lnetodns.MustNewName("service.api.example.com")
	message, err := name.AppendTo(nil)
	if err != nil {
		b.Fatal(err)
	}
	var decoded [253]byte
	b.ReportAllocs()
	for b.Loop() {
		written, next, err := decodeDNSNameInto(decoded[:], message, 0)
		if err != nil || next != len(message) || written == 0 {
			b.Fatalf("decode = %d, %d, %v", written, next, err)
		}
	}
}

func BenchmarkParseDNSResponse(b *testing.B) {
	request := dnsns.Request{Name: "service.api.example.com", Types: dnsns.RecordsA | dnsns.RecordsAAAA}
	name := lnetodns.MustNewName(request.Name)
	alias := lnetodns.MustNewName("api.example.com")
	aliasData, err := alias.AppendTo(nil)
	if err != nil {
		b.Fatal(err)
	}
	message := lnetodns.Message{
		Questions: []lnetodns.Question{
			{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET},
			{Name: name, Type: lnetodns.TypeAAAA, Class: lnetodns.ClassINET},
		},
		Answers: []lnetodns.Resource{
			lnetodns.NewResource(name, lnetodns.TypeCNAME, lnetodns.ClassINET, 60, aliasData),
			lnetodns.NewResource(alias, lnetodns.TypeA, lnetodns.ClassINET, 60, []byte{192, 0, 2, 1}),
			lnetodns.NewResource(alias, lnetodns.TypeAAAA, lnetodns.ClassINET, 60, netip.MustParseAddr("2001:db8::1").AsSlice()),
		},
	}
	payload, err := message.AppendTo(nil, 23, lnetodns.HeaderFlags(1<<15))
	if err != nil {
		b.Fatal(err)
	}
	records := make([]dnsns.Record, 0, 8)
	candidates := make([]dnsns.Record, len(payload)/11)
	names := make([]string, 2*len(candidates))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		benchmarkRecords, benchmarkResponse, benchmarkFailure, benchmarkErr = parseDNSResponseInto(records, candidates, names, payload, 23, request, 8)
		if benchmarkErr != nil || !benchmarkResponse || len(benchmarkRecords) != 3 {
			b.Fatalf("parse = %d, %v, %v, %v", len(benchmarkRecords), benchmarkResponse, benchmarkFailure, benchmarkErr)
		}
	}
}

func BenchmarkParseDNSResponseShapes(b *testing.B) {
	for _, depth := range []int{0, 1, 4} {
		b.Run(fmt.Sprintf("cname_depth=%d", depth), func(b *testing.B) {
			request := dnsns.Request{Name: "start.example.com", Types: dnsns.RecordsA | dnsns.RecordsAAAA}
			current := lnetodns.MustNewName(request.Name)
			answers := make([]lnetodns.Resource, 0, depth+2)
			for i := range depth {
				next := lnetodns.MustNewName(fmt.Sprintf("alias-%d.example.com", i))
				data, err := next.AppendTo(nil)
				if err != nil {
					b.Fatal(err)
				}
				answers = append(answers, lnetodns.NewResource(current, lnetodns.TypeCNAME, lnetodns.ClassINET, 60, data))
				current = next
			}
			answers = append(answers,
				lnetodns.NewResource(current, lnetodns.TypeA, lnetodns.ClassINET, 60, []byte{192, 0, 2, 1}),
				lnetodns.NewResource(current, lnetodns.TypeAAAA, lnetodns.ClassINET, 60, netip.MustParseAddr("2001:db8::1").AsSlice()),
			)
			name := lnetodns.MustNewName(request.Name)
			payload, err := (&lnetodns.Message{
				Questions: []lnetodns.Question{
					{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET},
					{Name: name, Type: lnetodns.TypeAAAA, Class: lnetodns.ClassINET},
				},
				Answers: answers,
			}).AppendTo(nil, 29, lnetodns.HeaderFlags(1<<15))
			if err != nil {
				b.Fatal(err)
			}
			records := make([]dnsns.Record, 0, depth+2)
			candidates := make([]dnsns.Record, len(payload)/11)
			names := make([]string, 2*len(candidates))
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for b.Loop() {
				benchmarkRecords, benchmarkResponse, benchmarkFailure, benchmarkErr = parseDNSResponseInto(records, candidates, names, payload, 29, request, depth+2)
				if benchmarkErr != nil || !benchmarkResponse || len(benchmarkRecords) != depth+2 {
					b.Fatalf("parse = %d, %v, %v, %v", len(benchmarkRecords), benchmarkResponse, benchmarkFailure, benchmarkErr)
				}
			}
		})
	}
}

func BenchmarkSelectDNSAnswers(b *testing.B) {
	request := dnsns.Request{Name: "service.api.example.com", Types: dnsns.RecordsA | dnsns.RecordsAAAA}
	candidates := []dnsns.Record{
		{Name: request.Name, Type: dnsns.RecordCNAME, TTLSeconds: 60, CanonicalName: "api.example.com"},
		{Name: "api.example.com", Type: dnsns.RecordA, TTLSeconds: 60, Address: netip.MustParseAddr("192.0.2.1")},
		{Name: "api.example.com", Type: dnsns.RecordAAAA, TTLSeconds: 60, Address: netip.MustParseAddr("2001:db8::1")},
	}
	records := make([]dnsns.Record, 0, 8)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkRecords, benchmarkFailure, benchmarkErr = selectDNSAnswersInto(records, candidates, request, 8)
		if benchmarkErr != nil || len(benchmarkRecords) != 3 {
			b.Fatalf("select = %d, %v, %v", len(benchmarkRecords), benchmarkFailure, benchmarkErr)
		}
	}
}

func BenchmarkAdapterTryResolveClose(b *testing.B) {
	config := dnsTestConfig(b, 85)
	config.DNS.MaxQueries = 1
	ns := newTestNamespace(b, config)
	request := dnsns.Request{Name: "service.api.example.com", Types: dnsns.RecordsA | dnsns.RecordsAAAA}
	// The test policy grants example.com and therefore this subdomain.
	b.ReportAllocs()
	for b.Loop() {
		value, progress, err := ns.adapter.TryResolve(request)
		if err != nil || progress != nscore.ProgressInProgress {
			b.Fatalf("resolve = %T, %v, %v", value, progress, err)
		}
		if err := value.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkQueryTryNext(b *testing.B) {
	config := dnsTestConfig(b, 86)
	ns := newTestNamespace(b, config)
	value, _, err := ns.adapter.TryResolve(dnsns.Request{Name: "example.com", Types: dnsns.RecordsA})
	if err != nil {
		b.Fatal(err)
	}
	query := value.(*dnsQuery)
	ns.core.Lock()
	query.records = []dnsns.Record{{Name: "example.com", Type: dnsns.RecordA, TTLSeconds: 60, Address: netip.MustParseAddr("192.0.2.1")}}
	query.state = dnsQueryDone
	ns.core.Unlock()
	b.ReportAllocs()
	for b.Loop() {
		ns.core.Lock()
		query.cursor = 0
		ns.core.Unlock()
		benchmarkRecord, benchmarkNext, benchmarkErr = query.TryNext()
		if benchmarkErr != nil || benchmarkNext != dnsns.NextReady {
			b.Fatalf("next = %+v, %v, %v", benchmarkRecord, benchmarkNext, benchmarkErr)
		}
	}
}

func BenchmarkQueryReadiness(b *testing.B) {
	config := dnsTestConfig(b, 87)
	ns := newTestNamespace(b, config)
	value, _, err := ns.adapter.TryResolve(dnsns.Request{Name: "example.com", Types: dnsns.RecordsA})
	if err != nil {
		b.Fatal(err)
	}
	query := value.(*dnsQuery)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkReady = query.Readiness()
	}
}
