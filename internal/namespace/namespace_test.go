package namespace

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
)

var errFakeInvalid = errors.New("fake: invalid argument")

var (
	_ Namespace   = (*fakeNamespace)(nil)
	_ UDPSocket   = (*fakeUDP)(nil)
	_ TCPListener = (*fakeListener)(nil)
	_ TCPStream   = (*fakeStream)(nil)
	_ DNSQuery    = (*fakeDNS)(nil)
)

type fakeResource struct {
	ready  Readiness
	closed bool
}

func (r *fakeResource) Readiness() Readiness { return r.ready }
func (r *fakeResource) Close() error {
	r.closed = true
	r.ready = ReadyClosed
	return nil
}

type fakeNamespace struct{ fakeResource }

func (n *fakeNamespace) TryBindUDP(local Endpoint) (UDPSocket, Progress, error) {
	if !local.Valid() {
		return nil, 0, errFakeInvalid
	}
	return &fakeUDP{fakeResource: fakeResource{ready: ReadyWritable}, local: local}, ProgressDone, nil
}

func (n *fakeNamespace) TryListenTCP(local Endpoint) (TCPListener, Progress, error) {
	if !local.Valid() {
		return nil, 0, errFakeInvalid
	}
	return &fakeListener{fakeResource: fakeResource{}, local: local}, ProgressDone, nil
}

func (n *fakeNamespace) TryConnectTCP(remote Endpoint) (TCPStream, Progress, error) {
	if !remote.Valid() {
		return nil, 0, errFakeInvalid
	}
	stream := &fakeStream{fakeResource: fakeResource{ready: ReadyWritable}, remote: remote}
	return stream, ProgressInProgress, nil
}

func (n *fakeNamespace) TryResolve(request DNSRequest) (DNSQuery, Progress, error) {
	if !request.Valid() {
		return nil, 0, errFakeInvalid
	}
	return &fakeDNS{fakeResource: fakeResource{}}, ProgressInProgress, nil
}

func (n *fakeNamespace) TryService(budget ServiceBudget) (ServiceReport, Progress, error) {
	if !budget.Valid() {
		return ServiceReport{}, 0, errFakeInvalid
	}
	return ServiceReport{Packets: 1, Bytes: min(64, budget.Bytes), Operations: 1}, ProgressDone, nil
}

type fakeDatagram struct {
	payload []byte
	source  Endpoint
}

type fakeUDP struct {
	fakeResource
	local Endpoint
	rx    []fakeDatagram
}

func (u *fakeUDP) LocalEndpoint() Endpoint { return u.local }
func (u *fakeUDP) TryReceive(dst []byte) (DatagramResult, error) {
	if len(u.rx) == 0 {
		return DatagramResult{}, nil
	}
	datagram := u.rx[0]
	u.rx = u.rx[1:]
	n := copy(dst, datagram.payload)
	return DatagramResult{
		Copied:        n,
		DatagramBytes: len(datagram.payload),
		Source:        datagram.source,
		Truncated:     n < len(datagram.payload),
		Ready:         true,
	}, nil
}
func (u *fakeUDP) TrySend(_ []byte, remote Endpoint) (Progress, error) {
	if !remote.Valid() {
		return 0, errFakeInvalid
	}
	return ProgressDone, nil
}

type fakeListener struct {
	fakeResource
	local    Endpoint
	accepted []TCPStream
}

func (l *fakeListener) LocalEndpoint() Endpoint { return l.local }
func (l *fakeListener) TryAccept() (TCPStream, Progress, error) {
	if len(l.accepted) == 0 {
		return nil, ProgressWouldBlock, nil
	}
	stream := l.accepted[0]
	l.accepted = l.accepted[1:]
	return stream, ProgressDone, nil
}

type fakeStream struct {
	fakeResource
	local     Endpoint
	remote    Endpoint
	connected bool
	input     []byte
}

func (s *fakeStream) LocalEndpoint() Endpoint  { return s.local }
func (s *fakeStream) RemoteEndpoint() Endpoint { return s.remote }
func (s *fakeStream) TryFinishConnect() (Progress, error) {
	if s.connected {
		return ProgressDone, nil
	}
	s.connected = true
	s.ready |= ReadyConnected | ReadyReadable
	return ProgressDone, nil
}
func (s *fakeStream) TryRead(dst []byte) (IOResult, error) {
	if len(s.input) == 0 {
		return IOResult{State: IOWouldBlock}, nil
	}
	n := copy(dst, s.input)
	s.input = s.input[n:]
	return IOResult{Bytes: n, State: IOReady}, nil
}
func (s *fakeStream) TryWrite(src []byte) (IOResult, error) {
	if len(src) == 0 {
		return IOResult{State: IOReady}, nil
	}
	return IOResult{Bytes: len(src), State: IOReady}, nil
}
func (s *fakeStream) TryShutdownWrite() (Progress, error) { return ProgressDone, nil }

type fakeDNS struct {
	fakeResource
	records  []DNSRecord
	ready    bool
	canceled bool
}

func (q *fakeDNS) Cancel() error {
	q.ready = true
	q.records = nil
	q.canceled = true
	q.fakeResource.ready = ReadyError
	return nil
}

func (q *fakeDNS) TryNext() (DNSRecord, DNSNext, error) {
	if q.canceled {
		return DNSRecord{}, 0, Fail(FailureCanceled, nil)
	}
	if !q.ready {
		return DNSRecord{}, DNSNextWouldBlock, nil
	}
	if len(q.records) == 0 {
		return DNSRecord{}, DNSNextEOF, nil
	}
	record := q.records[0]
	q.records = q.records[1:]
	return record, DNSNextReady, nil
}

func TestEndpointStructuralValidation(t *testing.T) {
	valid := []Endpoint{
		{Address: netip.MustParseAddr("192.0.2.1"), Port: 80},
		{Address: netip.MustParseAddr("2001:db8::1"), Port: 443, FlowInfo: 0xabcde},
		{Address: netip.MustParseAddr("fe80::1"), Port: 53, ScopeID: 2},
		{Address: netip.MustParseAddr("ff02::1"), Port: 9999, ScopeID: 3},
	}
	for _, endpoint := range valid {
		if !endpoint.Valid() {
			t.Fatalf("valid endpoint rejected: %+v", endpoint)
		}
	}
	invalid := []Endpoint{
		{},
		{Address: netip.MustParseAddr("::ffff:192.0.2.1"), Port: 80},
		{Address: netip.MustParseAddr("192.0.2.1"), ScopeID: 1},
		{Address: netip.MustParseAddr("192.0.2.1"), FlowInfo: 1},
		{Address: netip.MustParseAddr("2001:db8::1"), ScopeID: 1},
		{Address: netip.MustParseAddr("2001:db8::1"), FlowInfo: 0x10_0000},
		{Address: netip.MustParseAddr("fe80::1%eth0"), ScopeID: 1},
	}
	for _, endpoint := range invalid {
		if endpoint.Valid() {
			t.Fatalf("invalid endpoint accepted: %+v", endpoint)
		}
	}
}

func TestResultContractsRejectAmbiguousOrOverBudgetResults(t *testing.T) {
	for _, result := range []IOResult{
		{Bytes: 3, State: IOReady},
		{State: IOWouldBlock},
		{State: IOEOF},
	} {
		if !result.Valid(3) {
			t.Fatalf("valid I/O result rejected: %+v", result)
		}
	}
	for _, result := range []IOResult{
		{Bytes: -1, State: IOReady},
		{Bytes: 4, State: IOReady},
		{Bytes: 1, State: IOWouldBlock},
		{Bytes: 1, State: IOEOF},
		{State: 99},
	} {
		if result.Valid(3) {
			t.Fatalf("invalid I/O result accepted: %+v", result)
		}
	}

	budget := ServiceBudget{Packets: 2, Bytes: 128, Operations: 4}
	if !(ServiceReport{Packets: 2, Bytes: 128, Operations: 4}).ValidResult(budget, ProgressDone) {
		t.Fatal("exact service budget rejected")
	}
	if !(ServiceReport{}).ValidResult(budget, ProgressWouldBlock) || (ServiceReport{}).ValidResult(budget, ProgressDone) {
		t.Fatal("service progress semantics accepted an ambiguous result")
	}
	if (ServiceReport{Packets: 3}).ValidFor(budget) || (ServiceReport{Bytes: 129}).ValidFor(budget) || (ServiceReport{Operations: 5}).ValidFor(budget) {
		t.Fatal("over-budget service report accepted")
	}
	if (ServiceReport{}).ValidFor(ServiceBudget{}) {
		t.Fatal("zero service budget accepted")
	}
}

func TestFakeBackendNonblockingSemantics(t *testing.T) {
	backend := &fakeNamespace{}
	local := Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 8080}
	remote := Endpoint{Address: netip.MustParseAddr("198.51.100.2"), Port: 9000}

	udpResource, progress, err := backend.TryBindUDP(local)
	if err != nil || progress != ProgressDone {
		t.Fatalf("TryBindUDP = %v, %v", progress, err)
	}
	udp := udpResource.(*fakeUDP)
	if result, err := udp.TryReceive(make([]byte, 8)); err != nil || !result.Valid(8) || result.Ready {
		t.Fatalf("empty TryReceive = %+v, %v", result, err)
	}
	udp.rx = append(udp.rx, fakeDatagram{payload: []byte("data"), source: remote})
	dst := make([]byte, 2)
	result, err := udp.TryReceive(dst)
	if err != nil || !result.Valid(len(dst)) || !result.Ready || !result.Truncated || result.Copied != 2 || result.DatagramBytes != 4 {
		t.Fatalf("truncated TryReceive = %+v, %v", result, err)
	}
	if progress, err := udp.TrySend([]byte("packet"), remote); err != nil || progress != ProgressDone {
		t.Fatalf("TrySend = %v, %v", progress, err)
	}

	streamResource, progress, err := backend.TryConnectTCP(remote)
	if err != nil || progress != ProgressInProgress {
		t.Fatalf("TryConnectTCP = %v, %v", progress, err)
	}
	stream := streamResource.(*fakeStream)
	if progress, err := stream.TryFinishConnect(); err != nil || progress != ProgressDone {
		t.Fatalf("TryFinishConnect = %v, %v", progress, err)
	}
	if result, err := stream.TryRead(make([]byte, 4)); err != nil || !result.Valid(4) || result.State != IOWouldBlock {
		t.Fatalf("empty TryRead = %+v, %v", result, err)
	}
	stream.input = []byte("hello")
	if result, err := stream.TryRead(make([]byte, 3)); err != nil || !result.Valid(3) || result.Bytes != 3 {
		t.Fatalf("ready TryRead = %+v, %v", result, err)
	}

	queryResource, progress, err := backend.TryResolve(DNSRequest{Name: "example.com", Types: DNSRecordsA})
	if err != nil || progress != ProgressInProgress {
		t.Fatalf("TryResolve = %v, %v", progress, err)
	}
	query := queryResource.(*fakeDNS)
	if _, next, err := query.TryNext(); err != nil || next != DNSNextWouldBlock {
		t.Fatalf("pending TryNext = %v, %v", next, err)
	}
	query.ready = true
	query.records = append(query.records, DNSRecord{Name: "example.com", Type: DNSRecordA, TTLSeconds: 60, Address: netip.MustParseAddr("192.0.2.10")})
	if record, next, err := query.TryNext(); err != nil || next != DNSNextReady || !record.Valid() {
		t.Fatalf("ready TryNext = %+v, %v, %v", record, next, err)
	}
	if _, next, err := query.TryNext(); err != nil || next != DNSNextEOF {
		t.Fatalf("complete TryNext = %v, %v", next, err)
	}
	pendingResource, _, err := backend.TryResolve(DNSRequest{Name: "cancel.example", Types: DNSRecordsA})
	if err != nil {
		t.Fatal(err)
	}
	pending := pendingResource.(*fakeDNS)
	if err := pending.Cancel(); err != nil || pending.Readiness() != ReadyError {
		t.Fatalf("Cancel = readiness %v, %v", pending.Readiness(), err)
	}
	if _, _, err := pending.TryNext(); failureFromTest(err) != FailureCanceled {
		t.Fatalf("canceled TryNext = %v", err)
	}

	budget := ServiceBudget{Packets: 1, Bytes: 128, Operations: 1}
	report, progress, err := backend.TryService(budget)
	if err != nil || progress != ProgressDone || !report.ValidResult(budget, progress) {
		t.Fatalf("TryService = %+v, %v, %v", report, progress, err)
	}
}

func TestBackendFailureCategoriesSurviveWrapping(t *testing.T) {
	cause := errors.New("backend detail")
	err := fmt.Errorf("adapter: %w", Fail(FailureRemoteUnreachable, cause))
	failure, ok := FailureOf(err)
	if !ok || failure != FailureRemoteUnreachable || !errors.Is(err, cause) {
		t.Fatalf("FailureOf = %v, %v; error=%v", failure, ok, err)
	}
	failure, ok = FailureOf(Fail(Failure(255), cause))
	if !ok || failure != FailureIO {
		t.Fatalf("invalid failure fallback = %v, %v", failure, ok)
	}
	if _, ok := FailureOf(cause); ok {
		t.Fatal("uncategorized backend error acquired a failure category")
	}
}

func failureFromTest(err error) Failure {
	failure, _ := FailureOf(err)
	return failure
}

func TestDNSContractValidation(t *testing.T) {
	if !(DNSRequest{Name: "example.com", Types: DNSRecordsA | DNSRecordsAAAA}).Valid() {
		t.Fatal("valid DNS request rejected")
	}
	invalidRequests := []DNSRequest{
		{Name: "", Types: DNSRecordsA},
		{Name: "example.com", Types: 0x80},
		{Name: "Example.COM", Types: DNSRecordsA},
		{Name: "example.com.", Types: DNSRecordsA},
		{Name: "*.example.com", Types: DNSRecordsA},
		{Name: "192.0.2.1", Types: DNSRecordsA},
	}
	for _, request := range invalidRequests {
		if request.Valid() {
			t.Fatalf("invalid DNS request accepted: %+v", request)
		}
	}
	valid := []DNSRecord{
		{Name: "example.com", Type: DNSRecordA, Address: netip.MustParseAddr("192.0.2.1")},
		{Name: "example.com", Type: DNSRecordAAAA, Address: netip.MustParseAddr("2001:db8::1")},
		{Name: "www.example.com", Type: DNSRecordCNAME, CanonicalName: "example.com"},
	}
	for _, record := range valid {
		if !record.Valid() {
			t.Fatalf("valid DNS record rejected: %+v", record)
		}
	}
	invalid := []DNSRecord{
		{},
		{Name: "example.com", Type: DNSRecordA, Address: netip.MustParseAddr("2001:db8::1")},
		{Name: "example.com", Type: DNSRecordAAAA, Address: netip.MustParseAddr("::ffff:192.0.2.1")},
		{Name: "example.com", Type: DNSRecordCNAME, Address: netip.MustParseAddr("192.0.2.1"), CanonicalName: "alias.example"},
	}
	for _, record := range invalid {
		if record.Valid() {
			t.Fatalf("invalid DNS record accepted: %+v", record)
		}
	}
}
