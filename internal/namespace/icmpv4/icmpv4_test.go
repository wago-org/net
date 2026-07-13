package icmpv4

import (
	"net/netip"
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
)

var (
	_ Namespace = (*fakeNamespace)(nil)
	_ Echo      = (*fakeEcho)(nil)
)

type fakeNamespace struct{ echo nscore.Resource }

func (n *fakeNamespace) TryEcho(Request) (nscore.Resource, nscore.Progress, error) {
	return n.echo, nscore.ProgressInProgress, nil
}

type fakeEcho struct{ payload []byte }

func (*fakeEcho) Close() error                { return nil }
func (*fakeEcho) Cancel() error               { return nil }
func (*fakeEcho) Readiness() nscore.Readiness { return nscore.ReadyICMPv4Reply }
func (e *fakeEcho) TryResult(dst []byte) (Result, Next, error) {
	copied := copy(dst, e.payload)
	return Result{Source: netip.MustParseAddr("192.0.2.1"), Identifier: 7, Sequence: 9, Copied: copied, PayloadBytes: len(e.payload)}, NextReady, nil
}

func TestNarrowICMPv4FacetAndCopiedResultValidation(t *testing.T) {
	request := Request{Destination: netip.MustParseAddr("192.0.2.1"), Payload: []byte("echo")}
	if !request.Valid() {
		t.Fatal("valid request rejected")
	}
	for _, invalid := range []Request{
		{},
		{Destination: netip.IPv4Unspecified()},
		{Destination: netip.MustParseAddr("::ffff:192.0.2.1")},
		{Destination: netip.MustParseAddr("2001:db8::1")},
	} {
		if invalid.Valid() {
			t.Fatalf("invalid request accepted: %+v", invalid)
		}
	}

	backend := &fakeNamespace{echo: &fakeEcho{payload: request.Payload}}
	resource, progress, err := backend.TryEcho(request)
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("TryEcho = %v, %v", progress, err)
	}
	echo, ok := resource.(Echo)
	if !ok {
		t.Fatalf("echo resource type = %T", resource)
	}
	var dst [2]byte
	result, next, err := echo.TryResult(dst[:])
	if err != nil || next != NextReady || !result.Valid(len(dst)) || string(dst[:]) != "ec" || result.PayloadBytes != len(request.Payload) {
		t.Fatalf("TryResult = %+v, %v, %v, payload=%q", result, next, err, dst[:])
	}
	if (Result{Source: netip.MustParseAddr("192.0.2.1"), Copied: 2, PayloadBytes: 1}).Valid(2) {
		t.Fatal("result with copied bytes beyond payload accepted")
	}
}
