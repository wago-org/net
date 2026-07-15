package dhcpv4

import (
	"testing"

	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv4"
)

func BenchmarkClientLeaseSnapshot(b *testing.B) {
	clientCore, client := newClient(b, false)
	serverCore, _ := newServer(b, 1)
	resource, _, err := client.TryAcquire(dhcpns.Request{})
	if err != nil {
		b.Fatal(err)
	}
	defer resource.Close()
	transferOne(b, clientCore, serverCore)
	transferOne(b, serverCore, clientCore)
	transferOne(b, clientCore, serverCore)
	transferOne(b, serverCore, clientCore)
	lease := resource.(*leaseResource)

	clientCore.Lock()
	defer clientCore.Unlock()
	if result, ok := client.clientLeaseLocked(lease); !ok || !result.Valid() {
		b.Fatalf("warmup lease = %+v, %v", result, ok)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if result, ok := client.clientLeaseLocked(lease); !ok || !result.Valid() {
			b.Fatalf("lease = %+v, %v", result, ok)
		}
	}
}

func BenchmarkIngressDHCPv4OfferWithoutLease(b *testing.B) {
	clientCore, client := newClient(b, false)
	serverCore, _ := newServer(b, 1)
	resource, _, err := client.TryAcquire(dhcpns.Request{})
	if err != nil {
		b.Fatal(err)
	}
	transferOne(b, clientCore, serverCore)
	offer := serviceEgress(b, serverCore)
	if err := resource.Close(); err != nil {
		b.Fatal(err)
	}

	clientCore.Lock()
	defer clientCore.Unlock()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		handled, err := client.ingressLocked(offer)
		if err != nil || !handled {
			b.Fatalf("ingress = %v, %v", handled, err)
		}
	}
}
