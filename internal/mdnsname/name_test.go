package mdnsname

import "testing"

func TestNormalizeDNSServiceNames(t *testing.T) {
	name, ok := Normalize("Printer._HTTP._TCP.Local.")
	if !ok || name != "printer._http._tcp.local" || !ValidCanonical(name) {
		t.Fatalf("Normalize = %q, %v", name, ok)
	}
	for _, invalid := range []string{"", "*.local", "bad..local", "bad label.local", "é.local", "192.0.2.1"} {
		if _, ok := Normalize(invalid); ok {
			t.Fatalf("invalid name accepted: %q", invalid)
		}
	}
}
