package mdnsname

import (
	"bytes"
	"testing"
)

func TestNormalizeDNSServiceNames(t *testing.T) {
	name, ok := Normalize("Printer._HTTP._TCP.Local.")
	if !ok || name != "printer._http._tcp.local" || !ValidCanonical(name) {
		t.Fatalf("Normalize = %q, %v", name, ok)
	}
	for _, invalid := range []string{"", "*.local", "bad..local", "bad label.local", "é.local", "192.0.2.1", "255.255.255.255"} {
		if _, ok := Normalize(invalid); ok {
			t.Fatalf("invalid name accepted: %q", invalid)
		}
	}
}

func TestCanonicalStringAndBytesRejectOnlyCanonicalIPv4Literals(t *testing.T) {
	for _, test := range []struct {
		name string
		want bool
	}{
		{"printer._http._tcp.local", true},
		{"1234", true},
		{"1.2.3", true},
		{"1.2.3.4.5", true},
		{"256.2.3.4", true},
		{"01.2.3.4", true},
		{"1.2.3.4", false},
		{"0.0.0.0", false},
		{"255.255.255.255", false},
	} {
		if got := ValidCanonical(test.name); got != test.want {
			t.Errorf("ValidCanonical(%q) = %v, want %v", test.name, got, test.want)
		}
		if got := ValidCanonicalBytes([]byte(test.name)); got != test.want {
			t.Errorf("ValidCanonicalBytes(%q) = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestCanonicalValidationDoesNotAllocate(t *testing.T) {
	name := "printer._http._tcp.local"
	encoded := bytes.Clone([]byte(name))
	if allocations := testing.AllocsPerRun(1000, func() {
		if !ValidCanonical(name) || !ValidCanonicalBytes(encoded) {
			panic("valid name rejected")
		}
	}); allocations != 0 {
		t.Fatalf("canonical validation allocations = %v", allocations)
	}
}

func FuzzCanonicalStringBytesAgree(f *testing.F) {
	for _, seed := range []string{"printer._http._tcp.local", "192.0.2.1", "bad..local", "01.2.3.4", ""} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if got, want := ValidCanonicalBytes(encoded), ValidCanonical(string(encoded)); got != want {
			t.Fatalf("byte/string validation mismatch for %q: %v != %v", encoded, got, want)
		}
	})
}

func BenchmarkValidCanonical(b *testing.B) {
	name := "printer._http._tcp.local"
	b.ReportAllocs()
	for b.Loop() {
		if !ValidCanonical(name) {
			b.Fatal("valid name rejected")
		}
	}
}
