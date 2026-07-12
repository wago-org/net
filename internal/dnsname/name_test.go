package dnsname

import "testing"

func TestValidCanonicalAndNormalize(t *testing.T) {
	for _, name := range []string{"example.com", "service-1.api.example", "123.example", "127.1"} {
		if !ValidCanonical(name) || !ValidCanonicalBytes([]byte(name)) {
			t.Fatalf("valid name rejected: %q", name)
		}
		normalized, ok := Normalize(name)
		if !ok || normalized != name {
			t.Fatalf("Normalize(%q) = %q, %v", name, normalized, ok)
		}
	}

	for _, name := range []string{"", ".", "example.com.", "Example.com", "bad..example", "-bad.example", "bad-.example", "192.0.2.1", "*.example.com", "éxample.com"} {
		if ValidCanonical(name) || ValidCanonicalBytes([]byte(name)) {
			t.Fatalf("invalid canonical name accepted: %q", name)
		}
	}

	for input, want := range map[string]string{
		"Example.COM":  "example.com",
		"Example.COM.": "example.com",
		"example.com.": "example.com",
	} {
		got, ok := Normalize(input)
		if !ok || got != want {
			t.Fatalf("Normalize(%q) = %q, %v; want %q", input, got, ok, want)
		}
	}
}

func TestNameLengthAndLabelBounds(t *testing.T) {
	label63 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if !ValidCanonical(label63 + ".example") {
		t.Fatal("63-byte label rejected")
	}
	if ValidCanonical(label63 + "a.example") {
		t.Fatal("64-byte label accepted")
	}
	name253 := label63 + "." + label63 + "." + label63 + "." + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if len(name253) != MaxLength || !ValidCanonical(name253) {
		t.Fatalf("253-byte name rejected: length %d", len(name253))
	}
	if ValidCanonical(name253 + "a") {
		t.Fatal("254-byte name accepted")
	}
}
