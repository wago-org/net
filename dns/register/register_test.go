package register_test

import (
	"testing"

	_ "github.com/wago-org/net/dns/register"
	wago "github.com/wago-org/wago"
)

func TestRegistersDNSOnlyExtension(t *testing.T) {
	if _, ok := wago.NewExtension("net-dns"); !ok {
		t.Fatal("DNS-only extension was not registered")
	}
}
