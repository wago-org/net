package register_test

import (
	"testing"

	_ "github.com/wago-org/net/udp/register"
	wago "github.com/wago-org/wago"
)

func TestRegistersUDPOnlyExtension(t *testing.T) {
	if _, ok := wago.NewExtension("net-udp"); !ok {
		t.Fatal("UDP-only extension was not registered")
	}
}
