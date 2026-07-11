package register_test

import (
	"testing"

	_ "github.com/wago-org/net/tcp/register"
	wago "github.com/wago-org/wago"
)

func TestRegistersTCPOnlyExtension(t *testing.T) {
	if _, ok := wago.NewExtension("net-tcp"); !ok {
		t.Fatal("TCP-only extension was not registered")
	}
}
