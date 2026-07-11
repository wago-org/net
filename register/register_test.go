package register_test

import (
	"testing"

	_ "github.com/wago-org/net/register"
	wago "github.com/wago-org/wago"
)

func TestRegistersCorePlugin(t *testing.T) {
	ext, ok := wago.NewExtension("net")
	if !ok {
		t.Fatal("net plugin was not registered")
	}
	if got := ext.Info().ID; got != "github.com/wago-org/net" {
		t.Fatalf("registered extension ID = %q", got)
	}
}
