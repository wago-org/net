package register_test

import (
	"testing"

	wagonet "github.com/wago-org/net"
	_ "github.com/wago-org/net/icmpv6/register"
	wago "github.com/wago-org/wago"
)

func TestGranularFactory(t *testing.T) {
	extension, ok := wago.NewExtension("net-icmpv6")
	if !ok {
		t.Fatal("net-icmpv6 extension absent")
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(extension); err != nil {
		t.Fatal(err)
	}
	imports := 0
	for _, spec := range runtime.ProvidedImports() {
		if spec.Module == wagonet.ICMPv6Module {
			imports++
		}
	}
	if imports != 14 {
		t.Fatalf("imports = %d", imports)
	}
}
