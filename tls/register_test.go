package tls_test

import (
	cryptotls "crypto/tls"
	"errors"
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/tcp"
	wagonettls "github.com/wago-org/net/tls"
	wago "github.com/wago-org/wago"
)

func TestRegisterExposesOnlyTLSAndSharedCore(t *testing.T) {
	network := wagonet.New()
	profile := testProfile(t)
	if err := wagonettls.Register(network, wagonettls.WithClientProfile(profile)); err != nil {
		t.Fatal(err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatal(err)
	}
	if got, want := runtime.Capabilities(), []wago.Capability{wagonet.CapInfo, wagonet.CapTLS}; !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}
	imports := make(map[string]int)
	for _, spec := range runtime.ProvidedImports() {
		imports[spec.Module]++
	}
	want := map[string]int{wagonet.Module: 1, wagonet.TLSModule: 9}
	if !reflect.DeepEqual(imports, want) {
		t.Fatalf("imports = %v, want %v", imports, want)
	}
	if imports[wagonet.TCPModule] != 0 {
		t.Fatal("TLS-only exposed raw TCP imports")
	}
}

func TestTCPAndTLSComposeWithoutCapabilityWidening(t *testing.T) {
	network := wagonet.New()
	if err := tcp.Register(network); err != nil {
		t.Fatal(err)
	}
	if err := wagonettls.Register(network, wagonettls.WithClientProfile(testProfile(t))); err != nil {
		t.Fatal(err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatal(err)
	}
	wantCapabilities := []wago.Capability{wagonet.CapInfo, wagonet.CapTCP, wagonet.CapTLS}
	if got := runtime.Capabilities(); !reflect.DeepEqual(got, wantCapabilities) {
		t.Fatalf("capabilities = %v, want %v", got, wantCapabilities)
	}
	imports := make(map[string]int)
	for _, spec := range runtime.ProvidedImports() {
		imports[spec.Module]++
	}
	wantImports := map[string]int{wagonet.Module: 1, wagonet.TCPModule: 11, wagonet.TLSModule: 9}
	if !reflect.DeepEqual(imports, wantImports) {
		t.Fatalf("imports = %v, want %v", imports, wantImports)
	}
}

func TestRegisterRejectsMissingProfileDuplicateAndFrozen(t *testing.T) {
	if err := wagonettls.Register(nil, wagonettls.WithClientProfile(testProfile(t))); !errors.Is(err, wagonettls.ErrInvalidConfig) {
		t.Fatalf("nil network = %v", err)
	}
	if err := wagonettls.Register(wagonet.New()); !errors.Is(err, wagonettls.ErrInvalidConfig) {
		t.Fatalf("missing profile = %v", err)
	}
	network := wagonet.New()
	profile := testProfile(t)
	if err := wagonettls.Register(network, nil); !errors.Is(err, wagonettls.ErrInvalidOption) {
		t.Fatalf("nil option = %v", err)
	}
	if err := wagonettls.Register(network, wagonettls.WithClientProfile(profile)); err != nil {
		t.Fatal(err)
	}
	if err := wagonettls.Register(network, wagonettls.WithClientProfile(profile)); !errors.Is(err, wagonet.ErrProtocolAlreadyRegistered) {
		t.Fatalf("duplicate = %v", err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatal(err)
	}
	if err := wagonettls.Register(network, wagonettls.WithClientProfile(profile)); !errors.Is(err, wagonet.ErrProtocolRegistrationFrozen) {
		t.Fatalf("frozen = %v", err)
	}
}

func testProfile(t testing.TB) *wagonettls.ClientProfile {
	t.Helper()
	profile, err := wagonettls.NewClientProfile(1, &cryptotls.Config{}, wagonettls.AllowServerNames("api.example.com"), wagonettls.RequireALPN("h2"))
	if err != nil {
		t.Fatal(err)
	}
	return profile
}
