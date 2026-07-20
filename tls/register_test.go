package tls_test

import (
	"context"
	cryptotls "crypto/tls"
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	abicore "github.com/wago-org/net/internal/abi/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
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
	want := map[string]int{wagonet.Module: 1, wagonet.TLSModule: 13}
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
	wantImports := map[string]int{wagonet.Module: 1, wagonet.TCPModule: 11, wagonet.TLSModule: 13}
	if !reflect.DeepEqual(imports, wantImports) {
		t.Fatalf("imports = %v, want %v", imports, wantImports)
	}
}

func TestPublicTLSRegistrationLoopbackOptionControlsOnlyTLSConnect(t *testing.T) {
	for _, test := range []struct {
		name  string
		allow bool
		want  wagonet.Status
	}{
		{name: "default denied", want: wagonet.StatusAccessDenied},
		{name: "explicit TLS grant", allow: true, want: wagonet.StatusInProgress},
	} {
		t.Run(test.name, func(t *testing.T) {
			network := wagonet.New(wagonet.WithConfig(wagonet.Config{StaticIPv4: tlsStaticIPv4()}))
			profile, err := wagonettls.NewClientProfile(1, &cryptotls.Config{}, wagonettls.AllowServerNames("localhost"))
			if err != nil {
				t.Fatal(err)
			}
			options := []wagonettls.Option{wagonettls.WithClientProfile(profile)}
			if test.allow {
				options = append(options, wagonettls.AllowLoopback())
			}
			if err := wagonettls.Register(network, options...); err != nil {
				t.Fatal(err)
			}
			runtime := wago.NewRuntime()
			if err := runtime.Use(network); err != nil {
				t.Fatal(err)
			}
			module, err := runtime.Compile([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})
			if err != nil {
				t.Fatal(err)
			}
			instance, err := runtime.Instantiate(context.Background(), module)
			if err != nil {
				t.Fatal(err)
			}
			defer instance.Close()
			host := tlsExactHost{instance: instance, memory: make([]byte, 256)}
			if got := callTLS(t, runtime, host, "namespace_default", 0); got != wagonet.StatusOK {
				t.Fatalf("namespace_default = %v", got)
			}
			namespaceHandle := binary.LittleEndian.Uint64(host.memory[:8])
			if !abicore.EncodeEndpointV1(host.memory, 16, nscore.Endpoint{Address: netip.MustParseAddr("127.0.0.1"), Port: 443}) {
				t.Fatal("encode loopback")
			}
			copy(host.memory[48:], "localhost")
			if got := callTLS(t, runtime, host, "connect", namespaceHandle, 16, 1, 48, uint64(len("localhost")), 64); got != test.want {
				t.Fatalf("loopback connect = %v, want %v", got, test.want)
			}
			if test.allow {
				streamHandle := binary.LittleEndian.Uint64(host.memory[64:72])
				if got := callTLS(t, runtime, host, "close", streamHandle); got != wagonet.StatusOK {
					t.Fatalf("close = %v", got)
				}
			}
		})
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

type tlsExactHost struct {
	instance *wago.Instance
	memory   []byte
}

func (host tlsExactHost) Memory() []byte           { return host.memory }
func (host tlsExactHost) Instance() *wago.Instance { return host.instance }

func callTLS(t testing.TB, runtime *wago.Runtime, host tlsExactHost, name string, params ...uint64) wagonet.Status {
	t.Helper()
	function, ok := runtime.HostImports()[wagonet.TLSModule+"."+name].(wago.HostFunc)
	if !ok {
		t.Fatalf("TLS import %q missing", name)
	}
	results := []uint64{0}
	function(host, params, results)
	return wagonet.Status(wago.AsI32(results[0]))
}

func tlsStaticIPv4() *wagonet.StaticIPv4Config {
	return &wagonet.StaticIPv4Config{
		Hostname: "tls-loopback", RandSeed: 17,
		HardwareAddress: [6]byte{2, 0, 0, 0, 0, 17}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1},
		IPv4Address: netip.MustParseAddr("192.0.2.17"), MTU: 1500,
		Link: wagonet.PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 4, EgressFrames: 4},
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
