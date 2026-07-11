package net

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	"github.com/wago-org/net/internal/namespace"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/plugin"

	wago "github.com/wago-org/wago"
)

func TestExtensionMetadataAndABIBinding(t *testing.T) {
	ext := Init(Config{})
	info := ext.Info()
	if info.ID != "github.com/wago-org/net" || info.Stability != wago.Experimental {
		t.Fatalf("Info = %+v", info)
	}
	if got := info.Compat.Engines["wago"]; got != ">=0.1.0" {
		t.Fatalf("wago compatibility = %q", got)
	}

	rt := wago.NewRuntime()
	if err := rt.Use(ext); err != nil {
		t.Fatalf("Use: %v", err)
	}
	if got := rt.Capabilities(); !reflect.DeepEqual(got, []wago.Capability{CapDNS, CapInfo, CapTCP, CapUDP}) {
		t.Fatalf("Capabilities = %v", got)
	}
	imports := rt.ProvidedImports()
	if len(imports) != 24 {
		t.Fatalf("ProvidedImports length = %d, want 24", len(imports))
	}
	got := imports[0]
	if got.Module != Module || got.Name != "abi_version" || !got.HasCapability || got.Capability != CapInfo {
		t.Fatalf("abi_version metadata = %+v", got)
	}
	if len(got.Params) != 0 || !reflect.DeepEqual(got.Results, []wago.ValType{wago.ValI32}) {
		t.Fatalf("abi_version signature = %v -> %v", got.Params, got.Results)
	}
	wantUDP := map[string][]wago.ValType{
		"bind":              {wago.ValI64, wago.ValI32, wago.ValI32},
		"close":             {wago.ValI64},
		"namespace_default": {wago.ValI32},
		"poll":              {wago.ValI32, wago.ValI32, wago.ValI32, wago.ValI32},
		"receive":           {wago.ValI64, wago.ValI32, wago.ValI32, wago.ValI32},
		"send":              {wago.ValI64, wago.ValI32, wago.ValI32, wago.ValI32},
	}
	wantDNS := map[string][]wago.ValType{
		"cancel":            {wago.ValI64},
		"close":             {wago.ValI64},
		"namespace_default": {wago.ValI32},
		"next":              {wago.ValI64, wago.ValI32},
		"poll":              {wago.ValI32, wago.ValI32, wago.ValI32, wago.ValI32},
		"resolve":           {wago.ValI64, wago.ValI32, wago.ValI32},
	}
	wantTCP := map[string][]wago.ValType{
		"accept":            {wago.ValI64, wago.ValI32},
		"close_listener":    {wago.ValI64},
		"close_stream":      {wago.ValI64},
		"connect":           {wago.ValI64, wago.ValI32, wago.ValI32},
		"finish_connect":    {wago.ValI64},
		"listen":            {wago.ValI64, wago.ValI32, wago.ValI32},
		"namespace_default": {wago.ValI32},
		"poll":              {wago.ValI32, wago.ValI32, wago.ValI32, wago.ValI32},
		"read":              {wago.ValI64, wago.ValI32, wago.ValI32, wago.ValI32},
		"shutdown_write":    {wago.ValI64},
		"write":             {wago.ValI64, wago.ValI32, wago.ValI32, wago.ValI32},
	}
	for _, spec := range imports[1:] {
		var params []wago.ValType
		var capability wago.Capability
		switch spec.Module {
		case DNSModule:
			params = wantDNS[spec.Name]
			capability = CapDNS
			delete(wantDNS, spec.Name)
		case UDPModule:
			params = wantUDP[spec.Name]
			capability = CapUDP
			delete(wantUDP, spec.Name)
		case TCPModule:
			params = wantTCP[spec.Name]
			capability = CapTCP
			delete(wantTCP, spec.Name)
		default:
			t.Fatalf("unexpected networking import metadata = %+v", spec)
		}
		if params == nil || !spec.HasCapability || spec.Capability != capability || !reflect.DeepEqual(spec.Params, params) || !reflect.DeepEqual(spec.Results, []wago.ValType{wago.ValI32}) {
			t.Fatalf("protocol import metadata = %+v", spec)
		}
	}
	if len(wantDNS) != 0 || len(wantUDP) != 0 || len(wantTCP) != 0 {
		t.Fatalf("missing protocol imports: DNS=%v UDP=%v TCP=%v", wantDNS, wantUDP, wantTCP)
	}

	fn, ok := rt.HostImports()[Module+".abi_version"].(wago.HostFunc)
	if !ok {
		t.Fatalf("abi_version binding has type %T", rt.HostImports()[Module+".abi_version"])
	}
	results := make([]uint64, 1)
	fn(nil, nil, results)
	if got := uint32(results[0]); got != ABIVersion1 {
		t.Fatalf("abi_version = %#x, want %#x", got, ABIVersion1)
	}
}

func TestProtocolConfigurationAdvertisesCompleteGuestSurface(t *testing.T) {
	extension := Init(Config{StaticIPv4: &StaticIPv4Config{
		Hostname:               "tcp1",
		RandSeed:               1,
		HardwareAddress:        [6]byte{2, 0, 0, 0, 0, 1},
		GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 2},
		IPv4Address:            netip.MustParseAddr("192.0.2.1"),
		MTU:                    1500,
		Link:                   PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 2, EgressFrames: 2},
		TCP: TCPConfig{
			MaxListeners: 1, MaxOutboundStreams: 1, AcceptBacklog: 1,
			ReceiveBytes: 256, TransmitBytes: 256, TransmitPackets: 4,
		},
	}})
	runtime := wago.NewRuntime()
	if err := runtime.Use(extension); err != nil {
		t.Fatalf("Use TCP-configured extension: %v", err)
	}
	if got := runtime.Capabilities(); !reflect.DeepEqual(got, []wago.Capability{CapDNS, CapInfo, CapTCP, CapUDP}) {
		t.Fatalf("protocol capabilities = %v", got)
	}
	var dnsImports, tcpImports int
	for _, spec := range runtime.ProvidedImports() {
		if spec.Module == TCPModule {
			tcpImports++
		}
		if spec.Module == DNSModule {
			dnsImports++
		}
	}
	if dnsImports != 6 || tcpImports != 11 {
		t.Fatalf("protocol import counts = DNS %d/6 TCP %d/11", dnsImports, tcpImports)
	}
}

func TestSelectiveBackendAssemblyRejectsIncompatibleFamily(t *testing.T) {
	extension := New(WithConfig(Config{StaticIPv4: selectiveTestStaticIPv4()}))
	backend := plugin.NewBackend("other", nil, func(any) (nscore.Service, error) {
		return nscore.Service{Key: "test", Value: new(int)}, nil
	})
	if err := extension.RegisterModule(plugin.NewModule(plugin.ModuleTCP, func(*wago.Registry, plugin.Host) {}, backend)); err != nil {
		t.Fatal(err)
	}
	if err := wago.NewRuntime().Use(extension); !errors.Is(err, plugin.ErrIncompatibleBackend) {
		t.Fatalf("Use incompatible backend = %v", err)
	}
	if extension.instanceManager() != nil {
		t.Fatal("incompatible backend constructed an instance manager")
	}
}

func TestSelectiveBackendAssemblyRollsBackCoreBeforePublication(t *testing.T) {
	extension := New(WithConfig(Config{StaticIPv4: selectiveTestStaticIPv4()}))
	installErr := errors.New("install selected adapter")
	var common *lnetocore.Namespace
	backend := plugin.NewBackend(plugin.BackendLnetoV1, nil, func(base any) (nscore.Service, error) {
		common, _ = base.(*lnetocore.Namespace)
		return nscore.Service{}, installErr
	})
	if err := extension.RegisterModule(plugin.NewModule(plugin.ModuleTCP, func(*wago.Registry, plugin.Host) {}, backend)); err != nil {
		t.Fatal(err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(extension); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Instantiate(context.Background(), emptyModule(t, runtime)); !errors.Is(err, installErr) {
		t.Fatalf("Instantiate install failure = %v", err)
	}
	if common == nil || common.Link() == nil || !common.Link().Snapshot().Closed {
		t.Fatalf("rolled-back core = %#v", common)
	}
	if manager := extension.instanceManager(); manager == nil || manager.Len() != 0 {
		t.Fatalf("published failed state: manager=%v", manager)
	}
}

func selectiveTestStaticIPv4() *StaticIPv4Config {
	return &StaticIPv4Config{
		Hostname: "selective", RandSeed: 99,
		HardwareAddress: [6]byte{2, 0, 0, 0, 0, 99}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 100},
		IPv4Address: netip.MustParseAddr("192.0.2.99"), MTU: 1500,
		Link: PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 1, EgressFrames: 1},
	}
}

func TestExtensionRejectsInvalidStaticNamespaceBeforeRegistration(t *testing.T) {
	extension := Init(Config{StaticIPv4: &StaticIPv4Config{}})
	runtime := wago.NewRuntime()
	err := runtime.Use(extension)
	failure, ok := namespace.FailureOf(err)
	if !ok || failure != namespace.FailureInvalidArgument {
		t.Fatalf("invalid static namespace error = %v", err)
	}
	if extension.instanceManager() != nil {
		t.Fatal("invalid extension constructed an instance manager")
	}
}

func TestStatusValuesStable(t *testing.T) {
	want := []struct {
		status Status
		value  int32
		name   string
	}{
		{StatusOK, 0, "OK"},
		{StatusAgain, 1, "AGAIN"},
		{StatusInProgress, 2, "IN_PROGRESS"},
		{StatusEOF, 3, "EOF"},
		{StatusAccessDenied, 4, "ACCESS_DENIED"},
		{StatusInvalidArgument, 5, "INVALID_ARGUMENT"},
		{StatusBadHandle, 6, "BAD_HANDLE"},
		{StatusInvalidState, 7, "INVALID_STATE"},
		{StatusNotSupported, 8, "NOT_SUPPORTED"},
		{StatusNoMemory, 9, "NO_MEMORY"},
		{StatusResourceLimit, 10, "RESOURCE_LIMIT"},
		{StatusAddressInUse, 11, "ADDRESS_IN_USE"},
		{StatusAddressNotAvailable, 12, "ADDRESS_NOT_AVAILABLE"},
		{StatusRemoteUnreachable, 13, "REMOTE_UNREACHABLE"},
		{StatusConnectionRefused, 14, "CONNECTION_REFUSED"},
		{StatusConnectionReset, 15, "CONNECTION_RESET"},
		{StatusConnectionAborted, 16, "CONNECTION_ABORTED"},
		{StatusConnectionBroken, 17, "CONNECTION_BROKEN"},
		{StatusTimedOut, 18, "TIMED_OUT"},
		{StatusMessageTooLarge, 19, "MESSAGE_TOO_LARGE"},
		{StatusNameNotFound, 20, "NAME_NOT_FOUND"},
		{StatusTemporaryFailure, 21, "TEMPORARY_FAILURE"},
		{StatusIO, 22, "IO"},
		{StatusCanceled, 23, "CANCELED"},
		{StatusOther, 24, "OTHER"},
	}
	for _, tc := range want {
		if int32(tc.status) != tc.value || tc.status.String() != tc.name {
			t.Fatalf("status %q = %d/%q, want %d/%q", tc.name, tc.status, tc.status, tc.value, tc.name)
		}
	}
	if got := Status(1000).String(); got != "UNKNOWN" {
		t.Fatalf("unknown status string = %q", got)
	}
}
