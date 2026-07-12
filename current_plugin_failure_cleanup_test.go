package net

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	instancestate "github.com/wago-org/net/internal/instance/core"
	dnsinstance "github.com/wago-org/net/internal/instance/dns"
	tcpinstance "github.com/wago-org/net/internal/instance/tcp"
	udpinstance "github.com/wago-org/net/internal/instance/udp"
	"github.com/wago-org/net/internal/namespace"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type failedSocketSetupSnapshot struct {
	state                 *instancestate.State
	link                  *packetlink.Link
	udp, listener, stream resource.Handle
	dns                   resource.Handle
}

type failingSocketSetupExtension struct {
	network  *Extension
	failure  error
	captured chan failedSocketSetupSnapshot
}

func (*failingSocketSetupExtension) Info() wago.ExtensionInfo {
	return wago.ExtensionInfo{
		ID: "test.net-failed-socket-setup", Name: "failed socket setup", Version: "1.0.0",
		Repository: "https://example.com/net-failed-socket-setup", License: "Apache-2.0",
		RequiresCapabilities: []wago.PluginCapability{wago.PluginInstanceHooks},
	}
}

func (e *failingSocketSetupExtension) Register(reg *wago.Registry) error {
	lifecycle, err := reg.InstanceLifecycle()
	if err != nil {
		return err
	}
	lifecycle.AfterInstantiate(func(_ *wago.InstantiateContext, instance *wago.Instance) error {
		state, ok := e.network.instanceManager().ForInstance(instance)
		if !ok {
			return errors.New("networking state was not attached before failed socket setup")
		}
		udpHandle, progress, err := udpinstance.Bind(state, state.NamespaceHandle(), namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.71"), Port: 4401})
		if err != nil || progress != namespace.ProgressDone {
			return fmt.Errorf("bind UDP before failure: handle=%v progress=%v: %w", udpHandle, progress, err)
		}
		if progress, err = udpinstance.Send(state, udpHandle, []byte("retained-before-failure"), namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.90"), Port: 4402}); err != nil || progress != namespace.ProgressDone {
			return fmt.Errorf("send UDP before failure: progress=%v: %w", progress, err)
		}
		listener, progress, err := tcpinstance.Listen(state, state.NamespaceHandle(), namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.71"), Port: 4501})
		if err != nil || progress != namespace.ProgressDone {
			return fmt.Errorf("listen TCP before failure: handle=%v progress=%v: %w", listener, progress, err)
		}
		stream, progress, err := tcpinstance.Connect(state, state.NamespaceHandle(), namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.90"), Port: 4502})
		if err != nil || progress != namespace.ProgressInProgress {
			return fmt.Errorf("connect TCP before failure: handle=%v progress=%v: %w", stream, progress, err)
		}
		dns, progress, err := dnsinstance.Resolve(state, state.NamespaceHandle(), namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA})
		if err != nil || (progress != namespace.ProgressInProgress && progress != namespace.ProgressDone) {
			return fmt.Errorf("resolve DNS before failure: handle=%v progress=%v: %w", dns, progress, err)
		}
		value, err := state.LookupNamespace(state.NamespaceHandle())
		if err != nil {
			return fmt.Errorf("lookup namespace before failure: %w", err)
		}
		backend, ok := nscore.ResolveNamespaceBase(value).(interface{ Link() *packetlink.Link })
		if !ok || backend.Link() == nil {
			return fmt.Errorf("namespace base %T does not expose its packet link", value)
		}
		e.captured <- failedSocketSetupSnapshot{
			state: state, link: backend.Link(), udp: udpHandle, listener: listener, stream: stream, dns: dns,
		}
		return e.failure
	})
	return nil
}

func TestAfterInstantiateFailureRetiresActiveSockets(t *testing.T) {
	failure := errors.New("later socket setup failed")
	network := Init(currentPluginNetworkConfig())
	setup := &failingSocketSetupExtension{network: network, failure: failure, captured: make(chan failedSocketSetupSnapshot, 1)}
	runtime := wago.NewRuntime()
	defer runtime.Close()
	if err := runtime.Use(network, wago.WithPluginGrants(wago.PluginHostImports, wago.PluginInstanceHooks)); err != nil {
		t.Fatalf("Use networking: %v", err)
	}
	if err := runtime.Use(setup, wago.WithPluginGrants(wago.PluginInstanceHooks)); err != nil {
		t.Fatalf("Use failing setup: %v", err)
	}
	if instance, err := runtime.Instantiate(context.Background(), emptyModule(t, runtime)); !errors.Is(err, failure) || instance != nil {
		t.Fatalf("Instantiate after socket setup = %p, %v, want nil, %v", instance, err, failure)
	}
	snapshot := <-setup.captured
	for handle, kind := range map[resource.Handle]resource.Kind{
		snapshot.udp: resource.KindUDPSocket, snapshot.listener: resource.KindTCPListener,
		snapshot.stream: resource.KindTCPStream, snapshot.dns: resource.KindDNSQuery,
	} {
		if _, err := snapshot.state.Resources().Lookup(handle, kind); !errors.Is(err, resource.ErrClosed) {
			t.Fatalf("failed-setup handle %v (%v) lookup = %v, want ErrClosed", handle, kind, err)
		}
	}
	if got := snapshot.state.Resources().Len(); got != 0 {
		t.Fatalf("failed-setup resources after close = %d, want 0", got)
	}
	if usage, closed := snapshot.state.Quotas().Snapshot(); !closed || usage != (quota.Usage{}) {
		t.Fatalf("failed-setup quota after close = %+v, closed=%v", usage, closed)
	}
	if readiness := snapshot.state.Readiness().Snapshot(); !readiness.Closed || readiness.Registrations != 0 {
		t.Fatalf("failed-setup readiness after close = %+v", readiness)
	}
	if link := snapshot.link.Snapshot(); !link.Closed || link.IngressFrames != 0 || link.EgressFrames != 0 {
		t.Fatalf("failed-setup packet link after close = %+v", link)
	}
	if got := network.instanceManager().Len(); got != 0 {
		t.Fatalf("failed-setup networking states = %d, want 0", got)
	}
}
