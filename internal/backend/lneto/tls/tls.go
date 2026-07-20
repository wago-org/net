// Package tls integrates the backend-neutral Go TLS worker with one private
// lneto TCP adapter. Private TCP streams never enter the guest resource table.
package tls

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	gotls "github.com/wago-org/net/internal/backend/gotls"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	tcpbackend "github.com/wago-org/net/internal/backend/lneto/tcp"
	"github.com/wago-org/net/internal/checked"
	nscore "github.com/wago-org/net/internal/namespace/core"
	tcpns "github.com/wago-org/net/internal/namespace/tcp"
	tlsns "github.com/wago-org/net/internal/namespace/tls"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/resource"
	"github.com/wago-org/net/internal/tlslimits"
)

const tlsCloseOrder = 19

var (
	ErrInvalidConfig        = errors.New("net/tls: invalid lneto TLS configuration")
	ErrUnknownProfile       = errors.New("net/tls: unknown client profile")
	ErrUnauthorizedName     = errors.New("net/tls: unauthorized server name")
	limitedBroadcastAddress = netip.AddrFrom4([4]byte{255, 255, 255, 255})
)

// Config fixes private TCP storage, TLS queues, and immutable client profiles.
type Config struct {
	MaxStreams                     uint16
	MaxConcurrentHandshakes        uint16
	MaxServerNameBytes             uint16
	MaxServiceAttemptsPerHandshake uint32
	TCP                            tcpbackend.Config
	Engine                         gotls.Limits
	Profiles                       []gotls.Profile
}

// Adapter owns TLS streams and one private raw-byte TCP adapter.
type Adapter struct {
	core     *lnetocore.Namespace
	tcp      *tcpbackend.Adapter
	quotas   *quota.Account
	config   Config
	storage  tlslimits.Plan
	profiles map[uint32]gotls.Profile

	mu         sync.Mutex
	streams    []*stream
	handshakes int
	closed     bool
}

func New(common *lnetocore.Namespace, config Config) (*Adapter, error) {
	config.Engine.MaxServiceAttemptsPerHandshake = config.MaxServiceAttemptsPerHandshake
	storage, ok := validateConfig(config, checked.MaxInt())
	if common == nil || !ok {
		return nil, nscore.Fail(nscore.FailureInvalidArgument, ErrInvalidConfig)
	}
	common.Lock()
	if common.ClosedLocked() || common.PolicyLocked() == nil || common.QuotasLocked() == nil {
		common.Unlock()
		return nil, nscore.Fail(nscore.FailureInvalidArgument, ErrInvalidConfig)
	}
	quotas := common.QuotasLocked()
	common.Unlock()
	adapter := &Adapter{
		core: common, quotas: quotas, config: config, storage: storage,
		profiles: make(map[uint32]gotls.Profile, len(config.Profiles)),
		streams:  make([]*stream, 0, config.MaxStreams),
	}
	for _, input := range config.Profiles {
		profile, err := input.Clone()
		if err != nil {
			return nil, nscore.Fail(nscore.FailureUnsupportedConfiguration, err)
		}
		if _, exists := adapter.profiles[profile.ID]; exists {
			return nil, nscore.Fail(nscore.FailureInvalidArgument, ErrInvalidConfig)
		}
		adapter.profiles[profile.ID] = profile
	}
	privateTCP, err := tcpbackend.New(common, config.TCP)
	if err != nil {
		return nil, err
	}
	adapter.tcp = privateTCP
	if err := common.Install(lnetocore.Participant{CloseOrder: tlsCloseOrder, Close: adapter.CloseLocked}); err != nil {
		common.Lock()
		privateTCP.CloseLocked()
		common.Unlock()
		return nil, err
	}
	return adapter, nil
}

func validConfig(config Config) bool {
	_, ok := validateConfig(config, checked.MaxInt())
	return ok
}

func validateConfig(config Config, maxIntValue uint64) (tlslimits.Plan, bool) {
	if config.MaxServerNameBytes == 0 || config.MaxServerNameBytes > 253 || config.MaxServiceAttemptsPerHandshake == 0 || config.MaxServiceAttemptsPerHandshake > tlslimits.MaxServiceAttempts ||
		config.TCP.MaxListeners != 0 || config.TCP.MaxOutboundStreams < config.MaxStreams || config.TCP.TransmitPackets <= 0 || config.TCP.TransmitPackets > tlslimits.MaxTransportPackets ||
		config.TCP.TransmitPackets > config.TCP.TransmitBytes || len(config.Profiles) == 0 || len(config.Profiles) > tlslimits.MaxProfiles {
		return tlslimits.Plan{}, false
	}
	for _, profile := range config.Profiles {
		if profile.MaxPeerCertificates == 0 || profile.MaxPeerCertificates > tlslimits.MaxPeerCertificates || len(profile.AllowedNames) == 0 || len(profile.AllowedNames) > tlslimits.MaxServerNamesPerProfile {
			return tlslimits.Plan{}, false
		}
	}
	maxCertificateBytes := 0
	for _, profile := range config.Profiles {
		if profile.MaxCertificateChainBytes > maxCertificateBytes {
			maxCertificateBytes = profile.MaxCertificateChainBytes
		}
	}
	plan, ok := tlslimits.Validate(tlslimits.Config{
		MaxStreams: config.MaxStreams, MaxConcurrentHandshakes: config.MaxConcurrentHandshakes,
		PlaintextReceiveBytes: config.Engine.PlaintextReceiveBytes, PlaintextTransmitBytes: config.Engine.PlaintextTransmitBytes,
		CiphertextReceiveBytes: config.Engine.CiphertextReceiveBytes, CiphertextTransmitBytes: config.Engine.CiphertextTransmitBytes,
		TransportReceiveBytes: config.TCP.ReceiveBytes, TransportTransmitBytes: config.TCP.TransmitBytes,
		MaxHandshakeBytes: config.Engine.MaxHandshakeBytes, MaxCertificateChainBytes: maxCertificateBytes,
	}, maxIntValue)
	if !ok || !gotls.ValidLimits(config.Engine) {
		return tlslimits.Plan{}, false
	}
	return plan, true
}

func (adapter *Adapter) TryConnectTLS(remote nscore.Endpoint, profileID uint32, serverName string) (nscore.Resource, nscore.Progress, error) {
	if adapter == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	profile, exists := adapter.profiles[profileID]
	if !exists {
		return nil, 0, nscore.Fail(nscore.FailureInvalidArgument, ErrUnknownProfile)
	}
	if len(serverName) == 0 || len(serverName) > int(adapter.config.MaxServerNameBytes) {
		return nil, 0, nscore.Fail(nscore.FailureInvalidArgument, ErrUnauthorizedName)
	}
	normalized, identity, allowed := profile.AuthorizeServerName(serverName)
	if !allowed {
		return nil, 0, nscore.Fail(nscore.FailureAccessDenied, ErrUnauthorizedName)
	}

	adapter.mu.Lock()
	if adapter.closed {
		adapter.mu.Unlock()
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if len(adapter.streams) >= int(adapter.config.MaxStreams) || adapter.handshakes >= int(adapter.config.MaxConcurrentHandshakes) {
		adapter.mu.Unlock()
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, quota.ErrLimit)
	}
	adapter.handshakes++
	adapter.mu.Unlock()

	created := &stream{owner: adapter, handshakeLive: true}
	if err := adapter.quotas.AcquireTLSStream(&created.retained, adapter.storage.PlaintextBytes, adapter.storage.CiphertextBytes); err != nil {
		adapter.releaseHandshakeSlot(created)
		return nil, 0, mapQuotaError(err)
	}
	if err := adapter.quotas.AcquireTLSHandshake(&created.handshake, 1); err != nil {
		created.retained.Release()
		adapter.releaseHandshakeSlot(created)
		return nil, 0, mapQuotaError(err)
	}

	private, progress, err := adapter.tcp.TryConnectAuthorized(remote, func(compiled *policy.Policy, endpoint nscore.Endpoint) error {
		if !compiled.CheckEndpoint(policy.OperationTLSConnect, endpoint.Address, endpoint.Port) {
			return nscore.Fail(nscore.FailureAccessDenied, tcpbackend.ErrPolicyDenied)
		}
		// TLS is a unicast client surface. Even advanced policy cannot turn
		// multicast or limited broadcast into a meaningful TLS destination.
		if endpoint.Address.IsMulticast() || endpoint.Address == limitedBroadcastAddress {
			return nscore.Fail(nscore.FailureNotSupported, ErrInvalidConfig)
		}
		return nil
	})
	if err != nil {
		created.release()
		return nil, 0, err
	}
	transport, ok := private.(tcpns.Stream)
	if !ok || resource.IsNil(transport) {
		if !resource.IsNil(private) {
			_ = private.Close()
		}
		created.release()
		return nil, 0, nscore.Fail(nscore.FailureIO, ErrInvalidConfig)
	}
	engine, err := gotls.NewClient(transport, profile, normalized, identity, adapter.config.Engine)
	if err != nil {
		_ = transport.Close()
		created.release()
		return nil, 0, nscore.Fail(nscore.FailureUnsupportedConfiguration, err)
	}
	created.engine = engine
	adapter.mu.Lock()
	if adapter.closed {
		adapter.mu.Unlock()
		_ = engine.Close()
		created.release()
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	adapter.streams = append(adapter.streams, created)
	adapter.mu.Unlock()
	if progress == nscore.ProgressDone {
		progress = nscore.ProgressInProgress
	}
	return created, progress, nil
}

func mapQuotaError(err error) error {
	if errors.Is(err, quota.ErrLimit) {
		return nscore.Fail(nscore.FailureResourceLimit, err)
	}
	if errors.Is(err, quota.ErrClosed) {
		return nscore.Fail(nscore.FailureClosed, err)
	}
	return nscore.Fail(nscore.FailureInvalidArgument, err)
}

type stream struct {
	owner         *Adapter
	engine        *gotls.Stream
	retained      quota.Charge
	handshake     quota.Charge
	handshakeLive bool
	closed        bool
	mu            sync.Mutex
}

func (stream *stream) LocalEndpoint() nscore.Endpoint {
	if stream == nil || stream.engine == nil {
		return nscore.Endpoint{}
	}
	return stream.engine.LocalEndpoint()
}
func (stream *stream) RemoteEndpoint() nscore.Endpoint {
	if stream == nil || stream.engine == nil {
		return nscore.Endpoint{}
	}
	return stream.engine.RemoteEndpoint()
}
func (stream *stream) Readiness() nscore.Readiness {
	if stream == nil || stream.engine == nil {
		return nscore.ReadyClosed
	}
	ready := stream.engine.Readiness()
	stream.settleHandshake(ready)
	return ready
}
func (stream *stream) TryService(budget nscore.ServiceBudget) (nscore.ServiceReport, nscore.Progress, error) {
	if stream == nil || stream.engine == nil {
		return nscore.ServiceReport{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	report, progress, err := stream.engine.TryService(budget)
	stream.settleHandshake(stream.engine.Readiness())
	return report, progress, err
}
func (stream *stream) TryFinishConnect() (nscore.Progress, error) {
	if stream == nil || stream.engine == nil {
		return 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	progress, err := stream.engine.TryFinishConnect()
	if err != nil || progress == nscore.ProgressDone {
		stream.settleHandshake(stream.engine.Readiness())
	}
	return progress, err
}
func (stream *stream) TryRead(dst []byte) (nscore.IOResult, error) {
	if stream == nil || stream.engine == nil {
		return nscore.IOResult{}, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	return stream.engine.TryRead(dst)
}
func (stream *stream) TryWrite(src []byte) (nscore.IOResult, error) {
	if stream == nil || stream.engine == nil {
		return nscore.IOResult{}, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	return stream.engine.TryWrite(src)
}
func (stream *stream) TryShutdownWrite() (nscore.Progress, error) {
	if stream == nil || stream.engine == nil {
		return 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	return stream.engine.TryShutdownWrite()
}
func (stream *stream) ConnectionInfo() (tlsns.ConnectionInfo, bool) {
	if stream == nil || stream.engine == nil {
		return tlsns.ConnectionInfo{}, false
	}
	return stream.engine.ConnectionInfo()
}

func (stream *stream) settleHandshake(ready nscore.Readiness) {
	if ready&(nscore.ReadyConnected|nscore.ReadyError|nscore.ReadyClosed) == 0 {
		return
	}
	stream.mu.Lock()
	if stream.handshakeLive {
		stream.handshakeLive = false
		stream.handshake.Release()
		if stream.owner != nil {
			stream.owner.releaseHandshakeSlot(nil)
		}
	}
	stream.mu.Unlock()
}

func (stream *stream) Close() error {
	if stream == nil {
		return nil
	}
	stream.mu.Lock()
	if stream.closed {
		stream.mu.Unlock()
		return nil
	}
	stream.closed = true
	engine := stream.engine
	stream.mu.Unlock()
	var err error
	if engine != nil {
		err = engine.Close()
	}
	stream.release()
	if stream.owner != nil {
		stream.owner.remove(stream)
	}
	return err
}

func (stream *stream) release() {
	stream.mu.Lock()
	if stream.handshakeLive {
		stream.handshakeLive = false
		stream.handshake.Release()
		if stream.owner != nil {
			stream.owner.releaseHandshakeSlot(nil)
		}
	}
	stream.retained.Release()
	stream.mu.Unlock()
}

func (adapter *Adapter) releaseHandshakeSlot(created *stream) {
	adapter.mu.Lock()
	if adapter.handshakes > 0 {
		adapter.handshakes--
	}
	adapter.mu.Unlock()
}

func (adapter *Adapter) remove(target *stream) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	for index, candidate := range adapter.streams {
		if candidate != target {
			continue
		}
		copy(adapter.streams[index:], adapter.streams[index+1:])
		adapter.streams[len(adapter.streams)-1] = nil
		adapter.streams = adapter.streams[:len(adapter.streams)-1]
		return
	}
}

// CloseLocked wakes and joins every worker while the shared core lock is held.
// Private TCP resources are then closed by their own immediately following
// participant, avoiding recursive acquisition of the core lock.
func (adapter *Adapter) CloseLocked() {
	if adapter == nil {
		return
	}
	adapter.mu.Lock()
	if adapter.closed {
		adapter.mu.Unlock()
		return
	}
	adapter.closed = true
	streams := append([]*stream(nil), adapter.streams...)
	adapter.streams = nil
	adapter.mu.Unlock()
	for _, stream := range streams {
		stream.mu.Lock()
		stream.closed = true
		engine := stream.engine
		stream.mu.Unlock()
		if engine != nil {
			engine.CloseWorkersLocked()
		}
		stream.release()
	}
}
