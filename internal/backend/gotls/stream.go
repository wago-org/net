// Package gotls owns Wago's bounded worker integration with Go's standard
// crypto/tls and crypto/x509 implementations.
package gotls

import (
	"context"
	"crypto/sha256"
	cryptotls "crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"

	nscore "github.com/wago-org/net/internal/namespace/core"
	tlsns "github.com/wago-org/net/internal/namespace/tls"
)

// Transport is the private backend-neutral reliable byte stream owned by one
// TLS stream. It is never published in the guest resource table.
type Transport interface {
	nscore.Resource
	LocalEndpoint() nscore.Endpoint
	RemoteEndpoint() nscore.Endpoint
	TryFinishConnect() (nscore.Progress, error)
	TryRead([]byte) (nscore.IOResult, error)
	TryWrite([]byte) (nscore.IOResult, error)
	TryShutdownWrite() (nscore.Progress, error)
}

// Stream owns one crypto/tls client, fixed queues, exactly three bounded worker
// goroutines, and the private transport.
type Stream struct {
	transport Transport
	local     nscore.Endpoint
	remote    nscore.Endpoint
	bridge    *bridgeConn
	tls       *cryptotls.Conn
	limits    Limits

	cancel context.CancelFunc
	ready  chan struct{}
	wg     sync.WaitGroup

	mu   sync.Mutex
	cond *sync.Cond

	rxPlain       byteRing
	txPlain       byteRing
	writeScratch  []byte
	cipherScratch []byte

	verified        bool
	serviceAttempts uint32
	cleanEOF        bool
	shutdown        bool
	shutdownDone    bool
	closed          bool
	terminal        error
	info            tlsns.ConnectionInfo
	profile         Profile
	identity        tlsns.IdentityType
}

func NewClient(transport Transport, profile Profile, serverName string, identity tlsns.IdentityType, limits Limits) (*Stream, error) {
	if transport == nil || !limits.valid() || (identity != tlsns.IdentityDNS && identity != tlsns.IdentityIP) {
		return nil, ErrInvalidConfig
	}
	cloned, err := profile.Clone()
	if err != nil {
		return nil, err
	}
	config := cloned.Config.Clone()
	config.ServerName = serverName
	local, remote := transport.LocalEndpoint(), transport.RemoteEndpoint()
	if !local.Valid() || !remote.Valid() {
		return nil, ErrInvalidConfig
	}
	bridge := newBridgeConn(limits.CiphertextReceiveBytes, limits.CiphertextTransmitBytes, limits.MaxHandshakeBytes)
	ctx, cancel := context.WithCancel(context.Background())
	stream := &Stream{
		transport: transport, local: local, remote: remote, bridge: bridge, tls: cryptotls.Client(bridge, config), limits: limits,
		cancel: cancel, ready: make(chan struct{}), rxPlain: newByteRing(limits.PlaintextReceiveBytes),
		txPlain: newByteRing(limits.PlaintextTransmitBytes), writeScratch: make([]byte, 16<<10),
		cipherScratch: make([]byte, 16<<10),
		profile:       cloned, identity: identity,
	}
	stream.cond = sync.NewCond(&stream.mu)
	stream.wg.Add(3)
	go stream.handshakeWorker(ctx)
	go stream.readWorker()
	go stream.writeWorker()
	return stream, nil
}

func (stream *Stream) handshakeWorker(ctx context.Context) {
	defer stream.wg.Done()
	err := stream.tls.HandshakeContext(ctx)
	if err == nil {
		err = stream.validateConnection()
	}
	stream.mu.Lock()
	if err != nil {
		stream.terminal = mapTLSError(err)
	} else {
		stream.verified = true
	}
	stream.bridge.finishHandshake()
	close(stream.ready)
	stream.cond.Broadcast()
	stream.mu.Unlock()
}

func (stream *Stream) validateConnection() error {
	state := stream.tls.ConnectionState()
	if len(state.PeerCertificates) == 0 || len(state.PeerCertificates) > int(stream.profile.MaxPeerCertificates) {
		return ErrCertificateLimit
	}
	total := 0
	for _, certificate := range state.PeerCertificates {
		total += len(certificate.Raw)
		if total > stream.profile.MaxCertificateChainBytes {
			return ErrCertificateLimit
		}
	}
	if len(state.VerifiedChains) == 0 {
		return x509.UnknownAuthorityError{}
	}
	if stream.profile.RequiredALPN != "" && state.NegotiatedProtocol != stream.profile.RequiredALPN {
		return ErrALPN
	}
	stream.info = tlsns.ConnectionInfo{
		LocalEndpoint: stream.local, RemoteEndpoint: stream.remote,
		TLSVersion: state.Version, CipherSuite: state.CipherSuite, NegotiatedALPN: state.NegotiatedProtocol,
		Resumed: state.DidResume, PeerLeafSPKI256: sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo),
		VerifiedIdentity: stream.identity,
	}
	return nil
}

func (stream *Stream) readWorker() {
	defer stream.wg.Done()
	<-stream.ready
	stream.mu.Lock()
	failed := stream.terminal != nil || stream.closed
	stream.mu.Unlock()
	if failed {
		return
	}
	buffer := make([]byte, 16<<10)
	for {
		count, err := stream.tls.Read(buffer)
		if count != 0 {
			stream.mu.Lock()
			written := 0
			for written < count && !stream.closed {
				for stream.rxPlain.free() == 0 && !stream.closed {
					stream.cond.Wait()
				}
				written += stream.rxPlain.write(buffer[written:count])
				stream.cond.Broadcast()
			}
			stream.mu.Unlock()
		}
		if err != nil {
			stream.mu.Lock()
			if errors.Is(err, io.EOF) {
				stream.cleanEOF = true
			} else if !stream.closed {
				stream.terminal = mapTLSError(err)
			}
			stream.cond.Broadcast()
			stream.mu.Unlock()
			return
		}
	}
}

func (stream *Stream) writeWorker() {
	defer stream.wg.Done()
	<-stream.ready
	for {
		stream.mu.Lock()
		for stream.txPlain.len() == 0 && !stream.shutdown && !stream.closed && stream.terminal == nil {
			stream.cond.Wait()
		}
		if stream.closed || stream.terminal != nil {
			stream.mu.Unlock()
			return
		}
		if stream.txPlain.len() == 0 && stream.shutdown {
			stream.mu.Unlock()
			err := stream.tls.CloseWrite()
			stream.mu.Lock()
			if err != nil && !stream.closed {
				stream.terminal = mapTLSError(err)
			} else {
				stream.shutdownDone = true
			}
			stream.cond.Broadcast()
			stream.mu.Unlock()
			return
		}
		count := stream.txPlain.peek(stream.writeScratch)
		stream.mu.Unlock()
		written, err := stream.tls.Write(stream.writeScratch[:count])
		stream.mu.Lock()
		stream.txPlain.discard(written)
		stream.cond.Broadcast()
		if err != nil {
			if !stream.closed {
				stream.terminal = mapTLSError(err)
			}
			stream.mu.Unlock()
			return
		}
		stream.mu.Unlock()
	}
}

// TryService performs finite private transport work without waiting for a
// worker. Every loop is bounded by both the caller budget and profile limit.
func (stream *Stream) TryService(budget nscore.ServiceBudget) (nscore.ServiceReport, nscore.Progress, error) {
	if stream == nil || !budget.Valid() {
		return nscore.ServiceReport{}, 0, nscore.Fail(nscore.FailureInvalidArgument, ErrInvalidConfig)
	}
	stream.mu.Lock()
	closed := stream.closed
	if !closed && !stream.verified && stream.terminal == nil {
		stream.serviceAttempts++
		if stream.serviceAttempts > stream.limits.MaxServiceAttemptsPerHandshake {
			stream.terminal = nscore.Fail(nscore.FailureResourceLimit, ErrHandshakeLimit)
			stream.cond.Broadcast()
		}
	}
	terminal := stream.terminal
	stream.mu.Unlock()
	if closed {
		return nscore.ServiceReport{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if terminal != nil {
		stream.bridge.abort(terminal)
		return nscore.ServiceReport{}, 0, terminal
	}
	progress, err := stream.transport.TryFinishConnect()
	if err != nil {
		stream.fail(err)
		return nscore.ServiceReport{}, 0, err
	}
	if progress != nscore.ProgressDone {
		return nscore.ServiceReport{}, nscore.ProgressWouldBlock, nil
	}

	var report nscore.ServiceReport
	limit := min(stream.limits.MaxRecordsPerService, int(budget.Operations))
	for attempt := 0; attempt < limit && report.Bytes < budget.Bytes && report.Packets < budget.Packets; attempt++ {
		remaining := int(budget.Bytes - report.Bytes)
		worked, bytes, serviceErr := stream.pumpOnce(remaining)
		if serviceErr != nil {
			stream.fail(serviceErr)
			return report, serviceProgress(report), serviceErr
		}
		if !worked {
			break
		}
		report.Operations++
		if bytes != 0 {
			report.Packets++
			report.Bytes += uint32(bytes)
		}
	}
	return report, serviceProgress(report), nil
}

func (stream *Stream) pumpOnce(byteBudget int) (bool, int, error) {
	if byteBudget <= 0 {
		return false, 0, nil
	}
	count := stream.bridge.peekCipher(stream.cipherScratch[:min(len(stream.cipherScratch), byteBudget)])
	if count != 0 {
		result, err := stream.transport.TryWrite(stream.cipherScratch[:count])
		if err != nil {
			return false, 0, err
		}
		if result.State == nscore.IOReady {
			stream.bridge.discardCipher(result.Bytes)
			return true, result.Bytes, nil
		}
		if result.State != nscore.IOWouldBlock {
			return false, 0, nscore.Fail(nscore.FailureConnectionBroken, io.ErrUnexpectedEOF)
		}
	}
	free := min(stream.bridge.inboundFree(), min(len(stream.cipherScratch), byteBudget))
	if free == 0 {
		return false, 0, nil
	}
	result, err := stream.transport.TryRead(stream.cipherScratch[:free])
	if err != nil {
		return false, 0, err
	}
	switch result.State {
	case nscore.IOReady:
		fed, err := stream.bridge.feedCipher(stream.cipherScratch[:result.Bytes])
		return fed != 0, fed, err
	case nscore.IOEOF:
		stream.bridge.setPeerEOF()
		return true, 0, nil
	case nscore.IOWouldBlock:
		return false, 0, nil
	default:
		return false, 0, nscore.Fail(nscore.FailureIO, ErrInvalidConfig)
	}
}

func serviceProgress(report nscore.ServiceReport) nscore.Progress {
	if report.Operations != 0 {
		return nscore.ProgressDone
	}
	return nscore.ProgressWouldBlock
}

func (stream *Stream) fail(err error) {
	stream.mu.Lock()
	if stream.terminal == nil && !stream.closed {
		stream.terminal = mapTLSError(err)
	}
	stream.cond.Broadcast()
	stream.mu.Unlock()
	stream.bridge.abort(err)
}

func (stream *Stream) LocalEndpoint() nscore.Endpoint  { return stream.local }
func (stream *Stream) RemoteEndpoint() nscore.Endpoint { return stream.remote }

func (stream *Stream) TryFinishConnect() (nscore.Progress, error) {
	_, _, serviceErr := stream.TryService(nscore.ServiceBudget{Packets: uint32(stream.limits.MaxRecordsPerService), Bytes: uint32(len(stream.cipherScratch) * stream.limits.MaxRecordsPerService), Operations: uint32(stream.limits.MaxRecordsPerService)})
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closed {
		return 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if stream.terminal != nil {
		return 0, stream.terminal
	}
	if stream.verified {
		return nscore.ProgressDone, nil
	}
	if serviceErr != nil {
		return 0, serviceErr
	}
	return nscore.ProgressInProgress, nil
}

func (stream *Stream) TryRead(dst []byte) (nscore.IOResult, error) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closed {
		return nscore.IOResult{}, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if len(dst) == 0 {
		return nscore.IOResult{State: nscore.IOReady}, nil
	}
	if stream.rxPlain.len() != 0 {
		count := stream.rxPlain.read(dst)
		stream.cond.Broadcast()
		return nscore.IOResult{Bytes: count, State: nscore.IOReady}, nil
	}
	if stream.terminal != nil {
		return nscore.IOResult{}, stream.terminal
	}
	if stream.cleanEOF {
		return nscore.IOResult{State: nscore.IOEOF}, nil
	}
	return nscore.IOResult{State: nscore.IOWouldBlock}, nil
}

func (stream *Stream) TryWrite(src []byte) (nscore.IOResult, error) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closed {
		return nscore.IOResult{}, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if stream.terminal != nil {
		return nscore.IOResult{}, stream.terminal
	}
	if stream.shutdown {
		return nscore.IOResult{}, nscore.Fail(nscore.FailureInvalidState, net.ErrClosed)
	}
	if !stream.verified {
		return nscore.IOResult{State: nscore.IOWouldBlock}, nil
	}
	if len(src) == 0 {
		return nscore.IOResult{State: nscore.IOReady}, nil
	}
	count := stream.txPlain.write(src)
	if count == 0 {
		return nscore.IOResult{State: nscore.IOWouldBlock}, nil
	}
	stream.cond.Broadcast()
	return nscore.IOResult{Bytes: count, State: nscore.IOReady}, nil
}

func (stream *Stream) TryShutdownWrite() (nscore.Progress, error) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closed {
		return 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if stream.terminal != nil {
		return 0, stream.terminal
	}
	if !stream.verified {
		return nscore.ProgressInProgress, nil
	}
	stream.shutdown = true
	stream.cond.Broadcast()
	if stream.shutdownDone {
		return nscore.ProgressDone, nil
	}
	return nscore.ProgressInProgress, nil
}

func (stream *Stream) ConnectionInfo() (tlsns.ConnectionInfo, bool) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return stream.info, stream.verified && stream.terminal == nil && !stream.closed
}

func (stream *Stream) Readiness() nscore.Readiness {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closed {
		return nscore.ReadyClosed
	}
	var ready nscore.Readiness
	if stream.terminal != nil {
		return nscore.ReadyError | nscore.ReadyClosed
	}
	if stream.verified {
		ready |= nscore.ReadyConnected
		if !stream.shutdown && stream.txPlain.free() != 0 {
			ready |= nscore.ReadyWritable
		}
	}
	if stream.rxPlain.len() != 0 || stream.cleanEOF {
		ready |= nscore.ReadyReadable
	}
	return ready
}

// Close aborts locally, wakes every worker, waits only for local worker exit,
// and then closes the private transport. It never waits for peer packets.
func (stream *Stream) Close() error {
	if stream == nil {
		return nil
	}
	stream.mu.Lock()
	if stream.closed {
		stream.mu.Unlock()
		return nil
	}
	stream.closed = true
	stream.cond.Broadcast()
	stream.mu.Unlock()
	stream.cancel()
	stream.bridge.abort(context.Canceled)
	stream.wg.Wait()
	stream.mu.Lock()
	stream.rxPlain.clear()
	stream.txPlain.clear()
	clear(stream.writeScratch)
	clear(stream.cipherScratch)
	stream.mu.Unlock()
	return stream.transport.Close()
}

// CloseWorkersLocked is used only by shared-backend teardown while the private
// transport's owner lock is already held. Its transport is closed by the TCP
// participant immediately afterward.
func (stream *Stream) CloseWorkersLocked() {
	if stream == nil {
		return
	}
	stream.mu.Lock()
	if !stream.closed {
		stream.closed = true
		stream.cond.Broadcast()
	}
	stream.mu.Unlock()
	stream.cancel()
	stream.bridge.abort(context.Canceled)
	stream.wg.Wait()
}

func mapTLSError(err error) error {
	if err == nil {
		return nil
	}
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var certificate x509.CertificateInvalidError
	var record cryptotls.RecordHeaderError
	switch {
	case errors.As(err, &unknown), errors.As(err, &hostname), errors.As(err, &certificate):
		return nscore.Fail(nscore.FailureTLSAuthentication, err)
	case errors.Is(err, ErrALPN):
		return nscore.Fail(nscore.FailureTLSAuthentication, err)
	case errors.Is(err, ErrHandshakeLimit), errors.Is(err, ErrCertificateLimit):
		return nscore.Fail(nscore.FailureResourceLimit, err)
	case errors.As(err, &record), errors.Is(err, io.ErrUnexpectedEOF):
		return nscore.Fail(nscore.FailureTLSProtocol, err)
	case errors.Is(err, context.Canceled), errors.Is(err, net.ErrClosed), errors.Is(err, errBridgeClosed):
		return nscore.Fail(nscore.FailureCanceled, err)
	default:
		return nscore.Fail(nscore.FailureTLSProtocol, err)
	}
}
