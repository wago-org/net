package gotls

import (
	cryptotls "crypto/tls"
	"net"
	"runtime"
	"testing"
	"time"

	nscore "github.com/wago-org/net/internal/namespace/core"
	tlsns "github.com/wago-org/net/internal/namespace/tls"
)

func TestBoundedClientSessionCacheRetainsExactFiniteState(t *testing.T) {
	cache, err := newBoundedClientSessionCache(2, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	session := captureTestSession(t, 0)
	cache.Put("one", session)
	cache.Put("two", session)
	if _, ok := cache.Get("one"); !ok {
		t.Fatal("first session missing")
	}
	cache.Put("three", session)
	if _, ok := cache.Get("two"); ok {
		t.Fatal("least-recently-used session was not evicted")
	}
	if _, ok := cache.Get("one"); !ok {
		t.Fatal("recently used session was evicted")
	}
	if _, ok := cache.Get("three"); !ok {
		t.Fatal("new session missing")
	}

	cache.Put("one", nil)
	if _, ok := cache.Get("one"); ok {
		t.Fatal("nil put did not remove session")
	}
	cache.clear()
	if len(cache.entries) != 0 || cache.usedBytes != 0 {
		t.Fatalf("cleared cache retained entries=%d bytes=%d", len(cache.entries), cache.usedBytes)
	}
	if _, ok := cache.Get("three"); ok {
		t.Fatal("cleared cache returned a session")
	}
}

func TestBoundedClientSessionCacheRejectsOversizedAndInvalidBounds(t *testing.T) {
	if _, err := newBoundedClientSessionCache(0, 1); err != ErrInvalidConfig {
		t.Fatalf("zero entries = %v", err)
	}
	if _, err := newBoundedClientSessionCache(1, 0); err != ErrInvalidConfig {
		t.Fatalf("zero bytes = %v", err)
	}
	cache, err := newBoundedClientSessionCache(1, 256)
	if err != nil {
		t.Fatal(err)
	}
	cache.Put("oversized", captureTestSession(t, 1024))
	if _, ok := cache.Get("oversized"); ok {
		t.Fatal("oversized session retained")
	}
}

func TestBoundedClientSessionCacheResumesStandardGoTLS13(t *testing.T) {
	certificate, roots := testCertificate(t, "resume.example.com")
	serverConfig := &cryptotls.Config{
		Certificates: []cryptotls.Certificate{certificate},
		MinVersion:   cryptotls.VersionTLS13,
		MaxVersion:   cryptotls.VersionTLS13,
		NextProtos:   []string{"h2"},
	}
	oldKey, newKey := [32]byte{1}, [32]byte{2}
	serverConfig.SetSessionTicketKeys([][32]byte{oldKey})
	profile, err := (Profile{
		ID: 1,
		Config: &cryptotls.Config{
			RootCAs: roots, Time: func() time.Time { return time.Unix(1_800_000_000, 0) },
			MinVersion: cryptotls.VersionTLS13, MaxVersion: cryptotls.VersionTLS13, NextProtos: []string{"h2"},
		},
		RequiredALPN: "h2", MaxCertificateChainBytes: 64 << 10, MaxPeerCertificates: 4,
		AllowedNames:            map[string]tlsns.IdentityType{"resume.example.com": tlsns.IdentityDNS},
		MaxClientSessionEntries: 2, MaxClientSessionBytes: 64 << 10,
	}).Instantiate()
	if err != nil {
		t.Fatal(err)
	}
	if resumed := completeResumableHandshake(t, profile, serverConfig); resumed {
		t.Fatal("first connection unexpectedly resumed")
	}
	rotated := serverConfig.Clone()
	rotated.SetSessionTicketKeys([][32]byte{newKey, oldKey})
	if resumed := completeResumableHandshake(t, profile, rotated); !resumed {
		t.Fatal("connection did not resume through the retained rotation key")
	}
	newOnly := serverConfig.Clone()
	newOnly.SetSessionTicketKeys([][32]byte{newKey})
	if resumed := completeResumableHandshake(t, profile, newOnly); !resumed {
		t.Fatal("connection did not resume with the newly issued ticket")
	}
}

func TestClientProfileInstantiateOwnsFreshBoundedSessionCache(t *testing.T) {
	profile := Profile{
		ID:                       1,
		Config:                   &cryptotls.Config{},
		MaxCertificateChainBytes: 1024,
		MaxPeerCertificates:      1,
		AllowedNames:             map[string]tlsns.IdentityType{"example.com": tlsns.IdentityDNS},
		MaxClientSessionEntries:  2,
		MaxClientSessionBytes:    64 << 10,
	}
	first, err := profile.Instantiate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := profile.Instantiate()
	if err != nil {
		t.Fatal(err)
	}
	if first.Config.ClientSessionCache == nil || second.Config.ClientSessionCache == nil {
		t.Fatal("session cache was not installed")
	}
	if first.Config.ClientSessionCache == second.Config.ClientSessionCache {
		t.Fatal("profile instances shared mutable session cache")
	}
	first.Config.ClientSessionCache.Put("example.com", captureTestSession(t, 0))
	if _, ok := second.Config.ClientSessionCache.Get("example.com"); ok {
		t.Fatal("session state crossed profile instances")
	}
}

func completeResumableHandshake(t testing.TB, profile Profile, serverConfig *cryptotls.Config) bool {
	t.Helper()
	serverBridge := newBridgeConn(64<<10, 64<<10, 1<<20)
	server := cryptotls.Server(serverBridge, serverConfig.Clone())
	serverDone := make(chan error, 1)
	go func() {
		err := server.Handshake()
		serverBridge.finishHandshake()
		serverDone <- err
	}()
	client, err := NewClient(&memoryTransport{peer: serverBridge}, profile, "resume.example.com", tlsns.IdentityDNS, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for attempt := 0; attempt < 1_000_000; attempt++ {
		progress, err := client.TryFinishConnect()
		if err != nil {
			t.Fatal(err)
		}
		if progress == nscore.ProgressDone {
			break
		}
		if attempt == 999_999 {
			t.Fatal("resumable client handshake did not complete")
		}
		runtime.Gosched()
	}
	for attempt := 0; ; attempt++ {
		_, _, _ = client.TryService(nscore.ServiceBudget{Packets: 8, Bytes: 64 << 10, Operations: 8})
		select {
		case err := <-serverDone:
			if err != nil {
				t.Fatal(err)
			}
			goto serverReady
		default:
			if attempt == 999_999 {
				t.Fatal("resumable server handshake did not complete")
			}
			runtime.Gosched()
		}
	}

serverReady:
	writeDone := make(chan error, 1)
	go func() {
		_, err := server.Write([]byte{1})
		writeDone <- err
	}()
	var payload [1]byte
	for attempt := 0; attempt < 1_000_000; attempt++ {
		_, _, _ = client.TryService(nscore.ServiceBudget{Packets: 8, Bytes: 64 << 10, Operations: 8})
		result, err := client.TryRead(payload[:])
		if err != nil {
			t.Fatal(err)
		}
		if result.State == nscore.IOReady && result.Bytes == 1 {
			if err := <-writeDone; err != nil {
				t.Fatal(err)
			}
			info, ok := client.ConnectionInfo()
			if !ok {
				t.Fatal("resumable connection metadata unavailable")
			}
			serverBridge.abort(nil)
			return info.Resumed
		}
		runtime.Gosched()
	}
	t.Fatal("post-handshake ticket and payload were not received")
	return false
}

type captureSessionCache struct {
	session *cryptotls.ClientSessionState
}

func (*captureSessionCache) Get(string) (*cryptotls.ClientSessionState, bool) { return nil, false }
func (cache *captureSessionCache) Put(_ string, session *cryptotls.ClientSessionState) {
	if session != nil {
		cache.session = session
	}
}

func captureTestSession(t testing.TB, extraBytes int) *cryptotls.ClientSessionState {
	t.Helper()
	certificate, roots := testCertificate(t, "cache.example.com")
	serverSide, clientSide := net.Pipe()
	serverConfig := &cryptotls.Config{
		Certificates: []cryptotls.Certificate{certificate},
		MinVersion:   cryptotls.VersionTLS13,
		MaxVersion:   cryptotls.VersionTLS13,
	}
	serverConfig.SetSessionTicketKeys([][32]byte{{1}})
	capture := &captureSessionCache{}
	clientConfig := &cryptotls.Config{
		RootCAs:            roots,
		ServerName:         "cache.example.com",
		Time:               func() time.Time { return time.Unix(1_800_000_000, 0) },
		MinVersion:         cryptotls.VersionTLS13,
		MaxVersion:         cryptotls.VersionTLS13,
		ClientSessionCache: capture,
	}
	server := cryptotls.Server(serverSide, serverConfig)
	client := cryptotls.Client(clientSide, clientConfig)
	serverDone := make(chan error, 1)
	go func() {
		if err := server.Handshake(); err != nil {
			serverDone <- err
			return
		}
		_, err := server.Write([]byte{1})
		serverDone <- err
	}()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	var payload [1]byte
	if _, err := client.Read(payload[:]); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	_ = clientSide.Close()
	_ = serverSide.Close()
	if capture.session == nil {
		t.Fatal("TLS 1.3 server did not issue a session ticket")
	}
	if extraBytes == 0 {
		return capture.session
	}
	ticket, state, err := capture.session.ResumptionState()
	if err != nil {
		t.Fatal(err)
	}
	state.Extra = append(state.Extra, make([]byte, extraBytes))
	session, err := cryptotls.NewResumptionState(ticket, state)
	if err != nil {
		t.Fatal(err)
	}
	return session
}
