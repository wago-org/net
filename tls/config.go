package tls

import (
	"errors"

	"github.com/wago-org/net/internal/checked"
	"github.com/wago-org/net/internal/tlslimits"
)

var ErrInvalidConfig = errors.New("wagonet/tls: invalid configuration")

const (
	// MaximumStreams and MaximumConcurrentHandshakes bound worker and handshake
	// concurrency for one instance.
	MaximumStreams               = tlslimits.MaxStreams
	MaximumListeners             = tlslimits.MaxListeners
	MaximumAcceptBacklog         = tlslimits.MaxAcceptBacklog
	MaximumConcurrentHandshakes  = tlslimits.MaxConcurrentHandshakes
	MaximumClientProfiles        = tlslimits.MaxProfiles
	MaximumServerNamesPerProfile = tlslimits.MaxServerNamesPerProfile
	MaximumPeerCertificates      = tlslimits.MaxPeerCertificates
	MaximumALPNProtocols         = tlslimits.MaxALPNProtocols
	MaximumALPNAggregateBytes    = tlslimits.MaxALPNAggregateBytes
	MaximumTransportPackets      = tlslimits.MaxTransportPackets
	MaximumServiceAttempts       = tlslimits.MaxServiceAttempts

	// Maximum*Bytes are hard registration-time ceilings. In addition, all fixed
	// per-stream storage multiplied by MaxStreams must fit
	// MaximumAggregateRetainedBytes.
	MaximumPlaintextQueueBytes    = tlslimits.MaxPlaintextQueueBytes
	MaximumCiphertextQueueBytes   = tlslimits.MaxCiphertextQueueBytes
	MaximumTransportQueueBytes    = tlslimits.MaxTransportQueueBytes
	MaximumHandshakeBytes         = tlslimits.MaxHandshakeBytes
	MaximumCertificateChainBytes  = tlslimits.MaxCertificateChainBytes
	MaximumAggregateRetainedBytes = tlslimits.MaxAggregateRetainedBytes

	// Fixed scratch is included exactly once in per-stream quota arithmetic.
	FixedPlaintextScratchBytes  = tlslimits.PlaintextScratchBytes
	FixedCiphertextScratchBytes = tlslimits.CiphertextScratchBytes
)

// Config fixes every TLS-local stream, handshake, queue, and service bound.
// Zero values disable the corresponding resource; there is no unbounded
// sentinel.
type Config struct {
	MaxStreams                     uint16
	MaxListeners                   uint16
	AcceptBacklog                  uint16
	MaxConcurrentHandshakes        uint16
	PlaintextReceiveBytes          int
	PlaintextTransmitBytes         int
	CiphertextReceiveBytes         int
	CiphertextTransmitBytes        int
	TransportReceiveBytes          int
	TransportTransmitBytes         int
	TransportTransmitPackets       int
	MaxHandshakeBytes              int
	MaxCertificateChainBytes       int
	MaxPeerCertificates            uint16
	MaxServerNameBytes             uint16
	MaxALPNProtocols               uint16
	MaxALPNAggregateBytes          uint16
	MaxServiceAttemptsPerHandshake uint32
	MaxRecordsPerService           uint16
}

// DefaultConfig returns conservative finite TLS client/server storage. Listener
// authority remains disabled until separately granted; the underlying private
// TCP transport is configured by registration.
func DefaultConfig() Config {
	return Config{
		MaxStreams:                     8,
		MaxListeners:                   4,
		AcceptBacklog:                  4,
		MaxConcurrentHandshakes:        4,
		PlaintextReceiveBytes:          16 << 10,
		PlaintextTransmitBytes:         16 << 10,
		CiphertextReceiveBytes:         32 << 10,
		CiphertextTransmitBytes:        32 << 10,
		TransportReceiveBytes:          32 << 10,
		TransportTransmitBytes:         32 << 10,
		TransportTransmitPackets:       32,
		MaxHandshakeBytes:              256 << 10,
		MaxCertificateChainBytes:       192 << 10,
		MaxPeerCertificates:            8,
		MaxServerNameBytes:             253,
		MaxALPNProtocols:               8,
		MaxALPNAggregateBytes:          256,
		MaxServiceAttemptsPerHandshake: 4096,
		MaxRecordsPerService:           16,
	}
}

func validConfig(config Config) bool {
	_, ok := validateConfig(config, checked.MaxInt())
	return ok
}

func validateConfig(config Config, maxIntValue uint64) (tlslimits.Plan, bool) {
	plan, ok := tlslimits.Validate(tlslimits.Config{
		MaxStreams: config.MaxStreams, MaxListeners: config.MaxListeners, AcceptBacklog: config.AcceptBacklog, MaxConcurrentHandshakes: config.MaxConcurrentHandshakes,
		PlaintextReceiveBytes: config.PlaintextReceiveBytes, PlaintextTransmitBytes: config.PlaintextTransmitBytes,
		CiphertextReceiveBytes: config.CiphertextReceiveBytes, CiphertextTransmitBytes: config.CiphertextTransmitBytes,
		TransportReceiveBytes: config.TransportReceiveBytes, TransportTransmitBytes: config.TransportTransmitBytes,
		MaxHandshakeBytes: config.MaxHandshakeBytes, MaxCertificateChainBytes: config.MaxCertificateChainBytes,
	}, maxIntValue)
	if !ok || config.TransportTransmitPackets <= 0 || config.TransportTransmitPackets > config.TransportTransmitBytes || config.TransportTransmitPackets > MaximumTransportPackets ||
		config.MaxPeerCertificates == 0 || config.MaxPeerCertificates > MaximumPeerCertificates || config.MaxServerNameBytes == 0 || config.MaxServerNameBytes > 253 ||
		config.MaxALPNProtocols == 0 || config.MaxALPNProtocols > MaximumALPNProtocols || config.MaxALPNAggregateBytes == 0 || config.MaxALPNAggregateBytes > MaximumALPNAggregateBytes ||
		config.MaxServiceAttemptsPerHandshake == 0 || config.MaxServiceAttemptsPerHandshake > MaximumServiceAttempts || config.MaxRecordsPerService == 0 || config.MaxRecordsPerService > 256 {
		return tlslimits.Plan{}, false
	}
	return plan, true
}
