package tls

import "errors"

var ErrInvalidConfig = errors.New("wagonet/tls: invalid configuration")

// Config fixes every TLS-local stream, handshake, queue, and service bound.
// Zero values disable the corresponding resource; there is no unbounded
// sentinel.
type Config struct {
	MaxStreams                     uint16
	MaxConcurrentHandshakes        uint16
	PlaintextReceiveBytes          int
	PlaintextTransmitBytes         int
	CiphertextReceiveBytes         int
	CiphertextTransmitBytes        int
	MaxHandshakeBytes              int
	MaxCertificateChainBytes       int
	MaxPeerCertificates            uint16
	MaxServerNameBytes             uint16
	MaxALPNProtocols               uint16
	MaxALPNAggregateBytes          uint16
	MaxServiceAttemptsPerHandshake uint32
	MaxRecordsPerService           uint16
}

// DefaultConfig returns conservative finite client-only TLS storage. The
// underlying private TCP transport is configured separately by registration.
func DefaultConfig() Config {
	return Config{
		MaxStreams:                     8,
		MaxConcurrentHandshakes:        4,
		PlaintextReceiveBytes:          16 << 10,
		PlaintextTransmitBytes:         16 << 10,
		CiphertextReceiveBytes:         32 << 10,
		CiphertextTransmitBytes:        32 << 10,
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
	return config.MaxStreams > 0 && config.MaxConcurrentHandshakes > 0 &&
		config.MaxConcurrentHandshakes <= config.MaxStreams &&
		config.PlaintextReceiveBytes >= 1024 && config.PlaintextTransmitBytes >= 1024 &&
		config.CiphertextReceiveBytes >= 17<<10 && config.CiphertextTransmitBytes >= 17<<10 &&
		config.MaxHandshakeBytes >= 16<<10 && config.MaxCertificateChainBytes >= 1024 &&
		config.MaxCertificateChainBytes <= config.MaxHandshakeBytes &&
		config.MaxPeerCertificates > 0 && config.MaxServerNameBytes > 0 && config.MaxServerNameBytes <= 253 &&
		config.MaxALPNProtocols > 0 && config.MaxALPNAggregateBytes > 0 &&
		config.MaxServiceAttemptsPerHandshake > 0 && config.MaxRecordsPerService > 0
}
