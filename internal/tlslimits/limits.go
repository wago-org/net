// Package tlslimits owns the finite storage maxima and allocation plan shared
// by public TLS registration and internal TLS backends.
package tlslimits

import "github.com/wago-org/net/internal/checked"

const (
	MaxStreams               uint16 = 64
	MaxConcurrentHandshakes  uint16 = 64
	MaxProfiles                     = 256
	MaxServerNamesPerProfile        = 256
	MaxPeerCertificates      uint16 = 64
	MaxALPNProtocols         uint16 = 64
	MaxALPNAggregateBytes    uint16 = 4096
	MaxTransportPackets             = 4096
	MaxServiceAttempts       uint32 = 1 << 20

	MaxPlaintextQueueBytes   uint64 = 1 << 20
	MaxCiphertextQueueBytes  uint64 = 1 << 20
	MaxTransportQueueBytes   uint64 = 1 << 20
	MaxHandshakeBytes        uint64 = 4 << 20
	MaxCertificateChainBytes uint64 = 2 << 20

	// MaxAggregateRetainedBytes bounds all fixed TLS plaintext, ciphertext,
	// scratch, and private-TCP storage that MaxStreams could retain at once.
	MaxAggregateRetainedBytes uint64 = 64 << 20

	PlaintextScratchBytes  = 32 << 10
	CiphertextScratchBytes = 16 << 10
)

// Config contains every TLS-owned or private-transport storage dimension.
type Config struct {
	MaxStreams               uint16
	MaxConcurrentHandshakes  uint16
	PlaintextReceiveBytes    int
	PlaintextTransmitBytes   int
	CiphertextReceiveBytes   int
	CiphertextTransmitBytes  int
	TransportReceiveBytes    int
	TransportTransmitBytes   int
	MaxHandshakeBytes        int
	MaxCertificateChainBytes int
}

// Plan is the checked quota and allocation classification for one validated
// configuration. TransportBytes is charged by the private TCP adapter, not by
// TLS plaintext/ciphertext quota, while TotalBytes includes it exactly once.
type Plan struct {
	PlaintextBytes  uint64
	CiphertextBytes uint64
	TransportBytes  uint64
	PerStreamBytes  uint64
	TotalBytes      uint64
}

// Validate proves target-int representability, every sum, stream
// multiplication, and the repository aggregate retained-storage ceiling.
func Validate(config Config, maxIntValue uint64) (Plan, bool) {
	if config.MaxStreams == 0 || config.MaxStreams > MaxStreams ||
		config.MaxConcurrentHandshakes == 0 || config.MaxConcurrentHandshakes > MaxConcurrentHandshakes ||
		config.MaxConcurrentHandshakes > config.MaxStreams {
		return Plan{}, false
	}
	plainReceive, ok := storageValue(config.PlaintextReceiveBytes, 1024, MaxPlaintextQueueBytes, maxIntValue)
	if !ok {
		return Plan{}, false
	}
	plainTransmit, ok := storageValue(config.PlaintextTransmitBytes, 1024, MaxPlaintextQueueBytes, maxIntValue)
	if !ok {
		return Plan{}, false
	}
	cipherReceive, ok := storageValue(config.CiphertextReceiveBytes, 17<<10, MaxCiphertextQueueBytes, maxIntValue)
	if !ok {
		return Plan{}, false
	}
	cipherTransmit, ok := storageValue(config.CiphertextTransmitBytes, 17<<10, MaxCiphertextQueueBytes, maxIntValue)
	if !ok {
		return Plan{}, false
	}
	transportReceive, ok := storageValue(config.TransportReceiveBytes, 256, MaxTransportQueueBytes, maxIntValue)
	if !ok {
		return Plan{}, false
	}
	transportTransmit, ok := storageValue(config.TransportTransmitBytes, 256, MaxTransportQueueBytes, maxIntValue)
	if !ok {
		return Plan{}, false
	}
	if _, ok := storageValue(config.MaxHandshakeBytes, 16<<10, MaxHandshakeBytes, maxIntValue); !ok {
		return Plan{}, false
	}
	certificateBytes, ok := storageValue(config.MaxCertificateChainBytes, 1024, MaxCertificateChainBytes, maxIntValue)
	if !ok || certificateBytes > uint64(config.MaxHandshakeBytes) {
		return Plan{}, false
	}

	plaintext, ok := checked.AddUint64(plainReceive, plainTransmit)
	if !ok {
		return Plan{}, false
	}
	plaintext, ok = checked.AddUint64(plaintext, PlaintextScratchBytes)
	if !ok {
		return Plan{}, false
	}
	ciphertext, ok := checked.AddUint64(cipherReceive, cipherTransmit)
	if !ok {
		return Plan{}, false
	}
	ciphertext, ok = checked.AddUint64(ciphertext, CiphertextScratchBytes)
	if !ok {
		return Plan{}, false
	}
	transport, ok := checked.AddUint64(transportReceive, transportTransmit)
	if !ok {
		return Plan{}, false
	}
	perStream, ok := checked.AddUint64(plaintext, ciphertext)
	if !ok {
		return Plan{}, false
	}
	perStream, ok = checked.AddUint64(perStream, transport)
	if !ok || perStream > maxIntValue {
		return Plan{}, false
	}
	total, ok := checked.MultiplyUint64(perStream, uint64(config.MaxStreams))
	if !ok || total > MaxAggregateRetainedBytes {
		return Plan{}, false
	}
	return Plan{PlaintextBytes: plaintext, CiphertextBytes: ciphertext, TransportBytes: transport, PerStreamBytes: perStream, TotalBytes: total}, true
}

func storageValue(value int, minimum int, maximum uint64, maxIntValue uint64) (uint64, bool) {
	if value < minimum {
		return 0, false
	}
	converted := uint64(value)
	if converted > maximum {
		return 0, false
	}
	if _, ok := checked.Uint64ToInt(converted, maxIntValue); !ok {
		return 0, false
	}
	return converted, true
}
