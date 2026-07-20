package tls

import (
	"testing"

	"github.com/wago-org/net/internal/checked"
)

func TestTLSConfigDefaultsSmallerAndMaximumConcurrencyRemainValid(t *testing.T) {
	for name, config := range map[string]Config{
		"default": DefaultConfig(),
		"smaller": func() Config {
			config := DefaultConfig()
			config.MaxStreams = 1
			config.MaxConcurrentHandshakes = 1
			config.PlaintextReceiveBytes = 1024
			config.PlaintextTransmitBytes = 1024
			config.CiphertextReceiveBytes = 17 << 10
			config.CiphertextTransmitBytes = 17 << 10
			config.TransportReceiveBytes = 256
			config.TransportTransmitBytes = 256
			config.TransportTransmitPackets = 1
			config.MaxHandshakeBytes = 16 << 10
			config.MaxCertificateChainBytes = 1024
			return config
		}(),
		"maximum concurrency with ordinary storage": func() Config {
			config := DefaultConfig()
			config.MaxStreams = MaximumStreams
			config.MaxConcurrentHandshakes = MaximumConcurrentHandshakes
			return config
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			plan, ok := validateConfig(config, checked.MaxInt())
			if !ok || plan.PlaintextBytes == 0 || plan.CiphertextBytes == 0 || plan.TransportBytes == 0 || plan.TotalBytes > MaximumAggregateRetainedBytes {
				t.Fatalf("valid config plan = %+v, %v", plan, ok)
			}
		})
	}
}

func TestDefaultTLSStorageClassificationMatchesQuotaOwnership(t *testing.T) {
	plan, ok := validateConfig(DefaultConfig(), checked.MaxInt())
	if !ok {
		t.Fatal("default configuration invalid")
	}
	wantPlaintext := uint64(64 << 10)
	wantCiphertext := uint64(80 << 10)
	wantTransport := uint64(64 << 10)
	wantPerStream := uint64(208 << 10)
	wantTotal := uint64(8 * (208 << 10))
	if plan.PlaintextBytes != wantPlaintext || plan.CiphertextBytes != wantCiphertext || plan.TransportBytes != wantTransport || plan.PerStreamBytes != wantPerStream || plan.TotalBytes != wantTotal {
		t.Fatalf("default storage plan = %+v", plan)
	}
}

func TestTLSConfigRejectsIndividualAndAggregateStorageBounds(t *testing.T) {
	nearMaxInt := int(checked.MaxInt())
	tests := map[string]func(*Config){
		"plaintext receive near max int":    func(config *Config) { config.PlaintextReceiveBytes = nearMaxInt },
		"plaintext transmit near max int":   func(config *Config) { config.PlaintextTransmitBytes = nearMaxInt },
		"ciphertext receive near max int":   func(config *Config) { config.CiphertextReceiveBytes = nearMaxInt },
		"ciphertext transmit near max int":  func(config *Config) { config.CiphertextTransmitBytes = nearMaxInt },
		"transport receive near max int":    func(config *Config) { config.TransportReceiveBytes = nearMaxInt },
		"transport transmit near max int":   func(config *Config) { config.TransportTransmitBytes = nearMaxInt },
		"handshake near max int":            func(config *Config) { config.MaxHandshakeBytes = nearMaxInt },
		"certificate near max int":          func(config *Config) { config.MaxCertificateChainBytes = nearMaxInt },
		"plaintext receive above maximum":   func(config *Config) { config.PlaintextReceiveBytes = int(MaximumPlaintextQueueBytes + 1) },
		"plaintext transmit above maximum":  func(config *Config) { config.PlaintextTransmitBytes = int(MaximumPlaintextQueueBytes + 1) },
		"ciphertext receive above maximum":  func(config *Config) { config.CiphertextReceiveBytes = int(MaximumCiphertextQueueBytes + 1) },
		"ciphertext transmit above maximum": func(config *Config) { config.CiphertextTransmitBytes = int(MaximumCiphertextQueueBytes + 1) },
		"transport receive above maximum":   func(config *Config) { config.TransportReceiveBytes = int(MaximumTransportQueueBytes + 1) },
		"transport transmit above maximum":  func(config *Config) { config.TransportTransmitBytes = int(MaximumTransportQueueBytes + 1) },
		"handshake above maximum":           func(config *Config) { config.MaxHandshakeBytes = int(MaximumHandshakeBytes + 1) },
		"certificate above maximum":         func(config *Config) { config.MaxCertificateChainBytes = int(MaximumCertificateChainBytes + 1) },
		"streams above maximum":             func(config *Config) { config.MaxStreams = MaximumStreams + 1 },
		"handshakes above maximum":          func(config *Config) { config.MaxConcurrentHandshakes = MaximumConcurrentHandshakes + 1 },
		"peer certificates above maximum":   func(config *Config) { config.MaxPeerCertificates = MaximumPeerCertificates + 1 },
		"ALPN protocols above maximum":      func(config *Config) { config.MaxALPNProtocols = MaximumALPNProtocols + 1 },
		"ALPN bytes above maximum":          func(config *Config) { config.MaxALPNAggregateBytes = MaximumALPNAggregateBytes + 1 },
		"transport packets above maximum":   func(config *Config) { config.TransportTransmitPackets = MaximumTransportPackets + 1 },
		"service attempts above maximum":    func(config *Config) { config.MaxServiceAttemptsPerHandshake = MaximumServiceAttempts + 1 },
		"aggregate storage above maximum": func(config *Config) {
			config.MaxStreams = MaximumStreams
			config.MaxConcurrentHandshakes = MaximumConcurrentHandshakes
			config.PlaintextReceiveBytes = int(MaximumPlaintextQueueBytes)
			config.PlaintextTransmitBytes = int(MaximumPlaintextQueueBytes)
			config.CiphertextReceiveBytes = int(MaximumCiphertextQueueBytes)
			config.CiphertextTransmitBytes = int(MaximumCiphertextQueueBytes)
			config.TransportReceiveBytes = int(MaximumTransportQueueBytes)
			config.TransportTransmitBytes = int(MaximumTransportQueueBytes)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := DefaultConfig()
			mutate(&config)
			if plan, ok := validateConfig(config, checked.MaxInt()); ok {
				t.Fatalf("invalid config accepted with plan %+v", plan)
			}
		})
	}
}

func TestTLSConfigSimulated386RepresentabilityFailsBeforeAllocation(t *testing.T) {
	config := DefaultConfig()
	maxInt32 := uint64(^uint32(0) >> 1)
	value := maxInt32 + 1
	validationMaximum := maxInt32
	if checked.MaxInt() == maxInt32 {
		value = maxInt32
		validationMaximum = maxInt32 - 1
	}
	config.PlaintextReceiveBytes = int(value)
	allocations := testing.AllocsPerRun(1000, func() {
		if _, ok := validateConfig(config, validationMaximum); ok {
			panic("32-bit-unrepresentable TLS configuration accepted")
		}
	})
	if allocations != 0 {
		t.Fatalf("invalid validation allocations = %v", allocations)
	}
}
