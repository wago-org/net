package dns

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/internal/policy"
)

func TestAllowSuffixesRejectsEmptyInput(t *testing.T) {
	if err := AllowSuffixes().applyDNS(&registration{}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("empty suffix helper = %v", err)
	}
}

func TestSuffixAuthorityRequiresExplicitGrantAfterDefaultSuppression(t *testing.T) {
	config := registration{defaultAuthority: true}
	for _, option := range []Option{
		WithoutDefaultAuthority(),
		AllowSuffixes("Example.COM."),
	} {
		if err := option.applyDNS(&config); err != nil {
			t.Fatalf("apply option: %v", err)
		}
	}
	compiled, err := policy.Compile(config.authority())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	for _, name := range []string{"example.com", "www.example.com"} {
		if !compiled.CheckDNS(policy.OperationDNSResolve, name) {
			t.Fatalf("explicit suffix denied %q", name)
		}
	}
	if compiled.CheckDNS(policy.OperationDNSResolve, "example.net") {
		t.Fatal("name outside the explicit suffix was allowed")
	}
}

func TestAllowAllStillHonorsRawDenyRules(t *testing.T) {
	config := registration{defaultAuthority: true}
	for _, option := range []Option{
		WithoutDefaultAuthority(),
		AllowAll(),
		WithPolicy(wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
			Action: wagonet.PolicyDeny, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportDNS},
			Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, DNSSuffixes: []string{"blocked.example"},
		}}}),
	} {
		if err := option.applyDNS(&config); err != nil {
			t.Fatalf("apply option: %v", err)
		}
	}
	compiled, err := policy.Compile(config.authority())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !compiled.CheckDNS(policy.OperationDNSResolve, "allowed.example") {
		t.Fatal("AllowAll did not grant a valid DNS name")
	}
	if compiled.CheckDNS(policy.OperationDNSResolve, "www.blocked.example") {
		t.Fatal("raw suffix deny did not override AllowAll")
	}
}

func TestTCPFallbackOptionIsFiniteAndOrderIndependent(t *testing.T) {
	resolver := netip.MustParseAddr("192.0.2.53")
	for _, options := range [][]Option{
		{Resolver(resolver.String()), EnableTCPFallback(16<<10, 128)},
		{EnableTCPFallback(16<<10, 128), Resolver(resolver.String())},
		{WithConfig(Config{Server: resolver, MaxQueries: 2, MaxRecords: 4, MaxResponseBytes: 512, MaxAttempts: 1, RetryServiceAttempts: 1}), EnableTCPFallback(16<<10, 128)},
	} {
		config := registration{defaultAuthority: true}
		for _, option := range options {
			if err := option.applyDNS(&config); err != nil {
				t.Fatal(err)
			}
		}
		resolved := config.finalConfig()
		if resolved.MaxTCPResponseBytes != 16<<10 || resolved.MaxTCPServiceAttempts != 128 {
			t.Fatalf("TCP fallback config = %+v", resolved)
		}
	}
	for name, option := range map[string]Option{
		"short response": EnableTCPFallback(11, 1),
		"large response": EnableTCPFallback(65536, 1),
		"zero attempts":  EnableTCPFallback(512, 0),
		"many attempts":  EnableTCPFallback(512, 4097),
	} {
		t.Run(name, func(t *testing.T) {
			if err := option.applyDNS(&registration{}); !errors.Is(err, ErrInvalidOption) {
				t.Fatalf("invalid fallback = %v", err)
			}
		})
	}
	config := registration{}
	if err := EnableTCPFallback(512, 1).applyDNS(&config); err != nil {
		t.Fatal(err)
	}
	if err := EnableTCPFallback(512, 1).applyDNS(&config); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("duplicate fallback = %v", err)
	}
}

func TestResolverAndConfigComposeIndependentOfOptionOrder(t *testing.T) {
	resolver := netip.MustParseAddr("192.0.2.53")
	custom := Config{MaxQueries: 3, MaxRecords: 4, MaxResponseBytes: 640, MaxAttempts: 5, RetryServiceAttempts: 6}
	for _, test := range []struct {
		name    string
		options []Option
		want    Config
	}{
		{
			name:    "resolver then custom config",
			options: []Option{Resolver(resolver.String()), WithConfig(custom)},
			want:    Config{Server: resolver, MaxQueries: 3, MaxRecords: 4, MaxResponseBytes: 640, MaxAttempts: 5, RetryServiceAttempts: 6},
		},
		{
			name:    "custom config then resolver",
			options: []Option{WithConfig(custom), Resolver(resolver.String())},
			want:    Config{Server: resolver, MaxQueries: 3, MaxRecords: 4, MaxResponseBytes: 640, MaxAttempts: 5, RetryServiceAttempts: 6},
		},
		{
			name:    "resolver then explicit zero config",
			options: []Option{Resolver(resolver.String()), WithConfig(Config{})},
			want:    Config{Server: resolver},
		},
		{
			name:    "explicit zero config then resolver",
			options: []Option{WithConfig(Config{}), Resolver(resolver.String())},
			want:    Config{Server: resolver},
		},
		{
			name:    "resolver only installs defaults",
			options: []Option{Resolver(resolver.String())},
			want:    DefaultConfig(resolver),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := registration{defaultAuthority: true}
			for _, option := range test.options {
				if err := option.applyDNS(&config); err != nil {
					t.Fatalf("apply option: %v", err)
				}
			}
			if got := config.finalConfig(); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("final config = %+v, want %+v", got, test.want)
			}
		})
	}
}
