// Package inspectionpolicy owns the independently controlled custom-CLI
// inspection surface certified by release signoff and provenance verification.
package inspectionpolicy

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
)

const AggregateKey = "net"

//go:embed policy.json
var policyJSON []byte

type Policy struct {
	Bundles []Bundle `json:"bundles"`
}

type Bundle struct {
	Key          string         `json:"key"`
	Package      string         `json:"package"`
	Capabilities []string       `json:"capabilities"`
	Imports      map[string]int `json:"imports"`
	GranularOnly bool           `json:"granularOnly,omitempty"`
}

func Data() []byte {
	return append([]byte(nil), policyJSON...)
}

func Load() (Policy, error) {
	var policy Policy
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		return Policy{}, fmt.Errorf("inspection policy: decode: %w", err)
	}
	if err := Validate(policy); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func Validate(policy Policy) error {
	if len(policy.Bundles) < 2 {
		return fmt.Errorf("inspection policy: aggregate and granular bundles are required")
	}
	keys := make(map[string]struct{}, len(policy.Bundles))
	packages := make(map[string]struct{}, len(policy.Bundles))
	var aggregate *Bundle
	granularCapabilities := make(map[string]struct{}, len(policy.Bundles)-1)
	granularImports := make(map[string]int, len(policy.Bundles))
	previousKey := ""
	for index := range policy.Bundles {
		bundle := &policy.Bundles[index]
		if bundle.Key == "" || bundle.Package == "" {
			return fmt.Errorf("inspection policy: bundle %d has an empty key or package", index)
		}
		if _, duplicate := keys[bundle.Key]; duplicate {
			return fmt.Errorf("inspection policy: duplicate bundle key %q", bundle.Key)
		}
		keys[bundle.Key] = struct{}{}
		if previousKey != "" && bundle.Key <= previousKey {
			return fmt.Errorf("inspection policy: bundle keys are not sorted")
		}
		previousKey = bundle.Key
		if _, duplicate := packages[bundle.Package]; duplicate {
			return fmt.Errorf("inspection policy: duplicate bundle package %q", bundle.Package)
		}
		packages[bundle.Package] = struct{}{}
		if !sort.StringsAreSorted(bundle.Capabilities) || len(bundle.Capabilities) == 0 {
			return fmt.Errorf("inspection policy: capabilities for %q are empty or unsorted", bundle.Key)
		}
		for capabilityIndex, capability := range bundle.Capabilities {
			if capability == "" || capabilityIndex != 0 && capability == bundle.Capabilities[capabilityIndex-1] {
				return fmt.Errorf("inspection policy: invalid capability in %q", bundle.Key)
			}
		}
		if bundle.Imports["wago_net"] != 1 {
			return fmt.Errorf("inspection policy: %q must contain one wago_net import", bundle.Key)
		}
		for module, count := range bundle.Imports {
			if module == "" || count <= 0 {
				return fmt.Errorf("inspection policy: invalid import count for %q", bundle.Key)
			}
		}
		if bundle.Key == AggregateKey {
			aggregate = bundle
			continue
		}
		if len(bundle.Capabilities) != 2 || len(bundle.Imports) != 2 {
			return fmt.Errorf("inspection policy: granular bundle %q must contain core plus one protocol", bundle.Key)
		}
		protocolCapability := ""
		for _, capability := range bundle.Capabilities {
			if capability != "net.info" {
				protocolCapability = capability
			}
		}
		if protocolCapability == "" {
			return fmt.Errorf("inspection policy: granular bundle %q has no protocol capability", bundle.Key)
		}
		if bundle.GranularOnly {
			continue
		}
		if _, duplicate := granularCapabilities[protocolCapability]; duplicate {
			return fmt.Errorf("inspection policy: duplicate protocol capability %q", protocolCapability)
		}
		granularCapabilities[protocolCapability] = struct{}{}
		for module, count := range bundle.Imports {
			if module == "wago_net" {
				continue
			}
			if _, duplicate := granularImports[module]; duplicate {
				return fmt.Errorf("inspection policy: duplicate protocol import module %q", module)
			}
			granularImports[module] = count
		}
	}
	if aggregate == nil {
		return fmt.Errorf("inspection policy: aggregate bundle %q is missing", AggregateKey)
	}
	if len(aggregate.Capabilities) != len(granularCapabilities)+1 || len(aggregate.Imports) != len(granularImports)+1 {
		return fmt.Errorf("inspection policy: aggregate protocol surface is incomplete")
	}
	if !contains(aggregate.Capabilities, "net.info") {
		return fmt.Errorf("inspection policy: aggregate core capability is missing")
	}
	for capability := range granularCapabilities {
		if !contains(aggregate.Capabilities, capability) {
			return fmt.Errorf("inspection policy: aggregate capability %q is missing", capability)
		}
	}
	for module, count := range granularImports {
		if aggregate.Imports[module] != count {
			return fmt.Errorf("inspection policy: aggregate import %q = %d, want %d", module, aggregate.Imports[module], count)
		}
	}
	return nil
}

func Aggregate(policy Policy) (Bundle, bool) {
	for _, bundle := range policy.Bundles {
		if bundle.Key == AggregateKey {
			return bundle, true
		}
	}
	return Bundle{}, false
}

func ImportCount(bundle Bundle) int {
	total := 0
	for _, count := range bundle.Imports {
		total += count
	}
	return total
}

func contains(values []string, want string) bool {
	index := sort.SearchStrings(values, want)
	return index < len(values) && values[index] == want
}
