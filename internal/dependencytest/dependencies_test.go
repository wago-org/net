//go:build !tinygo

package dependencytest

import (
	"os/exec"
	"strings"
	"testing"
)

const modulePath = "github.com/wago-org/net"

type protocolDependency struct {
	public    string
	register  string
	binding   string
	operation string
	abi       string
	namespace string
	adapter   string
}

var protocolDependencies = map[string]protocolDependency{
	"tcp":    {public: modulePath + "/tcp", register: modulePath + "/tcp/register", binding: modulePath + "/internal/binding/tcp", operation: modulePath + "/internal/instance/tcp", abi: modulePath + "/internal/abi/tcp", namespace: modulePath + "/internal/namespace/tcp", adapter: modulePath + "/internal/backend/lneto/tcp"},
	"udp":    {public: modulePath + "/udp", register: modulePath + "/udp/register", binding: modulePath + "/internal/binding/udp", operation: modulePath + "/internal/instance/udp", abi: modulePath + "/internal/abi/udp", namespace: modulePath + "/internal/namespace/udp", adapter: modulePath + "/internal/backend/lneto/udp"},
	"dns":    {public: modulePath + "/dns", register: modulePath + "/dns/register", binding: modulePath + "/internal/binding/dns", operation: modulePath + "/internal/instance/dns", abi: modulePath + "/internal/abi/dns", namespace: modulePath + "/internal/namespace/dns", adapter: modulePath + "/internal/backend/lneto/dns"},
	"icmpv4": {public: modulePath + "/icmpv4", register: modulePath + "/icmpv4/register", binding: modulePath + "/internal/binding/icmpv4", operation: modulePath + "/internal/instance/icmpv4", abi: modulePath + "/internal/abi/icmpv4", namespace: modulePath + "/internal/namespace/icmpv4", adapter: modulePath + "/internal/backend/lneto/icmpv4"},
	"ntp":    {public: modulePath + "/ntp", register: modulePath + "/ntp/register", binding: modulePath + "/internal/binding/ntp", operation: modulePath + "/internal/instance/ntp", abi: modulePath + "/internal/abi/ntp", namespace: modulePath + "/internal/namespace/ntp", adapter: modulePath + "/internal/backend/lneto/ntp"},
	"mdns":   {public: modulePath + "/mdns", register: modulePath + "/mdns/register", binding: modulePath + "/internal/binding/mdns", operation: modulePath + "/internal/instance/mdns", abi: modulePath + "/internal/abi/mdns", namespace: modulePath + "/internal/namespace/mdns", adapter: modulePath + "/internal/backend/lneto/mdns"},
}

func TestFixtureDependencyBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		selected map[string]bool
	}{
		{name: "root", selected: map[string]bool{}},
		{name: "tcp", selected: map[string]bool{"tcp": true}},
		{name: "udp", selected: map[string]bool{"udp": true}},
		{name: "dns", selected: map[string]bool{"dns": true}},
		{name: "icmpv4", selected: map[string]bool{"icmpv4": true}},
		{name: "ntp", selected: map[string]bool{"ntp": true}},
		{name: "mdns", selected: map[string]bool{"mdns": true}},
		{name: "tcpudp", selected: map[string]bool{"tcp": true, "udp": true}},
		{name: "tcpdns", selected: map[string]bool{"tcp": true, "dns": true}},
		{name: "udpdns", selected: map[string]bool{"udp": true, "dns": true}},
		{name: "all", selected: map[string]bool{"tcp": true, "udp": true, "dns": true, "icmpv4": true, "ntp": true, "mdns": true}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := listDependencies(t, "./testdata/"+test.name)
			for _, required := range []string{
				modulePath,
				modulePath + "/internal/abi/core",
				modulePath + "/internal/instance/core",
				modulePath + "/internal/namespace/core",
				modulePath + "/internal/backend/lneto/core",
			} {
				if !dependencies[required] {
					t.Fatalf("dependency %q absent; shared instance-core/backend boundary changed without updating the gate", required)
				}
			}
			for protocol, dependency := range protocolDependencies {
				if test.selected[protocol] {
					if !dependencies[dependency.public] || !dependencies[dependency.binding] || !dependencies[dependency.operation] || !dependencies[dependency.abi] || !dependencies[dependency.namespace] || !dependencies[dependency.adapter] {
						t.Fatalf("selected %s dependencies absent: public=%v binding=%v operation=%v ABI=%v namespace=%v adapter=%v", protocol, dependencies[dependency.public], dependencies[dependency.binding], dependencies[dependency.operation], dependencies[dependency.abi], dependencies[dependency.namespace], dependencies[dependency.adapter])
					}
					continue
				}
				if dependencies[dependency.public] || dependencies[dependency.binding] || dependencies[dependency.operation] || dependencies[dependency.abi] || dependencies[dependency.namespace] || dependencies[dependency.adapter] {
					t.Fatalf("unselected %s compiled: public=%v binding=%v operation=%v ABI=%v namespace=%v adapter=%v", protocol, dependencies[dependency.public], dependencies[dependency.binding], dependencies[dependency.operation], dependencies[dependency.abi], dependencies[dependency.namespace], dependencies[dependency.adapter])
				}
			}
			if dependencies[modulePath+"/internal/namespace"] {
				t.Fatal("production graph reached the temporary aggregate namespace compatibility package")
			}
			if dependencies[modulePath+"/internal/backend/lneto"] {
				t.Fatal("production graph reached the temporary aggregate lneto assembler")
			}
			for _, aggregate := range []string{modulePath + "/compat", modulePath + "/register"} {
				if dependencies[aggregate] {
					t.Fatalf("selective fixture unexpectedly depends on aggregate package %q", aggregate)
				}
			}
		})
	}
}

func TestSelfRegisterPackageDependencyBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		selected map[string]bool
	}{
		{name: "tcp", fixture: "../../tcp/register", selected: map[string]bool{"tcp": true}},
		{name: "udp", fixture: "../../udp/register", selected: map[string]bool{"udp": true}},
		{name: "dns", fixture: "../../dns/register", selected: map[string]bool{"dns": true}},
		{name: "icmpv4", fixture: "../../icmpv4/register", selected: map[string]bool{"icmpv4": true}},
		{name: "ntp", fixture: "../../ntp/register", selected: map[string]bool{"ntp": true}},
		{name: "mdns", fixture: "../../mdns/register", selected: map[string]bool{"mdns": true}},
		{name: "all", fixture: "../../register", selected: map[string]bool{"tcp": true, "udp": true, "dns": true, "icmpv4": true, "ntp": true, "mdns": true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := listDependencies(t, test.fixture)
			for protocol, dependency := range protocolDependencies {
				if test.selected[protocol] {
					if !dependencies[dependency.public] || !dependencies[dependency.binding] || !dependencies[dependency.operation] || !dependencies[dependency.abi] || !dependencies[dependency.namespace] || !dependencies[dependency.adapter] {
						t.Fatalf("selected %s self-register graph is incomplete", protocol)
					}
					if test.name != "all" && !dependencies[dependency.register] {
						t.Fatalf("selected %s granular register package absent", protocol)
					}
					continue
				}
				if dependencies[dependency.public] || dependencies[dependency.register] || dependencies[dependency.binding] || dependencies[dependency.operation] || dependencies[dependency.abi] || dependencies[dependency.namespace] || dependencies[dependency.adapter] {
					t.Fatalf("unselected %s compiled by %s self-register graph", protocol, test.name)
				}
			}
			if dependencies[modulePath+"/compat"] || dependencies[modulePath+"/internal/namespace"] || dependencies[modulePath+"/internal/backend/lneto"] {
				t.Fatalf("%s self-register graph reached an aggregate compatibility implementation", test.name)
			}
			if test.name == "all" && !dependencies[modulePath+"/register"] {
				t.Fatal("all-protocol register bundle absent")
			}
		})
	}
}

func listDependencies(t *testing.T, fixture string) map[string]bool {
	t.Helper()
	command := exec.Command("go", "list", "-deps", "-f={{.ImportPath}}", fixture)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(command.Args, " "), err, output)
	}
	dependencies := make(map[string]bool)
	for _, dependency := range strings.Fields(string(output)) {
		dependencies[dependency] = true
	}
	return dependencies
}
