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
	binding   string
	operation string
	abi       string
	namespace string
}

var protocolDependencies = map[string]protocolDependency{
	"tcp": {public: modulePath + "/tcp", binding: modulePath + "/internal/binding/tcp", operation: modulePath + "/internal/instance/tcp", abi: modulePath + "/internal/abi/tcp", namespace: modulePath + "/internal/namespace/tcp"},
	"udp": {public: modulePath + "/udp", binding: modulePath + "/internal/binding/udp", operation: modulePath + "/internal/instance/udp", abi: modulePath + "/internal/abi/udp", namespace: modulePath + "/internal/namespace/udp"},
	"dns": {public: modulePath + "/dns", binding: modulePath + "/internal/binding/dns", operation: modulePath + "/internal/instance/dns", abi: modulePath + "/internal/abi/dns", namespace: modulePath + "/internal/namespace/dns"},
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
		{name: "tcpudp", selected: map[string]bool{"tcp": true, "udp": true}},
		{name: "tcpdns", selected: map[string]bool{"tcp": true, "dns": true}},
		{name: "udpdns", selected: map[string]bool{"udp": true, "dns": true}},
		{name: "all", selected: map[string]bool{"tcp": true, "udp": true, "dns": true}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := listDependencies(t, "./testdata/"+test.name)
			for _, required := range []string{
				modulePath,
				modulePath + "/internal/abi/core",
				modulePath + "/internal/instance/core",
				modulePath + "/internal/namespace/core",
				modulePath + "/internal/backend/lneto",
				modulePath + "/internal/backend/lneto/core",
				modulePath + "/internal/backend/lneto/dns",
				modulePath + "/internal/backend/lneto/tcp",
				modulePath + "/internal/backend/lneto/udp",
			} {
				if !dependencies[required] {
					t.Fatalf("dependency %q absent; shared instance-core/backend boundary changed without updating the gate", required)
				}
			}
			for protocol, dependency := range protocolDependencies {
				if test.selected[protocol] {
					if !dependencies[dependency.public] || !dependencies[dependency.binding] || !dependencies[dependency.operation] || !dependencies[dependency.abi] || !dependencies[dependency.namespace] {
						t.Fatalf("selected %s dependencies absent: public=%v binding=%v operation=%v ABI=%v namespace=%v", protocol, dependencies[dependency.public], dependencies[dependency.binding], dependencies[dependency.operation], dependencies[dependency.abi], dependencies[dependency.namespace])
					}
					continue
				}
				if dependencies[dependency.public] || dependencies[dependency.binding] || dependencies[dependency.operation] || dependencies[dependency.abi] {
					t.Fatalf("unselected %s compiled: public=%v binding=%v operation=%v ABI=%v", protocol, dependencies[dependency.public], dependencies[dependency.binding], dependencies[dependency.operation], dependencies[dependency.abi])
				}
				// All adapters are now separate packages, but aggregate root construction
				// still imports all three in every fixture until namespace contributions
				// move into selective descriptors. TCP contracts remain structural.
				if protocol == "tcp" && dependencies[dependency.namespace] {
					t.Fatalf("unselected TCP namespace facet compiled")
				}
			}
			if dependencies[modulePath+"/internal/namespace"] {
				t.Fatal("production graph reached the temporary aggregate namespace compatibility package")
			}
			for _, aggregate := range []string{modulePath + "/compat", modulePath + "/register"} {
				if dependencies[aggregate] {
					t.Fatalf("selective fixture unexpectedly depends on aggregate package %q", aggregate)
				}
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
