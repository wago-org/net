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
}

var protocolDependencies = map[string]protocolDependency{
	"tcp": {public: modulePath + "/tcp", binding: modulePath + "/internal/binding/tcp", operation: modulePath + "/internal/instance/tcp", abi: modulePath + "/internal/abi/tcp"},
	"udp": {public: modulePath + "/udp", binding: modulePath + "/internal/binding/udp", operation: modulePath + "/internal/instance/udp", abi: modulePath + "/internal/abi/udp"},
	"dns": {public: modulePath + "/dns", binding: modulePath + "/internal/binding/dns", operation: modulePath + "/internal/instance/dns", abi: modulePath + "/internal/abi/dns"},
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
				modulePath + "/internal/backend/lneto",
			} {
				if !dependencies[required] {
					t.Fatalf("dependency %q absent; shared instance-core/backend boundary changed without updating the gate", required)
				}
			}
			for protocol, dependency := range protocolDependencies {
				if test.selected[protocol] {
					if !dependencies[dependency.public] || !dependencies[dependency.binding] || (dependency.operation != "" && !dependencies[dependency.operation]) || (dependency.abi != "" && !dependencies[dependency.abi]) {
						t.Fatalf("selected %s dependencies absent: public=%v binding=%v operation=%v ABI=%v", protocol, dependencies[dependency.public], dependencies[dependency.binding], dependencies[dependency.operation], dependencies[dependency.abi])
					}
					continue
				}
				if dependencies[dependency.public] || dependencies[dependency.binding] || (dependency.operation != "" && dependencies[dependency.operation]) || (dependency.abi != "" && dependencies[dependency.abi]) {
					t.Fatalf("unselected %s compiled: public=%v binding=%v operation=%v ABI=%v", protocol, dependencies[dependency.public], dependencies[dependency.binding], dependencies[dependency.operation], dependencies[dependency.abi])
				}
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
