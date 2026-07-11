//go:build !tinygo

package dependencytest

import (
	"os/exec"
	"strings"
	"testing"
)

const modulePath = "github.com/wago-org/net"

type protocolDependency struct {
	public  string
	binding string
}

var protocolDependencies = map[string]protocolDependency{
	"tcp": {public: modulePath + "/tcp", binding: modulePath + "/internal/binding/tcp"},
	"udp": {public: modulePath + "/udp", binding: modulePath + "/internal/binding/udp"},
	"dns": {public: modulePath + "/dns", binding: modulePath + "/internal/binding/dns"},
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
				modulePath + "/internal/instance",
				modulePath + "/internal/backend/lneto",
			} {
				if !dependencies[required] {
					t.Fatalf("dependency %q absent; unified instance/backend blocker changed without updating the boundary gate", required)
				}
			}
			for protocol, dependency := range protocolDependencies {
				if test.selected[protocol] {
					if !dependencies[dependency.public] || !dependencies[dependency.binding] {
						t.Fatalf("selected %s dependencies absent: public=%v binding=%v", protocol, dependencies[dependency.public], dependencies[dependency.binding])
					}
					continue
				}
				if dependencies[dependency.public] || dependencies[dependency.binding] {
					t.Fatalf("unselected %s compiled: public=%v binding=%v", protocol, dependencies[dependency.public], dependencies[dependency.binding])
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
