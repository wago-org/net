package guest

import "testing"

type hardeningPanicMemoryModule struct{}

func (*hardeningPanicMemoryModule) Memory() []byte {
	panic("typed-nil HostModule method invoked")
}

func TestMemoryFailsClosedForTypedNilHostModule(t *testing.T) {
	var module *hardeningPanicMemoryModule
	if memory := Memory(module); memory != nil {
		t.Fatalf("Memory(typed nil) = %v, want nil", memory)
	}
}
