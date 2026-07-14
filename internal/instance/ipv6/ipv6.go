// Package ipv6 owns exact-instance configured IPv6 namespace operations.
package ipv6

import (
	core "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	ipv6ns "github.com/wago-org/net/internal/namespace/ipv6"
	"github.com/wago-org/net/internal/resource"
)

// Configuration returns the immutable IPv6 contribution attached to the exact
// namespace handle. No backend or guest slice is retained.
func Configuration(state *core.State, namespaceHandle resource.Handle) (configuration ipv6ns.Configuration, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		value, lookupErr := locked.Resources.Lookup(namespaceHandle, resource.KindNamespace)
		if lookupErr != nil {
			return lookupErr
		}
		backend, ok := nscore.ResolveNamespaceService(value, ipv6ns.ServiceKey).(ipv6ns.Namespace)
		if !ok {
			return nscore.Fail(nscore.FailureNotSupported, core.ErrInvalidBackendResult)
		}
		configuration = backend.Configuration()
		if !configuration.Valid() {
			configuration = ipv6ns.Configuration{}
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		return nil
	})
	return
}
