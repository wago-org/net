// Package tcp defines the narrow backend-neutral TCP namespace facet and
// listener/stream resource contracts.
package tcp

import nscore "github.com/wago-org/net/internal/namespace/core"

// Namespace creates TCP resources on the shared namespace object. Resources are
// returned through the shared lifetime contract and must satisfy Listener or
// Stream as appropriate before callers publish them.
type Namespace interface {
	TryListenTCP(local nscore.Endpoint) (nscore.Resource, nscore.Progress, error)
	TryConnectTCP(remote nscore.Endpoint) (nscore.Resource, nscore.Progress, error)
}

// Listener accepts only fully established streams. The returned shared resource
// must satisfy Stream before it is exposed to a caller.
type Listener interface {
	nscore.Resource
	LocalEndpoint() nscore.Endpoint
	TryAccept() (nscore.Resource, nscore.Progress, error)
}

// Stream exposes nonblocking connection completion and byte-stream I/O.
type Stream interface {
	nscore.Resource
	LocalEndpoint() nscore.Endpoint
	RemoteEndpoint() nscore.Endpoint
	TryFinishConnect() (nscore.Progress, error)
	TryRead(dst []byte) (nscore.IOResult, error)
	TryWrite(src []byte) (nscore.IOResult, error)
	TryShutdownWrite() (nscore.Progress, error)
}
