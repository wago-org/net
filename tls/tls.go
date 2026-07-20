// Package tls selectively registers Wago's outbound, verified, nonblocking TLS
// client capability. TLS is independent from the public raw-TCP capability.
package tls

import "errors"

var ErrInvalidOption = errors.New("wagonet/tls: invalid option")
