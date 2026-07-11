// Package namespace is a temporary compatibility alias layer. Shared contracts
// live in namespace/core and protocol contracts live in namespace/tcp,
// namespace/udp, and namespace/dns. Production code must import those exact
// packages so omitted protocols remain absent from dependency graphs.
package namespace

import (
	dnsns "github.com/wago-org/net/internal/namespace/dns"
	nscore "github.com/wago-org/net/internal/namespace/core"
	tcpns "github.com/wago-org/net/internal/namespace/tcp"
	udpns "github.com/wago-org/net/internal/namespace/udp"
)

type Endpoint = nscore.Endpoint
type Progress = nscore.Progress

const (
	ProgressDone       = nscore.ProgressDone
	ProgressWouldBlock = nscore.ProgressWouldBlock
	ProgressInProgress = nscore.ProgressInProgress
)

type IOState = nscore.IOState

const (
	IOReady      = nscore.IOReady
	IOWouldBlock = nscore.IOWouldBlock
	IOEOF        = nscore.IOEOF
)

type IOResult = nscore.IOResult
type Readiness = nscore.Readiness

const (
	ReadyReadable  = nscore.ReadyReadable
	ReadyWritable  = nscore.ReadyWritable
	ReadyAccept    = nscore.ReadyAccept
	ReadyConnected = nscore.ReadyConnected
	ReadyDNSResult = nscore.ReadyDNSResult
	ReadyError     = nscore.ReadyError
	ReadyClosed    = nscore.ReadyClosed
)

type Pollable = nscore.Pollable
type Resource = nscore.Resource
type Namespace = nscore.Namespace
type ServiceBudget = nscore.ServiceBudget
type ServiceReport = nscore.ServiceReport

type UDPSocket = udpns.Socket
type DatagramResult = udpns.DatagramResult

type TCPListener = tcpns.Listener
type TCPStream = tcpns.Stream

type DNSRecordType = dnsns.RecordType

const (
	DNSRecordA     = dnsns.RecordA
	DNSRecordAAAA  = dnsns.RecordAAAA
	DNSRecordCNAME = dnsns.RecordCNAME
)

type DNSRecordTypes = dnsns.RecordTypes

const (
	DNSRecordsA    = dnsns.RecordsA
	DNSRecordsAAAA = dnsns.RecordsAAAA
)

type DNSRequest = dnsns.Request
type DNSRecord = dnsns.Record
type DNSNext = dnsns.Next

const (
	DNSNextReady      = dnsns.NextReady
	DNSNextWouldBlock = dnsns.NextWouldBlock
	DNSNextEOF        = dnsns.NextEOF
)

type DNSQuery = dnsns.Query
