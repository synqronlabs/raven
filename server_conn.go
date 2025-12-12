package raven

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"
)

// ConnectionState represents the current state of an SMTP session per RFC 5321.
type ConnectionState int

const (
	StateConnect ConnectionState = iota
	StateGreeted
	StateMail
	StateRcpt
	StateData
	StateBDAT
	StateQuit
)

// String returns the string representation of the connection state.
func (s ConnectionState) String() string {
	switch s {
	case StateConnect:
		return "CONNECT"
	case StateGreeted:
		return "GREETED"
	case StateMail:
		return "MAIL"
	case StateRcpt:
		return "RCPT"
	case StateData:
		return "DATA"
	case StateBDAT:
		return "BDAT"
	case StateQuit:
		return "QUIT"
	default:
		return "UNKNOWN"
	}
}

// Extension represents an SMTP extension advertised via EHLO response.
type Extension string

const (
	Ext8BitMIME            Extension = "8BITMIME"
	ExtPipelining          Extension = "PIPELINING"
	ExtSMTPUTF8            Extension = "SMTPUTF8"
	ExtSTARTTLS            Extension = "STARTTLS"
	ExtSize                Extension = "SIZE"
	ExtDSN                 Extension = "DSN"
	ExtAuth                Extension = "AUTH"
	ExtChunking            Extension = "CHUNKING"
	ExtBinaryMIME          Extension = "BINARYMIME"
	ExtEnhancedStatusCodes Extension = "ENHANCEDSTATUSCODES"
	ExtRequireTLS          Extension = "REQUIRETLS"
)

// TLSInfo contains information about the TLS connection.
type TLSInfo struct {
	Enabled            bool
	Version            uint16
	CipherSuite        uint16
	ServerName         string
	PeerCertificates   [][]byte
	NegotiatedProtocol string
}

// AuthInfo contains information about client authentication.
type AuthInfo struct {
	Authenticated   bool
	Mechanism       string
	Identity        string
	AuthenticatedAt time.Time
}

// ConnectionTrace contains diagnostic information for a connection.
type ConnectionTrace struct {
	ID               string
	RemoteAddr       net.Addr
	LocalAddr        net.Addr
	ConnectedAt      time.Time
	ClientHostname   string
	CommandCount     int64
	TransactionCount int64
	BytesRead        int64
	BytesWritten     int64
	LastActivity     time.Time
	Errors           []error
}

// ConnectionLimits defines resource limits for a connection.
type ConnectionLimits struct {
	MaxMessageSize int64
	MaxRecipients  int
	MaxCommands    int64
	MaxErrors      int
	IdleTimeout    time.Duration
	CommandTimeout time.Duration
	DataTimeout    time.Duration
}

// Connection represents an SMTP session.
type Connection struct {
	conn           net.Conn
	ctx            context.Context
	cancel         context.CancelFunc
	reader         *bufio.Reader
	writer         *bufio.Writer
	mu             sync.RWMutex
	state          ConnectionState
	Trace          ConnectionTrace
	TLS            TLSInfo
	Auth           AuthInfo
	Limits         ConnectionLimits
	Extensions     map[Extension]string
	currentMail    *Mail
	serverHostname string

	// bdatBuffer accumulates chunk data during BDAT transfers.
	bdatBuffer []byte

	// closedChan is closed when the connection is terminated.
	closedChan chan struct{}

	// closed indicates the connection has been closed.
	closed bool
}

// NewConnection creates a new Connection from a net.Conn.
// The provided context is used for cancellation and deadlines.
func NewConnection(ctx context.Context, conn net.Conn, serverHostname string, limits ConnectionLimits, bufioSize int) *Connection {
	connCtx, cancel := context.WithCancel(ctx)
	now := time.Now()

	c := &Connection{
		conn:   conn,
		ctx:    connCtx,
		cancel: cancel,
		reader: bufio.NewReaderSize(conn, bufioSize),
		writer: bufio.NewWriterSize(conn, bufioSize),
		state:  StateConnect,
		Trace: ConnectionTrace{
			RemoteAddr:   conn.RemoteAddr(),
			LocalAddr:    conn.LocalAddr(),
			ConnectedAt:  now,
			LastActivity: now,
		},
		Limits:         limits,
		Extensions:     make(map[Extension]string),
		serverHostname: serverHostname,
		closedChan:     make(chan struct{}),
	}

	return c
}

func (c *Connection) Context() context.Context {
	return c.ctx
}

func (c *Connection) State() ConnectionState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// StateInfo returns multiple state values in a single lock acquisition.
// This reduces lock contention when multiple state checks are needed.
type StateInfo struct {
	State           ConnectionState
	IsTLS           bool
	IsAuthenticated bool
}

// GetStateInfo returns connection state, TLS status, and auth status atomically.
func (c *Connection) GetStateInfo() StateInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return StateInfo{
		State:           c.state,
		IsTLS:           c.TLS.Enabled,
		IsAuthenticated: c.Auth.Authenticated,
	}
}

// SetState sets the connection state.
func (c *Connection) SetState(state ConnectionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = state
}

func (c *Connection) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Connection) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *Connection) IsTLS() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.TLS.Enabled
}

func (c *Connection) IsAuthenticated() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Auth.Authenticated
}

// CurrentMail returns the current mail transaction, or nil if none is active.
func (c *Connection) CurrentMail() *Mail {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentMail
}

// BeginTransaction starts a new mail transaction.
func (c *Connection) BeginTransaction() *Mail {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.currentMail = NewMail()
	c.currentMail.ReceivedAt = time.Now()
	return c.currentMail
}

// ResetTransaction aborts the current mail transaction (RSET command).
// Returns the connection to the GREETED state per RFC 5321.
func (c *Connection) ResetTransaction() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.currentMail = nil
	c.bdatBuffer = nil
	if c.state != StateConnect {
		c.state = StateGreeted
	}
}

// CompleteTransaction finalizes the current mail transaction.
// Returns the completed Mail and resets for the next transaction.
func (c *Connection) CompleteTransaction() *Mail {
	c.mu.Lock()
	defer c.mu.Unlock()
	mail := c.currentMail
	c.currentMail = nil
	c.bdatBuffer = nil
	c.state = StateGreeted
	c.Trace.TransactionCount++
	return mail
}

// AppendBDATChunk appends data to the BDAT buffer during chunked transfers.
func (c *Connection) AppendBDATChunk(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bdatBuffer = append(c.bdatBuffer, data...)
}

// BDATBufferSize returns the current size of the BDAT buffer.
func (c *Connection) BDATBufferSize() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return int64(len(c.bdatBuffer))
}

// ConsumeBDATBuffer returns the accumulated BDAT data and clears the buffer.
func (c *Connection) ConsumeBDATBuffer() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	data := c.bdatBuffer
	c.bdatBuffer = nil
	return data
}

// Close closes the connection and releases resources.
func (c *Connection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	c.cancel()
	close(c.closedChan)

	// Flush any pending writes
	_ = c.writer.Flush()

	return c.conn.Close()
}

// Done returns a channel that is closed when the connection is terminated.
func (c *Connection) Done() <-chan struct{} {
	return c.closedChan
}

// UpdateActivity updates the last activity timestamp and increments command count.
func (c *Connection) UpdateActivity() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Trace.LastActivity = time.Now()
	c.Trace.CommandCount++
}

// RecordError records an error for this connection.
func (c *Connection) RecordError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Trace.Errors = append(c.Trace.Errors, err)
}

// ErrorCount returns the number of errors recorded for this connection.
func (c *Connection) ErrorCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.Trace.Errors)
}

// SetClientHostname sets the hostname from EHLO/HELO.
func (c *Connection) SetClientHostname(hostname string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Trace.ClientHostname = hostname
}

// SetExtension sets an extension with optional parameters.
func (c *Connection) SetExtension(ext Extension, params string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Extensions[ext] = params
}

// HasExtension checks if an extension is enabled.
func (c *Connection) HasExtension(ext Extension) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.Extensions[ext]
	return ok
}

// UpgradeToTLS upgrades the connection to TLS using STARTTLS.
func (c *Connection) UpgradeToTLS(config *tls.Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	tlsConn := tls.Server(c.conn, config)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}

	// Update connection state
	c.conn = tlsConn
	c.reader = bufio.NewReader(tlsConn)
	c.writer = bufio.NewWriter(tlsConn)

	// Record TLS information
	state := tlsConn.ConnectionState()
	c.TLS = TLSInfo{
		Enabled:            true,
		Version:            state.Version,
		CipherSuite:        state.CipherSuite,
		ServerName:         state.ServerName,
		NegotiatedProtocol: state.NegotiatedProtocol,
	}

	// Store peer certificates
	for _, cert := range state.PeerCertificates {
		c.TLS.PeerCertificates = append(c.TLS.PeerCertificates, cert.Raw)
	}

	// Reset state after STARTTLS per RFC 3207
	c.state = StateConnect

	return nil
}

// GenerateReceivedHeader creates a Received header for the current transaction.
// This follows the format specified in RFC 5321 and RFC 6531.
func (c *Connection) GenerateReceivedHeader(forRecipient string) TraceField {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Determine protocol per RFC 5321, RFC 6531, and RFC 3848.
	// Protocol values: SMTP, ESMTP, ESMTPS, ESMTPA, ESMTPSA,
	// UTF8SMTP, UTF8SMTPS, UTF8SMTPA, UTF8SMTPSA
	var protocol string

	// Check if SMTPUTF8 is being used (message requires UTF8 support)
	useUTF8 := c.currentMail != nil && c.currentMail.Envelope.SMTPUTF8

	if useUTF8 {
		// Use UTF8SMTP variants
		protocol = "UTF8SMTP"
		if c.TLS.Enabled {
			protocol = "UTF8SMTPS"
		}
	} else {
		protocol = "SMTP"
		if c.TLS.Enabled {
			protocol = "ESMTPS"
		} else if len(c.Extensions) > 0 {
			protocol = "ESMTP"
		}
	}

	// Append 'A' for authenticated connections
	if c.Auth.Authenticated {
		protocol += "A"
	}

	return TraceField{
		Type:       "Received",
		FromDomain: c.Trace.ClientHostname,
		FromIP:     c.Trace.RemoteAddr.String(),
		ByDomain:   c.serverHostname,
		Via:        "TCP",
		With:       protocol,
		For:        forRecipient,
		Timestamp:  time.Now(),
		TLS:        c.TLS.Enabled,
	}
}
