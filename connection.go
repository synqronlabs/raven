package raven

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"
)

// ConnectionState represents the current state of an SMTP session per RFC 5321 Section 4.1.4.
type ConnectionState int

const (
	// StateConnect is the initial state when a client connects.
	StateConnect ConnectionState = iota
	// StateGreeted indicates EHLO/HELO has been successfully processed.
	StateGreeted
	// StateMail indicates MAIL FROM has been accepted, transaction in progress.
	StateMail
	// StateRcpt indicates at least one RCPT TO has been accepted.
	StateRcpt
	// StateData indicates DATA command has been issued, awaiting message content.
	StateData
	// StateBDAT indicates BDAT command is in progress (CHUNKING extension).
	StateBDAT
	// StateQuit indicates QUIT command received, connection closing.
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
	// Ext8BitMIME indicates support for 8-bit MIME (RFC 6152).
	Ext8BitMIME Extension = "8BITMIME"
	// ExtPipelining indicates support for command pipelining (RFC 2920).
	ExtPipelining Extension = "PIPELINING"
	// ExtSMTPUTF8 indicates support for internationalized email (RFC 6531).
	ExtSMTPUTF8 Extension = "SMTPUTF8"
	// ExtSTARTTLS indicates support for TLS upgrade (RFC 3207).
	ExtSTARTTLS Extension = "STARTTLS"
	// ExtSize indicates support for message size declaration (RFC 1870).
	ExtSize Extension = "SIZE"
	// ExtDSN indicates support for Delivery Status Notifications (RFC 3461).
	ExtDSN Extension = "DSN"
	// ExtAuth indicates support for SMTP AUTH (RFC 4954).
	ExtAuth Extension = "AUTH"
	// ExtChunking indicates support for BDAT command (RFC 3030).
	ExtChunking Extension = "CHUNKING"
	// ExtBinaryMIME indicates support for binary MIME (RFC 3030).
	ExtBinaryMIME Extension = "BINARYMIME"
	// ExtEnhancedStatusCodes indicates support for enhanced status codes (RFC 2034).
	ExtEnhancedStatusCodes Extension = "ENHANCEDSTATUSCODES"
)

// TLSInfo contains information about the TLS connection, if established.
type TLSInfo struct {
	// Enabled indicates whether TLS is active on this connection.
	Enabled bool
	// Version is the TLS version (e.g., tls.VersionTLS13).
	Version uint16
	// CipherSuite is the negotiated cipher suite.
	CipherSuite uint16
	// ServerName is the SNI server name provided by the client.
	ServerName string
	// PeerCertificates contains the client's certificate chain, if provided.
	PeerCertificates [][]byte
	// NegotiatedProtocol is the ALPN protocol, if any.
	NegotiatedProtocol string
}

// AuthInfo contains information about client authentication.
type AuthInfo struct {
	// Authenticated indicates whether the client has successfully authenticated.
	Authenticated bool
	// Mechanism is the SASL mechanism used (e.g., "PLAIN", "LOGIN").
	Mechanism string
	// Identity is the authenticated identity (username/email).
	Identity string
	// AuthenticatedAt is when authentication succeeded.
	AuthenticatedAt time.Time
}

// ConnectionTrace contains tracing and diagnostic information for a connection.
// This is used for logging, debugging, and generating Received headers.
type ConnectionTrace struct {
	// ID is a unique identifier for this connection (for correlation in logs).
	ID string
	// RemoteAddr is the remote client address.
	RemoteAddr net.Addr
	// LocalAddr is the local server address.
	LocalAddr net.Addr
	// ConnectedAt is when the connection was established.
	ConnectedAt time.Time
	// ClientHostname is the hostname provided in EHLO/HELO.
	ClientHostname string
	// ReverseDNS is the reverse DNS lookup result for the client IP.
	ReverseDNS string
	// CommandCount is the total number of commands processed.
	CommandCount int64
	// TransactionCount is the number of mail transactions completed.
	TransactionCount int64
	// BytesRead is the total bytes read from the client.
	BytesRead int64
	// BytesWritten is the total bytes written to the client.
	BytesWritten int64
	// LastActivity is the timestamp of the last command/response.
	LastActivity time.Time
	// Errors contains any errors encountered during the session.
	Errors []error
}

// ConnectionLimits defines resource limits for a connection.
type ConnectionLimits struct {
	// MaxMessageSize is the maximum allowed message size in bytes (0 = unlimited).
	MaxMessageSize int64
	// MaxRecipients is the maximum recipients per transaction (0 = unlimited).
	MaxRecipients int
	// MaxCommands is the maximum commands before forced disconnect (0 = unlimited).
	MaxCommands int64
	// MaxErrors is the maximum errors before forced disconnect (0 = unlimited).
	MaxErrors int
	// IdleTimeout is the maximum idle time before disconnect.
	IdleTimeout time.Duration
	// CommandTimeout is the maximum time to wait for a complete command.
	CommandTimeout time.Duration
	// DataTimeout is the maximum time to wait for DATA content.
	DataTimeout time.Duration
}

// Connection represents an individual TCP connection for an ESMTP server.
// It manages the full lifecycle of an SMTP session as per RFC 5321,
// with support for pipelining (RFC 2920) and various SMTP extensions.
type Connection struct {
	// conn is the underlying network connection.
	conn net.Conn

	// ctx is the context for this connection, used for cancellation and deadlines.
	ctx context.Context
	// cancel is the cancel function for the connection context.
	cancel context.CancelFunc

	// reader is the buffered reader for incoming data.
	reader *bufio.Reader
	// writer is the buffered writer for outgoing data.
	writer *bufio.Writer

	// mu protects concurrent access to connection state.
	mu sync.RWMutex

	// state is the current SMTP session state.
	state ConnectionState

	// Trace contains connection tracing and diagnostic information.
	Trace ConnectionTrace

	// TLS contains TLS connection information.
	TLS TLSInfo

	// Auth contains authentication information.
	Auth AuthInfo

	// Limits contains the resource limits for this connection.
	Limits ConnectionLimits

	// Extensions contains the set of extensions advertised to the client.
	Extensions map[Extension]string

	// currentMail is the mail transaction currently in progress.
	// Nil when no transaction is active (before MAIL FROM or after reset).
	currentMail *Mail

	// serverHostname is the hostname the server uses in greetings and Received headers.
	serverHostname string

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

// Context returns the connection's context.
func (c *Connection) Context() context.Context {
	return c.ctx
}

// State returns the current connection state.
func (c *Connection) State() ConnectionState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// SetState sets the connection state.
func (c *Connection) SetState(state ConnectionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = state
}

// RemoteAddr returns the remote client address.
func (c *Connection) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// LocalAddr returns the local server address.
func (c *Connection) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// IsTLS returns whether the connection is using TLS.
func (c *Connection) IsTLS() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.TLS.Enabled
}

// IsAuthenticated returns whether the client has authenticated.
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
	c.state = StateGreeted
	c.Trace.TransactionCount++
	return mail
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
// This follows the format specified in RFC 5321 Section 4.4 and RFC 6531 Section 3.7.3.
func (c *Connection) GenerateReceivedHeader(forRecipient string) TraceField {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Determine protocol per RFC 5321, RFC 6531 Section 3.7.3, and RFC 3848.
	// Protocol values: SMTP, ESMTP, ESMTPS, ESMTPA, ESMTPSA,
	// UTF8SMTP, UTF8SMTPS, UTF8SMTPA, UTF8SMTPSA
	var protocol string

	// Check if SMTPUTF8 is being used (message requires UTF8 support)
	useUTF8 := c.currentMail != nil && c.currentMail.Envelope.SMTPUTF8

	if useUTF8 {
		// RFC 6531 Section 3.7.3: Use UTF8SMTP variants
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

	// Append 'A' for authenticated connections per RFC 3848
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
