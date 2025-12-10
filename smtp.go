// Package raven provides a high-performance, RFC-compliant SMTP server library for Go.
//
// Raven is designed for building mail transfer agents (MTAs), mail submission agents (MSAs),
// and custom email processing applications with a focus on flexibility, correctness, and security.
//
// # Features
//
//   - Full RFC 5321 compliance with complete SMTP protocol implementation
//   - Modern SMTP extensions: STARTTLS, AUTH, 8BITMIME, SMTPUTF8, PIPELINING, SIZE, DSN, CHUNKING
//   - Flexible callback system for hooking into every stage of the SMTP transaction
//   - Built-in connection management with configurable limits
//   - Efficient concurrent connection handling
//   - Structured logging with slog integration
//   - Graceful shutdown with configurable timeouts
//   - SMTP smuggling protection with strict CRLF line ending validation
//
// # Quick Start
//
// Create a basic SMTP server that logs received messages:
//
//	config := raven.DefaultServerConfig()
//	config.Hostname = "mail.example.com"
//	config.Callbacks = &raven.Callbacks{
//	    OnMessage: func(ctx context.Context, conn *raven.Connection, mail *raven.Mail) error {
//	        log.Printf("Received mail from %s", mail.Envelope.From.String())
//	        return nil
//	    },
//	}
//
//	server, err := raven.NewServer(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	log.Fatal(server.ListenAndServe())
//
// # TLS Configuration
//
// Enable STARTTLS by providing a TLS configuration:
//
//	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	config := raven.DefaultServerConfig()
//	config.Hostname = "mail.example.com"
//	config.TLSConfig = &tls.Config{
//	    Certificates: []tls.Certificate{cert},
//	    MinVersion:   tls.VersionTLS12,
//	}
//
//	server, err := raven.NewServer(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	log.Fatal(server.ListenAndServe())
//
// # Authentication
//
// Implement authentication with the OnAuth callback:
//
//	config.Callbacks = &raven.Callbacks{
//	    OnAuth: func(ctx context.Context, conn *raven.Connection, mechanism, identity, password string) error {
//	        if !validateCredentials(identity, password) {
//	            return errors.New("invalid credentials")
//	        }
//	        return nil
//	    },
//	}
//
// # Callback System
//
// The Callbacks structure provides hooks for every stage of the SMTP transaction:
//
//   - OnConnect: Called when a client connects, before the greeting
//   - OnHelo/OnEhlo: Called when HELO/EHLO command is received
//   - OnMailFrom: Called when MAIL FROM command is received
//   - OnRcptTo: Called for each RCPT TO command
//   - OnData: Called when DATA command is received
//   - OnMessage: Called when a complete message has been received
//   - OnAuth: Called when authentication is attempted
//   - OnDisconnect: Called when a client disconnects
//
// All callbacks are optional and can return errors to reject commands.
//
// # Resource Limits
//
// Configure limits to protect against abuse:
//
//	config.MaxMessageSize = 10 * 1024 * 1024  // 10 MB
//	config.MaxRecipients = 100
//	config.MaxConnections = 1000
//	config.MaxCommands = 1000
//	config.MaxErrors = 10
//
// # Graceful Shutdown
//
// Shutdown the server gracefully:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//
//	if err := server.Shutdown(ctx); err != nil {
//	    log.Printf("Shutdown error: %v", err)
//	}
//
// # RFC Compliance
//
// Raven implements the following RFCs:
//
//   - RFC 5321: Simple Mail Transfer Protocol
//   - RFC 2920: SMTP Service Extension for Command Pipelining
//   - RFC 3207: SMTP Service Extension for Secure SMTP over TLS
//   - RFC 4954: SMTP Service Extension for Authentication
//   - RFC 6152: SMTP Service Extension for 8-bit MIME Transport
//   - RFC 6531: SMTP Extension for Internationalized Email
//   - RFC 1870: SMTP Service Extension for Message Size Declaration
//   - RFC 3461: SMTP Service Extension for Delivery Status Notifications
//   - RFC 3030: SMTP Service Extensions for Transmission of Large and Binary MIME Messages
//   - RFC 2034: SMTP Service Extension for Returning Enhanced Error Codes
//
// # Security
//
// Raven includes several security features:
//
//   - Strict CRLF validation to prevent SMTP smuggling attacks
//   - TLS support with STARTTLS and implicit TLS
//   - SASL authentication with PLAIN and LOGIN mechanisms
//   - Configurable resource limits to prevent abuse
//   - Connection-level rate limiting and IP filtering via callbacks
package raven

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/synqronlabs/raven/dns"
	"github.com/synqronlabs/raven/utils"
)

// Common SMTP errors.
var (
	ErrServerClosed     = errors.New("smtp: server closed")
	ErrLineTooLong      = errors.New("smtp: line too long")
	ErrTooManyRecipents = errors.New("smtp: too many recipients")
	ErrMessageTooLarge  = errors.New("smtp: message too large")
	ErrTimeout          = errors.New("smtp: timeout")
	ErrTLSRequired      = errors.New("smtp: TLS required")
	ErrAuthRequired     = errors.New("smtp: authentication required")
)

// SMTPCode represents standard SMTP reply codes per RFC 5321.
type SMTPCode int

const (
	CodeServiceReady          SMTPCode = 220
	CodeServiceClosing        SMTPCode = 221
	CodeAuthSuccess           SMTPCode = 235
	CodeOK                    SMTPCode = 250
	CodeStartMailInput        SMTPCode = 354
	CodeServiceUnavailable    SMTPCode = 421
	CodeMailboxUnavailable    SMTPCode = 450
	CodeLocalError            SMTPCode = 451
	CodeInsufficientStorage   SMTPCode = 452
	CodeCommandUnrecognized   SMTPCode = 500
	CodeSyntaxError           SMTPCode = 501
	CodeCommandNotImplemented SMTPCode = 502
	CodeBadSequence           SMTPCode = 503
	CodeParameterNotImpl      SMTPCode = 504
	CodeMailboxNotFound       SMTPCode = 550
	CodeUserNotLocal          SMTPCode = 551
	CodeExceededStorage       SMTPCode = 552
	CodeMailboxNameInvalid    SMTPCode = 553
	CodeTransactionFailed     SMTPCode = 554
)

// Response represents an SMTP response to be sent to the client.
type Response struct {
	Code         SMTPCode
	EnhancedCode string
	Message      string
}

// String formats the response as an SMTP reply line.
func (r Response) String() string {
	if r.EnhancedCode != "" {
		return fmt.Sprintf("%d %s %s", r.Code, r.EnhancedCode, r.Message)
	}
	return fmt.Sprintf("%d %s", r.Code, r.Message)
}

// Callbacks defines the callback interface for SMTP server events.
// All callbacks are optional; nil callbacks are simply not invoked.
// Callbacks should return quickly to avoid blocking the connection handler.
type Callbacks struct {
	// OnConnect is called when a new client connects.
	// Return an error to reject the connection with a 554 response.
	OnConnect func(ctx context.Context, conn *Connection) error

	// OnDisconnect is called when a client disconnects.
	OnDisconnect func(ctx context.Context, conn *Connection)

	// OnHelo is called when HELO command is received.
	// Return an error to reject with a 550 response.
	OnHelo func(ctx context.Context, conn *Connection, hostname string) error

	// OnEhlo is called when EHLO command is received.
	// Return an error to reject with a 550 response.
	// The returned map of extensions will be advertised to the client.
	OnEhlo func(ctx context.Context, conn *Connection, hostname string) (extensions map[Extension]string, err error)

	// OnStartTLS is called before TLS handshake begins.
	// Return an error to reject the STARTTLS command.
	OnStartTLS func(ctx context.Context, conn *Connection) error

	// OnAuth is called when authentication is attempted.
	// Return nil to accept the authentication, error to reject.
	OnAuth func(ctx context.Context, conn *Connection, mechanism, identity, password string) error

	// OnMailFrom is called when MAIL FROM command is received.
	// Return an error to reject the sender with a 550 response.
	OnMailFrom func(ctx context.Context, conn *Connection, from Path, params map[string]string) error

	// OnRcptTo is called for each RCPT TO command.
	// Return an error to reject the recipient with a 550 response.
	OnRcptTo func(ctx context.Context, conn *Connection, to Path, params map[string]string) error

	// OnData is called when DATA command is received and before message content.
	// Return an error to reject with a 554 response.
	OnData func(ctx context.Context, conn *Connection) error

	// OnBDAT is called when BDAT command is received (CHUNKING extension).
	// The size parameter indicates the chunk size, last indicates if this is the final chunk.
	// Return an error to reject with a 554 response.
	OnBDAT func(ctx context.Context, conn *Connection, size int64, last bool) error

	// OnMessage is called when a complete message has been received.
	// The Mail object contains the envelope and content.
	// Return an error to reject the message with a 554 response.
	OnMessage func(ctx context.Context, conn *Connection, mail *Mail) error

	// OnReset is called when RSET command is received.
	OnReset func(ctx context.Context, conn *Connection)

	// OnVerify is called when VRFY command is received.
	// Return the verified address or an error.
	OnVerify func(ctx context.Context, conn *Connection, address string) (MailboxAddress, error)

	// OnExpand is called when EXPN command is received.
	// Return the list of addresses or an error.
	OnExpand func(ctx context.Context, conn *Connection, listName string) ([]MailboxAddress, error)

	// OnUnknownCommand is called for unrecognized commands.
	// Return a custom response or nil to use default 500 response.
	OnUnknownCommand func(ctx context.Context, conn *Connection, command, args string) *Response
}

// ServerConfig contains configuration options for the SMTP server.
type ServerConfig struct {
	// Hostname is the server's hostname used in greetings and Received headers.
	// Required.
	Hostname string

	// Addr is the address to listen on (e.g., ":25", "0.0.0.0:587").
	// Default: ":25"
	Addr string

	// TLSConfig is the TLS configuration for STARTTLS and implicit TLS.
	// If nil, STARTTLS will not be offered.
	TLSConfig *tls.Config

	// RequireTLS requires clients to use TLS before authentication.
	RequireTLS bool

	// RequireAuth requires clients to authenticate before sending mail.
	RequireAuth bool

	// MaxMessageSize is the maximum message size in bytes (0 = unlimited).
	// Advertised via SIZE extension.
	MaxMessageSize int64

	// MaxRecipients is the maximum recipients per message (0 = unlimited).
	MaxRecipients int

	// MaxConnections is the maximum concurrent connections (0 = unlimited).
	MaxConnections int

	// MaxCommands is the maximum commands per connection (0 = unlimited).
	MaxCommands int64

	// MaxErrors is the maximum errors before disconnect (0 = unlimited).
	MaxErrors int

	// ReadTimeout is the timeout for reading a command line.
	// Default: 5 minutes
	ReadTimeout time.Duration

	// WriteTimeout is the timeout for writing a response.
	// Default: 5 minutes
	WriteTimeout time.Duration

	// DataTimeout is the timeout for reading DATA content.
	// Default: 10 minutes
	DataTimeout time.Duration

	// IdleTimeout is the maximum idle time before disconnect.
	// Default: 5 minutes
	IdleTimeout time.Duration

	// MaxLineLength is the maximum length of a command line (RFC 5321: 512).
	// Default: 512
	MaxLineLength int

	// Enable8BitMIME enables 8BITMIME extension (RFC 6152).
	// Default: true
	Enable8BitMIME bool

	// EnableSMTPUTF8 enables SMTPUTF8 extension (RFC 6531).
	// Default: true
	EnableSMTPUTF8 bool

	// EnableDSN enables DSN extension (RFC 3461).
	// Default: false
	EnableDSN bool

	// EnableChunking enables CHUNKING/BDAT extension (RFC 3030).
	// This allows clients to send message data in chunks using BDAT command
	// instead of the traditional DATA command.
	// Default: false
	EnableChunking bool

	// EnableReverseDNS enables reverse DNS lookups for incoming connections.
	// When enabled, the server will perform a PTR record lookup for the client's
	// IP address and populate the ReverseDNS field in ConnectionTrace.
	// This can be useful for logging and generating Received headers with hostnames.
	// Default: false
	EnableReverseDNS bool

	// AuthMechanisms is the list of supported AUTH mechanisms.
	// Default: ["PLAIN", "LOGIN"]
	AuthMechanisms []string

	// Logger is the structured logger for the server.
	// Default: slog.Default()
	Logger *slog.Logger

	// Callbacks contains the event callbacks.
	Callbacks *Callbacks
}

// DefaultServerConfig returns a ServerConfig with sensible defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Addr:           ":25",
		ReadTimeout:    5 * time.Minute,
		WriteTimeout:   5 * time.Minute,
		DataTimeout:    10 * time.Minute,
		IdleTimeout:    5 * time.Minute,
		MaxLineLength:  512,
		Enable8BitMIME: true,
		EnableSMTPUTF8: true,
		AuthMechanisms: []string{"PLAIN", "LOGIN"},
		Logger:         slog.Default(),
	}
}

// Server is an SMTP server that handles concurrent connections.
type Server struct {
	config   ServerConfig
	listener net.Listener

	// connections tracks active connections
	connMu      sync.Mutex
	connections map[*Connection]struct{}
	connCount   atomic.Int64

	// shutdown coordination
	ctx        context.Context
	cancel     context.CancelFunc
	shutdownWg sync.WaitGroup
	closed     atomic.Bool
}

// NewServer creates a new SMTP server with the given configuration.
func NewServer(config ServerConfig) (*Server, error) {
	if config.Hostname == "" {
		return nil, errors.New("smtp: hostname is required")
	}

	// Apply defaults
	if config.Addr == "" {
		config.Addr = ":25"
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 5 * time.Minute
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 5 * time.Minute
	}
	if config.DataTimeout == 0 {
		config.DataTimeout = 10 * time.Minute
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = 5 * time.Minute
	}
	if config.MaxLineLength == 0 {
		config.MaxLineLength = 512
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.AuthMechanisms == nil {
		config.AuthMechanisms = []string{"PLAIN", "LOGIN"}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		config:      config,
		connections: make(map[*Connection]struct{}),
		ctx:         ctx,
		cancel:      cancel,
	}, nil
}

// ListenAndServe starts the SMTP server on the configured address.
func (s *Server) ListenAndServe() error {
	listener, err := net.Listen("tcp", s.config.Addr)
	if err != nil {
		return fmt.Errorf("smtp: failed to listen: %w", err)
	}
	return s.Serve(listener)
}

// ListenAndServeTLS starts the SMTP server with implicit TLS.
func (s *Server) ListenAndServeTLS() error {
	if s.config.TLSConfig == nil {
		return errors.New("smtp: TLS config is required for TLS server")
	}
	listener, err := tls.Listen("tcp", s.config.Addr, s.config.TLSConfig)
	if err != nil {
		return fmt.Errorf("smtp: failed to listen TLS: %w", err)
	}
	return s.Serve(listener)
}

// Serve accepts connections on the listener and handles them.
func (s *Server) Serve(listener net.Listener) error {
	s.listener = listener

	s.config.Logger.Info("SMTP server started",
		slog.String("addr", listener.Addr().String()),
		slog.String("hostname", s.config.Hostname),
	)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.closed.Load() {
				return ErrServerClosed
			}
			s.config.Logger.Error("accept error", slog.Any("error", err))
			continue
		}

		// Check connection limit
		if s.config.MaxConnections > 0 && s.connCount.Load() >= int64(s.config.MaxConnections) {
			s.config.Logger.Warn("connection limit reached",
				slog.String("remote", conn.RemoteAddr().String()),
			)
			_ = conn.Close()
			continue
		}

		s.shutdownWg.Add(1)
		go s.handleConnection(conn)
	}
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.closed.Store(true)
	s.cancel()

	if s.listener != nil {
		_ = s.listener.Close()
	}

	// Send 421 response to all connected clients
	s.sendShutdownResponse()

	// Wait for connections to finish with context timeout
	done := make(chan struct{})
	go func() {
		s.shutdownWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		// Force close remaining connections
		s.connMu.Lock()
		for conn := range s.connections {
			_ = conn.Close()
		}
		s.connMu.Unlock()
		return ctx.Err()
	}
}

// Close immediately closes the server and all connections.
func (s *Server) Close() error {
	s.closed.Store(true)
	s.cancel()

	if s.listener != nil {
		_ = s.listener.Close()
	}

	// Send 421 response to all connected clients before closing
	s.sendShutdownResponse()

	s.connMu.Lock()
	for conn := range s.connections {
		_ = conn.Close()
	}
	s.connMu.Unlock()

	return nil
}

// sendShutdownResponse sends a 421 response to all connected clients and closes them.
// Per RFC 5321, servers should send 421 before closing connections.
func (s *Server) sendShutdownResponse() {
	s.connMu.Lock()
	defer s.connMu.Unlock()

	for conn := range s.connections {
		// Set a short write deadline to avoid blocking shutdown
		_ = conn.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		resp := Response{
			Code:    CodeServiceUnavailable,
			Message: fmt.Sprintf("%s Service shutting down [%s]", s.config.Hostname, conn.Trace.ID),
		}
		line := resp.String() + "\r\n"
		_, _ = conn.writer.WriteString(line)
		_ = conn.writer.Flush()
		// Close the connection to unblock any pending reads
		_ = conn.conn.Close()
	}
}

// generateConnectionID creates a unique connection ID.
func generateConnectionID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// handleConnection processes a single client connection.
func (s *Server) handleConnection(netConn net.Conn) {
	defer s.shutdownWg.Done()

	limits := ConnectionLimits{
		MaxMessageSize: s.config.MaxMessageSize,
		MaxRecipients:  s.config.MaxRecipients,
		MaxCommands:    s.config.MaxCommands,
		MaxErrors:      s.config.MaxErrors,
		IdleTimeout:    s.config.IdleTimeout,
		CommandTimeout: s.config.ReadTimeout,
		DataTimeout:    s.config.DataTimeout,
	}

	conn := NewConnection(s.ctx, netConn, s.config.Hostname, limits, s.config.MaxLineLength)
	conn.Trace.ID = generateConnectionID()

	// Check if implicit TLS
	if _, ok := netConn.(*tls.Conn); ok {
		tlsConn := netConn.(*tls.Conn)
		state := tlsConn.ConnectionState()
		conn.TLS = TLSInfo{
			Enabled:            true,
			Version:            state.Version,
			CipherSuite:        state.CipherSuite,
			ServerName:         state.ServerName,
			NegotiatedProtocol: state.NegotiatedProtocol,
		}
	}

	// Track connection
	s.connMu.Lock()
	s.connections[conn] = struct{}{}
	s.connMu.Unlock()
	s.connCount.Add(1)

	defer func() {
		s.connMu.Lock()
		delete(s.connections, conn)
		s.connMu.Unlock()
		s.connCount.Add(-1)
		_ = conn.Close()

		// OnDisconnect callback
		if s.config.Callbacks != nil && s.config.Callbacks.OnDisconnect != nil {
			s.config.Callbacks.OnDisconnect(conn.Context(), conn)
		}
	}()

	logger := s.config.Logger.With(
		slog.String("conn_id", conn.Trace.ID),
		slog.String("remote", conn.RemoteAddr().String()),
	)

	logger.Info("client connected")

	// Perform reverse DNS lookup if enabled
	if s.config.EnableReverseDNS {
		if ptrRecord, err := dns.ReverseDNSLookup(conn.RemoteAddr()); err == nil {
			conn.Trace.ReverseDNS = ptrRecord
			logger.Debug("reverse DNS lookup successful",
				slog.String("ptr", ptrRecord),
			)
		} else {
			logger.Debug("reverse DNS lookup failed",
				slog.Any("error", err),
			)
		}
	}

	// OnConnect callback
	if s.config.Callbacks != nil && s.config.Callbacks.OnConnect != nil {
		if err := s.config.Callbacks.OnConnect(conn.Context(), conn); err != nil {
			logger.Warn("connection rejected", slog.Any("error", err))
			s.writeResponse(conn, Response{
				Code:    CodeTransactionFailed,
				Message: "Connection rejected",
			})
			return
		}
	}

	// Send greeting
	s.writeResponse(conn, Response{
		Code:    CodeServiceReady,
		Message: fmt.Sprintf("%s ESMTP ready [%s]", s.config.Hostname, conn.Trace.ID),
	})

	// Main command loop
	s.commandLoop(conn, logger)

	logger.Info("client disconnected",
		slog.Int64("commands", conn.Trace.CommandCount),
		slog.Int64("transactions", conn.Trace.TransactionCount),
	)
}

// commandLoop processes commands from the client.
func (s *Server) commandLoop(conn *Connection, logger *slog.Logger) {
	reader := bufio.NewReader(conn.reader)

	for {
		// Check for shutdown
		select {
		case <-conn.Context().Done():
			return
		default:
		}

		// Set read deadline
		if err := conn.conn.SetReadDeadline(time.Now().Add(s.config.ReadTimeout)); err != nil {
			return
		}

		// Read command line
		line, err := s.readLine(reader)
		if err != nil {
			if err == io.EOF || errors.Is(err, net.ErrClosed) {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.writeResponse(conn, Response{
					Code:    CodeServiceUnavailable,
					Message: "Timeout waiting for command",
				})
				return
			}
			if errors.Is(err, ErrLineTooLong) {
				s.writeResponse(conn, Response{
					Code:    CodeSyntaxError,
					Message: "Line too long",
				})
				conn.RecordError(err)
				continue
			}
			if errors.Is(err, ErrBadLineEnding) {
				s.writeResponse(conn, Response{
					Code:    CodeSyntaxError,
					Message: "Line must be terminated with CRLF",
				})
				conn.RecordError(err)
				continue
			}
			logger.Error("read error", slog.Any("error", err))
			return
		}

		conn.UpdateActivity()

		// Check command limit
		if conn.Limits.MaxCommands > 0 && conn.Trace.CommandCount > conn.Limits.MaxCommands {
			s.writeResponse(conn, Response{
				Code:    CodeServiceUnavailable,
				Message: "Too many commands",
			})
			return
		}

		// Check error limit
		if conn.Limits.MaxErrors > 0 && conn.ErrorCount() >= conn.Limits.MaxErrors {
			s.writeResponse(conn, Response{
				Code:    CodeServiceUnavailable,
				Message: "Too many errors",
			})
			return
		}

		// Parse command
		cmd, args := parseCommand(line)
		logger.Debug("command received", slog.String("cmd", cmd), slog.String("args", args))

		// Handle command
		response := s.handleCommand(conn, cmd, args, reader, logger)
		if response != nil {
			s.writeResponse(conn, *response)
		}

		// Check if connection should close
		if conn.State() == StateQuit {
			return
		}
	}
}

// ErrBadLineEnding is returned when a line is not terminated by CRLF.
var ErrBadLineEnding = errors.New("smtp: line not terminated by CRLF")

// readLine reads a single SMTP line, enforcing strict CRLF and a maximum length.
// It returns the line without the trailing CRLF.
func (s *Server) readLine(reader *bufio.Reader) (string, error) {
	var total int

	for {
		chunk, err := reader.ReadSlice('\n') // returns data including '\n' or ErrBufferFull
		total += len(chunk)

		// If the line length has exceeded the configured maximum, drain the rest of the line
		// (if any) and return ErrLineTooLong.
		if total > s.config.MaxLineLength {
			// If ReadSlice returned ErrBufferFull we still haven't hit '\n' yet,
			// so keep discarding until we find one.
			if err == bufio.ErrBufferFull {
				// discard until we see a '\n' or an actual error
				for err == bufio.ErrBufferFull {
					_, err = reader.ReadSlice('\n')
				}
				// If err != nil after this loop, we'll fall through and return ErrLineTooLong
			}
			return "", ErrLineTooLong
		}

		if err == nil {
			// chunk ends with '\n'. Enforce that it's preceded by '\r' (strict CRLF).
			// chunk length is at least 1 because it contains '\n'
			if len(chunk) < 2 || chunk[len(chunk)-2] != '\r' {
				return "", ErrBadLineEnding
			}
			// Return the line without the trailing CRLF.
			// Convert to string (this copies the data).
			return string(chunk[:len(chunk)-2]), nil
		}

		if err == bufio.ErrBufferFull {
			// We haven't seen '\n' yet; loop to read more. Continue accumulating length.
			continue
		}

		// Any other error (including EOF) should be returned as is.
		return "", err
	}
}

// parseCommand splits a command line into verb and arguments.
func parseCommand(line string) (cmd, args string) {
	line = strings.TrimSpace(line)
	idx := strings.IndexByte(line, ' ')
	if idx == -1 {
		return strings.ToUpper(line), ""
	}
	return strings.ToUpper(line[:idx]), strings.TrimSpace(line[idx+1:])
}

// handleCommand processes a single SMTP command.
func (s *Server) handleCommand(conn *Connection, cmd, args string, reader *bufio.Reader, logger *slog.Logger) *Response {
	switch cmd {
	case "HELO":
		return s.handleHelo(conn, args)
	case "EHLO":
		return s.handleEhlo(conn, args)
	case "MAIL":
		return s.handleMail(conn, args)
	case "RCPT":
		return s.handleRcpt(conn, args)
	case "DATA":
		return s.handleData(conn, reader, logger)
	case "BDAT":
		return s.handleBDAT(conn, args, reader, logger)
	case "RSET":
		return s.handleRset(conn)
	case "VRFY":
		return s.handleVrfy(conn, args)
	case "EXPN":
		return s.handleExpn(conn, args)
	case "NOOP":
		return &Response{Code: CodeOK, Message: "OK"}
	case "QUIT":
		return s.handleQuit(conn)
	case "STARTTLS":
		return s.handleStartTLS(conn)
	case "AUTH":
		return s.handleAuth(conn, args, reader)
	default:
		// Unknown command callback
		if s.config.Callbacks != nil && s.config.Callbacks.OnUnknownCommand != nil {
			if resp := s.config.Callbacks.OnUnknownCommand(conn.Context(), conn, cmd, args); resp != nil {
				return resp
			}
		}
		conn.RecordError(fmt.Errorf("unknown command: %s", cmd))
		return &Response{Code: CodeCommandUnrecognized, Message: "Command not recognized"}
	}
}

// handleHelo processes the HELO command.
func (s *Server) handleHelo(conn *Connection, hostname string) *Response {
	if hostname == "" {
		return &Response{Code: CodeSyntaxError, Message: "Hostname required"}
	}

	// Callback
	if s.config.Callbacks != nil && s.config.Callbacks.OnHelo != nil {
		if err := s.config.Callbacks.OnHelo(conn.Context(), conn, hostname); err != nil {
			return &Response{Code: CodeMailboxNotFound, Message: err.Error()}
		}
	}

	conn.SetClientHostname(hostname)
	conn.SetState(StateGreeted)
	conn.ResetTransaction()

	ip, err := utils.GetIPFromAddr(conn.RemoteAddr())
	if err != nil {
		ip = net.IPv4zero
	}

	msg := fmt.Sprintf("%s Hello %s [%s]", s.config.Hostname, ip.String(), conn.Trace.ID)
	if conn.Trace.ReverseDNS != "" {
		msg = fmt.Sprintf("%s Hello %s (%s) [%s]", s.config.Hostname, ip.String(), conn.Trace.ReverseDNS, conn.Trace.ID)
	}
	return &Response{
		Code:    CodeOK,
		Message: msg,
	}
}

// handleEhlo processes the EHLO command.
func (s *Server) handleEhlo(conn *Connection, hostname string) *Response {
	if hostname == "" {
		return &Response{Code: CodeSyntaxError, Message: "Hostname required"}
	}

	// Build extension list
	extensions := make(map[Extension]string)

	if s.config.Enable8BitMIME {
		extensions[Ext8BitMIME] = ""
		conn.SetExtension(Ext8BitMIME, "")
	}
	if s.config.EnableSMTPUTF8 {
		extensions[ExtSMTPUTF8] = ""
		conn.SetExtension(ExtSMTPUTF8, "")
	}
	if s.config.TLSConfig != nil && !conn.IsTLS() {
		extensions[ExtSTARTTLS] = ""
		conn.SetExtension(ExtSTARTTLS, "")
	}
	if s.config.MaxMessageSize > 0 {
		extensions[ExtSize] = strconv.FormatInt(s.config.MaxMessageSize, 10)
		conn.SetExtension(ExtSize, strconv.FormatInt(s.config.MaxMessageSize, 10))
	}
	if s.config.EnableDSN {
		extensions[ExtDSN] = ""
		conn.SetExtension(ExtDSN, "")
	}
	if s.config.EnableChunking {
		extensions[ExtChunking] = ""
		conn.SetExtension(ExtChunking, "")
	}
	// Only advertise AUTH if TLS is not required, or if TLS is active
	if len(s.config.AuthMechanisms) > 0 && (!s.config.RequireTLS || conn.IsTLS()) {
		authParams := strings.Join(s.config.AuthMechanisms, " ")
		extensions[ExtAuth] = authParams
		conn.SetExtension(ExtAuth, authParams)
	}
	extensions[ExtEnhancedStatusCodes] = ""
	conn.SetExtension(ExtEnhancedStatusCodes, "")

	// Callback - may modify extensions
	if s.config.Callbacks != nil && s.config.Callbacks.OnEhlo != nil {
		extOverride, err := s.config.Callbacks.OnEhlo(conn.Context(), conn, hostname)
		if err != nil {
			return &Response{Code: CodeMailboxNotFound, Message: err.Error()}
		}
		if extOverride != nil {
			extensions = extOverride
		}
	}

	conn.SetClientHostname(hostname)
	conn.SetState(StateGreeted)
	conn.ResetTransaction()

	ip, err := utils.GetIPFromAddr(conn.RemoteAddr())
	if err != nil {
		ip = net.IPv4zero
	}

	// Build multiline response
	greeting := fmt.Sprintf("%s Hello %s [%s]", s.config.Hostname, ip.String(), conn.Trace.ID)
	if conn.Trace.ReverseDNS != "" {
		greeting = fmt.Sprintf("%s Hello %s (%s) [%s]", s.config.Hostname, ip.String(), conn.Trace.ReverseDNS, conn.Trace.ID)
	}
	lines := []string{greeting}
	for ext, params := range extensions {
		if params != "" {
			lines = append(lines, fmt.Sprintf("%s %s", ext, params))
		} else {
			lines = append(lines, string(ext))
		}
	}

	s.writeMultilineResponse(conn, CodeOK, lines)
	return nil
}

// handleMail processes the MAIL FROM command.
func (s *Server) handleMail(conn *Connection, args string) *Response {
	if conn.State() < StateGreeted {
		return &Response{Code: CodeBadSequence, Message: "Send EHLO/HELO first"}
	}
	if conn.State() >= StateMail {
		return &Response{Code: CodeBadSequence, Message: "MAIL command already given"}
	}

	// Check TLS requirement
	if s.config.RequireTLS && !conn.IsTLS() {
		return &Response{
			Code:         CodeTransactionFailed,
			EnhancedCode: "5.7.0",
			Message:      "TLS required",
		}
	}

	// Check auth requirement
	if s.config.RequireAuth && !conn.IsAuthenticated() {
		return &Response{
			Code:         CodeTransactionFailed,
			EnhancedCode: "5.7.0",
			Message:      "Authentication required",
		}
	}

	// Parse MAIL FROM:<address> [params]
	args = strings.TrimSpace(args)
	if !strings.HasPrefix(strings.ToUpper(args), "FROM:") {
		return &Response{Code: CodeSyntaxError, Message: "Syntax: MAIL FROM:<address>"}
	}
	args = strings.TrimSpace(args[5:])

	from, params, err := parsePathWithParams(args)
	if err != nil {
		return &Response{Code: CodeSyntaxError, Message: err.Error()}
	}

	// RFC 6531: If SMTPUTF8 parameter is not present, reject non-ASCII addresses
	if _, hasSMTPUTF8 := params["SMTPUTF8"]; !hasSMTPUTF8 {
		if ContainsNonASCII(from.Mailbox.LocalPart) || ContainsNonASCII(from.Mailbox.Domain) {
			return &Response{
				Code:         CodeMailboxNameInvalid,
				EnhancedCode: "5.6.7",
				Message:      "Address contains non-ASCII characters but SMTPUTF8 not requested",
			}
		}
	}

	// Check SIZE parameter
	if sizeStr, ok := params["SIZE"]; ok {
		size, err := strconv.ParseInt(sizeStr, 10, 64)
		if err != nil {
			return &Response{Code: CodeSyntaxError, Message: "Invalid SIZE parameter"}
		}
		if conn.Limits.MaxMessageSize > 0 && size > conn.Limits.MaxMessageSize {
			return &Response{
				Code:         CodeExceededStorage,
				EnhancedCode: "5.3.4",
				Message:      "Message too large",
			}
		}
	}

	// Callback
	if s.config.Callbacks != nil && s.config.Callbacks.OnMailFrom != nil {
		if err := s.config.Callbacks.OnMailFrom(conn.Context(), conn, from, params); err != nil {
			return &Response{Code: CodeMailboxNotFound, Message: err.Error()}
		}
	}

	// Start transaction
	mail := conn.BeginTransaction()
	mail.Envelope.From = from

	// Process parameters
	if bodyType, ok := params["BODY"]; ok {
		mail.Envelope.BodyType = BodyType(strings.ToUpper(bodyType))
	}
	if _, ok := params["SMTPUTF8"]; ok {
		mail.Envelope.SMTPUTF8 = true
	}
	if envID, ok := params["ENVID"]; ok {
		mail.Envelope.EnvID = envID
	}
	if ret, ok := params["RET"]; ok {
		mail.Envelope.DSNParams = &DSNEnvelopeParams{RET: strings.ToUpper(ret)}
	}
	if sizeStr, ok := params["SIZE"]; ok {
		mail.Envelope.Size, _ = strconv.ParseInt(sizeStr, 10, 64)
	}
	if conn.IsAuthenticated() {
		mail.Envelope.Auth = conn.Auth.Identity
	}
	mail.Envelope.ExtensionParams = params

	conn.SetState(StateMail)

	return &Response{
		Code:         CodeOK,
		EnhancedCode: "2.1.0",
		Message:      "OK",
	}
}

// handleRcpt processes the RCPT TO command.
func (s *Server) handleRcpt(conn *Connection, args string) *Response {
	if conn.State() < StateMail {
		return &Response{Code: CodeBadSequence, Message: "Send MAIL first"}
	}

	mail := conn.CurrentMail()
	if mail == nil {
		return &Response{Code: CodeBadSequence, Message: "No mail transaction"}
	}

	// Check recipient limit
	if conn.Limits.MaxRecipients > 0 && len(mail.Envelope.To) >= conn.Limits.MaxRecipients {
		return &Response{
			Code:         CodeInsufficientStorage,
			EnhancedCode: "5.5.3",
			Message:      "Too many recipients",
		}
	}

	// Parse RCPT TO:<address> [params]
	args = strings.TrimSpace(args)
	if !strings.HasPrefix(strings.ToUpper(args), "TO:") {
		return &Response{Code: CodeSyntaxError, Message: "Syntax: RCPT TO:<address>"}
	}
	args = strings.TrimSpace(args[3:])

	to, params, err := parsePathWithParams(args)
	if err != nil {
		return &Response{Code: CodeSyntaxError, Message: err.Error()}
	}

	// RFC 6531: If SMTPUTF8 was not requested in MAIL FROM, reject non-ASCII addresses
	if !mail.Envelope.SMTPUTF8 {
		if ContainsNonASCII(to.Mailbox.LocalPart) || ContainsNonASCII(to.Mailbox.Domain) {
			return &Response{
				Code:         CodeMailboxNameInvalid,
				EnhancedCode: "5.6.7",
				Message:      "Address contains non-ASCII characters but SMTPUTF8 not requested",
			}
		}
	}

	// Callback
	if s.config.Callbacks != nil && s.config.Callbacks.OnRcptTo != nil {
		if err := s.config.Callbacks.OnRcptTo(conn.Context(), conn, to, params); err != nil {
			return &Response{Code: CodeMailboxNotFound, Message: err.Error()}
		}
	}

	// Add recipient
	rcpt := Recipient{Address: to}
	if notify, ok := params["NOTIFY"]; ok {
		rcpt.DSNParams = &DSNRecipientParams{
			Notify: strings.Split(notify, ","),
		}
	}
	if orcpt, ok := params["ORCPT"]; ok {
		if rcpt.DSNParams == nil {
			rcpt.DSNParams = &DSNRecipientParams{}
		}
		rcpt.DSNParams.ORcpt = orcpt
	}

	mail.Envelope.To = append(mail.Envelope.To, rcpt)
	conn.SetState(StateRcpt)

	return &Response{
		Code:         CodeOK,
		EnhancedCode: "2.1.5",
		Message:      "OK",
	}
}

// handleData processes the DATA command.
func (s *Server) handleData(conn *Connection, reader *bufio.Reader, logger *slog.Logger) *Response {
	if conn.State() < StateRcpt {
		return &Response{Code: CodeBadSequence, Message: "Send RCPT first"}
	}

	mail := conn.CurrentMail()
	if mail == nil || len(mail.Envelope.To) == 0 {
		return &Response{Code: CodeBadSequence, Message: "No recipients"}
	}

	// Callback
	if s.config.Callbacks != nil && s.config.Callbacks.OnData != nil {
		if err := s.config.Callbacks.OnData(conn.Context(), conn); err != nil {
			return &Response{Code: CodeTransactionFailed, Message: err.Error()}
		}
	}

	conn.SetState(StateData)

	// Send intermediate response
	s.writeResponse(conn, Response{
		Code:    CodeStartMailInput,
		Message: "Start mail input; end with <CRLF>.<CRLF>",
	})

	// Set data timeout
	if err := conn.conn.SetReadDeadline(time.Now().Add(s.config.DataTimeout)); err != nil {
		return &Response{Code: CodeLocalError, Message: "Internal error"}
	}

	// Read message data
	data, err := s.readDataContent(reader, conn.Limits.MaxMessageSize)
	if err != nil {
		if errors.Is(err, ErrMessageTooLarge) {
			conn.ResetTransaction()
			return &Response{
				Code:         CodeExceededStorage,
				EnhancedCode: "5.3.4",
				Message:      "Message too large",
			}
		}
		if errors.Is(err, ErrBadLineEnding) {
			conn.ResetTransaction()
			return &Response{
				Code:         CodeSyntaxError,
				EnhancedCode: "5.6.0",
				Message:      "Message must use CRLF line endings",
			}
		}
		logger.Error("data read error", slog.Any("error", err))
		conn.ResetTransaction()
		return &Response{Code: CodeLocalError, Message: "Error reading message"}
	}

	mail.Content.Body = data
	mail.Raw = data
	mail.ID = generateConnectionID()

	// Add Received header
	receivedHeader := conn.GenerateReceivedHeader("")
	mail.Trace = append([]TraceField{receivedHeader}, mail.Trace...)

	// OnMessage callback
	if s.config.Callbacks != nil && s.config.Callbacks.OnMessage != nil {
		if err := s.config.Callbacks.OnMessage(conn.Context(), conn, mail); err != nil {
			conn.ResetTransaction()
			return &Response{Code: CodeTransactionFailed, Message: err.Error()}
		}
	}

	// Complete transaction
	conn.CompleteTransaction()

	logger.Info("message received",
		slog.String("mail_id", mail.ID),
		slog.String("from", mail.Envelope.From.String()),
		slog.Int("recipients", len(mail.Envelope.To)),
		slog.Int("size", len(data)),
	)

	return &Response{
		Code:         CodeOK,
		EnhancedCode: "2.0.0",
		Message:      fmt.Sprintf("OK, queued as %s [%s]", mail.ID, conn.Trace.ID),
	}
}

// readDataContent reads the message content until <CRLF>.<CRLF>.
// Strictly requires CRLF line endings to prevent SMTP smuggling attacks.
func (s *Server) readDataContent(reader *bufio.Reader, maxSize int64) ([]byte, error) {
	var buf bytes.Buffer

	for {
		line, err := s.readLine(reader)
		if err != nil {
			return nil, err
		}

		// Check for end of data (line is ".", already stripped of CRLF)
		if line == "." {
			break
		}

		// Remove dot-stuffing (RFC 5321 Section 4.5.2)
		// Lines starting with "." have the leading dot removed
		if len(line) > 0 && line[0] == '.' {
			line = line[1:]
		}

		// Check size limit (account for CRLF that will be added back)
		lineWithCRLF := line + "\r\n"
		if maxSize > 0 && int64(buf.Len())+int64(len(lineWithCRLF)) > maxSize {
			return nil, ErrMessageTooLarge
		}

		buf.WriteString(lineWithCRLF)
	}

	return buf.Bytes(), nil
}

// handleBDAT processes the BDAT command (RFC 3030 CHUNKING extension).
// BDAT allows message data to be sent in chunks, with a size prefix for each chunk.
// Syntax: BDAT <size> [LAST]
func (s *Server) handleBDAT(conn *Connection, args string, reader *bufio.Reader, logger *slog.Logger) *Response {
	// Check if CHUNKING is enabled
	if !s.config.EnableChunking {
		return &Response{Code: CodeCommandNotImplemented, Message: "BDAT not available"}
	}

	// Must have recipients first (either from StateRcpt or ongoing BDAT)
	if conn.State() < StateRcpt && conn.State() != StateBDAT {
		return &Response{Code: CodeBadSequence, Message: "Send RCPT first"}
	}

	mail := conn.CurrentMail()
	if mail == nil || len(mail.Envelope.To) == 0 {
		return &Response{Code: CodeBadSequence, Message: "No recipients"}
	}

	// Parse BDAT arguments: <size> [LAST]
	args = strings.TrimSpace(args)
	if args == "" {
		return &Response{Code: CodeSyntaxError, Message: "Syntax: BDAT <size> [LAST]"}
	}

	parts := strings.Fields(args)
	if len(parts) < 1 || len(parts) > 2 {
		return &Response{Code: CodeSyntaxError, Message: "Syntax: BDAT <size> [LAST]"}
	}

	chunkSize, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || chunkSize < 0 {
		return &Response{Code: CodeSyntaxError, Message: "Invalid chunk size"}
	}

	isLast := false
	if len(parts) == 2 {
		if strings.ToUpper(parts[1]) != "LAST" {
			return &Response{Code: CodeSyntaxError, Message: "Syntax: BDAT <size> [LAST]"}
		}
		isLast = true
	}

	// Check if adding this chunk would exceed max message size
	currentSize := int64(len(mail.Raw))
	if conn.Limits.MaxMessageSize > 0 && currentSize+chunkSize > conn.Limits.MaxMessageSize {
		// Discard the chunk data to keep protocol in sync
		s.discardBDATChunk(reader, chunkSize)
		conn.ResetTransaction()
		return &Response{
			Code:         CodeExceededStorage,
			EnhancedCode: "5.3.4",
			Message:      "Message too large",
		}
	}

	// Callback before reading chunk
	if s.config.Callbacks != nil && s.config.Callbacks.OnBDAT != nil {
		if err := s.config.Callbacks.OnBDAT(conn.Context(), conn, chunkSize, isLast); err != nil {
			// Discard the chunk data to keep protocol in sync
			s.discardBDATChunk(reader, chunkSize)
			conn.ResetTransaction()
			return &Response{Code: CodeTransactionFailed, Message: err.Error()}
		}
	}

	conn.SetState(StateBDAT)

	// Set data timeout
	if err := conn.conn.SetReadDeadline(time.Now().Add(s.config.DataTimeout)); err != nil {
		return &Response{Code: CodeLocalError, Message: "Internal error"}
	}

	// Read the chunk data (binary, exact size)
	chunkData, err := s.readBDATChunk(reader, chunkSize)
	if err != nil {
		logger.Error("BDAT read error", slog.Any("error", err))
		conn.ResetTransaction()
		return &Response{Code: CodeLocalError, Message: "Error reading chunk data"}
	}

	// Append chunk to message
	mail.Raw = append(mail.Raw, chunkData...)

	// If this is the last chunk, complete the transaction
	if isLast {
		mail.Content.Body = mail.Raw
		mail.ID = generateConnectionID()

		// Add Received header
		receivedHeader := conn.GenerateReceivedHeader("")
		mail.Trace = append([]TraceField{receivedHeader}, mail.Trace...)

		// OnMessage callback
		if s.config.Callbacks != nil && s.config.Callbacks.OnMessage != nil {
			if err := s.config.Callbacks.OnMessage(conn.Context(), conn, mail); err != nil {
				conn.ResetTransaction()
				return &Response{Code: CodeTransactionFailed, Message: err.Error()}
			}
		}

		// Complete transaction
		conn.CompleteTransaction()

		logger.Info("message received via BDAT",
			slog.String("mail_id", mail.ID),
			slog.String("from", mail.Envelope.From.String()),
			slog.Int("recipients", len(mail.Envelope.To)),
			slog.Int("size", len(mail.Raw)),
		)

		return &Response{
			Code:         CodeOK,
			EnhancedCode: "2.0.0",
			Message:      fmt.Sprintf("OK, queued as %s [%s]", mail.ID, conn.Trace.ID),
		}
	}

	// Not the last chunk, acknowledge and wait for more
	return &Response{
		Code:         CodeOK,
		EnhancedCode: "2.0.0",
		Message:      fmt.Sprintf("OK, %d bytes received", chunkSize),
	}
}

// readBDATChunk reads exactly 'size' bytes of binary data for a BDAT chunk.
func (s *Server) readBDATChunk(reader *bufio.Reader, size int64) ([]byte, error) {
	data := make([]byte, size)
	_, err := io.ReadFull(reader, data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// discardBDATChunk discards 'size' bytes from the reader (used on error).
func (s *Server) discardBDATChunk(reader *bufio.Reader, size int64) {
	_, _ = io.CopyN(io.Discard, reader, size)
}

// handleRset processes the RSET command.
func (s *Server) handleRset(conn *Connection) *Response {
	// Callback
	if s.config.Callbacks != nil && s.config.Callbacks.OnReset != nil {
		s.config.Callbacks.OnReset(conn.Context(), conn)
	}

	conn.ResetTransaction()

	return &Response{
		Code:         CodeOK,
		EnhancedCode: "2.0.0",
		Message:      "OK",
	}
}

// handleVrfy processes the VRFY command.
func (s *Server) handleVrfy(conn *Connection, args string) *Response {
	if args == "" {
		return &Response{Code: CodeSyntaxError, Message: "Syntax: VRFY <address>"}
	}

	// Callback
	if s.config.Callbacks != nil && s.config.Callbacks.OnVerify != nil {
		addr, err := s.config.Callbacks.OnVerify(conn.Context(), conn, args)
		if err != nil {
			return &Response{Code: CodeMailboxNotFound, Message: err.Error()}
		}
		return &Response{
			Code:    CodeOK,
			Message: addr.String(),
		}
	}

	// Default: disabled for privacy
	return &Response{
		Code:    CodeMailboxNotFound,
		Message: "VRFY disabled",
	}
}

// handleExpn processes the EXPN command.
func (s *Server) handleExpn(conn *Connection, args string) *Response {
	if args == "" {
		return &Response{Code: CodeSyntaxError, Message: "Syntax: EXPN <list>"}
	}

	// Callback
	if s.config.Callbacks != nil && s.config.Callbacks.OnExpand != nil {
		addrs, err := s.config.Callbacks.OnExpand(conn.Context(), conn, args)
		if err != nil {
			return &Response{Code: CodeMailboxNotFound, Message: err.Error()}
		}
		lines := make([]string, len(addrs))
		for i, addr := range addrs {
			lines[i] = addr.String()
		}
		s.writeMultilineResponse(conn, CodeOK, lines)
		return nil
	}

	// Default: disabled for privacy
	return &Response{
		Code:    CodeMailboxNotFound,
		Message: "EXPN disabled",
	}
}

// handleQuit processes the QUIT command.
func (s *Server) handleQuit(conn *Connection) *Response {
	conn.SetState(StateQuit)
	return &Response{
		Code:    CodeServiceClosing,
		Message: fmt.Sprintf("%s Service closing transmission channel [%s]", s.config.Hostname, conn.Trace.ID),
	}
}

// handleStartTLS processes the STARTTLS command.
func (s *Server) handleStartTLS(conn *Connection) *Response {
	if conn.State() < StateGreeted {
		return &Response{Code: CodeBadSequence, Message: "Send EHLO first"}
	}
	if s.config.TLSConfig == nil {
		return &Response{Code: CodeCommandNotImplemented, Message: "STARTTLS not available"}
	}
	if conn.IsTLS() {
		return &Response{Code: CodeBadSequence, Message: "TLS already active"}
	}

	// Callback
	if s.config.Callbacks != nil && s.config.Callbacks.OnStartTLS != nil {
		if err := s.config.Callbacks.OnStartTLS(conn.Context(), conn); err != nil {
			return &Response{Code: CodeTransactionFailed, Message: err.Error()}
		}
	}

	// Send ready response
	s.writeResponse(conn, Response{
		Code:    CodeServiceReady,
		Message: "Ready to start TLS",
	})

	// Upgrade connection
	if err := conn.UpgradeToTLS(s.config.TLSConfig); err != nil {
		conn.RecordError(err)
		// Connection is likely broken at this point
		return nil
	}

	return nil
}

// handleAuth processes the AUTH command.
func (s *Server) handleAuth(conn *Connection, args string, reader *bufio.Reader) *Response {
	if conn.State() < StateGreeted {
		return &Response{Code: CodeBadSequence, Message: "Send EHLO first"}
	}
	if conn.IsAuthenticated() {
		return &Response{Code: CodeBadSequence, Message: "Already authenticated"}
	}
	if (s.config.RequireTLS) && !conn.IsTLS() {
		return &Response{
			Code:         530,
			EnhancedCode: "5.7.0",
			Message:      "Must issue a STARTTLS command first",
		}
	}

	parts := strings.SplitN(args, " ", 2)
	mechanism := strings.ToUpper(parts[0])

	// Check if mechanism is supported
	supported := slices.Contains(s.config.AuthMechanisms, mechanism)
	if !supported {
		return &Response{Code: CodeParameterNotImpl, Message: "Mechanism not supported"}
	}

	var identity, password string
	var err error

	switch mechanism {
	case "PLAIN":
		identity, password, err = s.handleAuthPlain(conn, parts, reader)
	case "LOGIN":
		identity, password, err = s.handleAuthLogin(conn, reader)
	default:
		return &Response{Code: CodeParameterNotImpl, Message: "Mechanism not implemented"}
	}

	if err != nil {
		conn.RecordError(err)
		return &Response{Code: CodeTransactionFailed, Message: "Authentication failed"}
	}

	// Callback for verification
	if s.config.Callbacks != nil && s.config.Callbacks.OnAuth != nil {
		if err := s.config.Callbacks.OnAuth(conn.Context(), conn, mechanism, identity, password); err != nil {
			conn.RecordError(err)
			return &Response{
				Code:         CodeTransactionFailed,
				EnhancedCode: "5.7.8",
				Message:      "Authentication credentials invalid",
			}
		}
	}

	// Set authenticated state
	conn.mu.Lock()
	conn.Auth = AuthInfo{
		Authenticated:   true,
		Mechanism:       mechanism,
		Identity:        identity,
		AuthenticatedAt: time.Now(),
	}
	conn.mu.Unlock()

	return &Response{
		Code:         CodeAuthSuccess,
		EnhancedCode: "2.7.0",
		Message:      "Authentication successful",
	}
}

// handleAuthPlain processes PLAIN authentication.
func (s *Server) handleAuthPlain(conn *Connection, parts []string, reader *bufio.Reader) (identity, password string, err error) {
	var encoded string

	if len(parts) > 1 && parts[1] != "" {
		// Initial response provided
		encoded = parts[1]
	} else {
		// Request credentials
		s.writeResponse(conn, Response{Code: 334, Message: ""})
		line, err := s.readLine(reader)
		if err != nil {
			return "", "", err
		}
		encoded = line
	}

	// Cancel
	if encoded == "*" {
		return "", "", errors.New("authentication cancelled")
	}

	// Decode base64
	decoded, err := decodeBase64(encoded)
	if err != nil {
		return "", "", err
	}

	// Format: authzid\0authcid\0password
	parts2 := bytes.Split(decoded, []byte{0})
	if len(parts2) != 3 {
		return "", "", errors.New("invalid PLAIN format")
	}

	// authzid is optional, authcid is identity
	identity = string(parts2[1])
	if identity == "" {
		identity = string(parts2[0])
	}
	password = string(parts2[2])

	return identity, password, nil
}

// handleAuthLogin processes LOGIN authentication.
func (s *Server) handleAuthLogin(conn *Connection, reader *bufio.Reader) (identity, password string, err error) {
	// Request username
	s.writeResponse(conn, Response{Code: 334, Message: "VXNlcm5hbWU6"}) // "Username:" base64

	line, err := s.readLine(reader)
	if err != nil {
		return "", "", err
	}
	if line == "*" {
		return "", "", errors.New("authentication cancelled")
	}

	userBytes, err := decodeBase64(line)
	if err != nil {
		return "", "", err
	}
	identity = string(userBytes)

	// Request password
	s.writeResponse(conn, Response{Code: 334, Message: "UGFzc3dvcmQ6"}) // "Password:" base64

	line, err = s.readLine(reader)
	if err != nil {
		return "", "", err
	}
	if line == "*" {
		return "", "", errors.New("authentication cancelled")
	}

	passBytes, err := decodeBase64(line)
	if err != nil {
		return "", "", err
	}
	password = string(passBytes)

	return identity, password, nil
}

// writeResponse sends a single response to the client.
func (s *Server) writeResponse(conn *Connection, resp Response) {
	if err := conn.conn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout)); err != nil {
		return
	}

	line := resp.String() + "\r\n"
	_, err := conn.writer.WriteString(line)
	if err != nil {
		conn.RecordError(err)
		return
	}
	_ = conn.writer.Flush()
}

// writeMultilineResponse sends a multiline response.
func (s *Server) writeMultilineResponse(conn *Connection, code SMTPCode, lines []string) {
	if err := conn.conn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout)); err != nil {
		return
	}

	for i, line := range lines {
		var formatted string
		if i < len(lines)-1 {
			formatted = fmt.Sprintf("%d-%s\r\n", code, line)
		} else {
			formatted = fmt.Sprintf("%d %s\r\n", code, line)
		}
		_, err := conn.writer.WriteString(formatted)
		if err != nil {
			conn.RecordError(err)
			return
		}
	}
	_ = conn.writer.Flush()
}

// parsePathWithParams parses an address path with optional parameters.
func parsePathWithParams(s string) (Path, map[string]string, error) {
	params := make(map[string]string)

	// Find the angle-bracketed address
	start := strings.IndexByte(s, '<')
	end := strings.IndexByte(s, '>')

	if start == -1 || end == -1 || end < start {
		return Path{}, nil, errors.New("missing angle brackets")
	}

	address := s[start+1 : end]
	paramStr := strings.TrimSpace(s[end+1:])

	// Parse address
	var path Path
	if address == "" {
		// Null path
		path = Path{}
	} else {
		addr, err := ParseAddress(address)
		if err != nil {
			return Path{}, nil, fmt.Errorf("invalid address: %w", err)
		}
		path = Path{Mailbox: addr}
	}

	// Parse parameters
	if paramStr != "" {
		for param := range strings.FieldsSeq(paramStr) {
			idx := strings.IndexByte(param, '=')
			if idx == -1 {
				params[strings.ToUpper(param)] = ""
			} else {
				params[strings.ToUpper(param[:idx])] = param[idx+1:]
			}
		}
	}

	return path, params, nil
}

// decodeBase64 decodes a base64 string.
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
