package raven

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	ravenio "github.com/synqronlabs/raven/io"
	"github.com/synqronlabs/raven/utils"
)

// SMTP Server Errors
var (
	ErrServerClosed     = errors.New("smtp: server closed")
	ErrTooManyRecipents = errors.New("smtp: too many recipients")
	ErrMessageTooLarge  = errors.New("smtp: message too large")
	Err8BitIn7BitMode   = errors.New("smtp: 8-bit data in 7BIT mode")
	ErrTimeout          = errors.New("smtp: timeout")
	ErrTLSRequired      = errors.New("smtp: TLS required")
	ErrAuthRequired     = errors.New("smtp: authentication required")
	ErrInvalidCommand   = errors.New("smtp: invalid command")
	ErrLoopDetected     = errors.New("smtp: mail loop detected (too many Received headers)")
)

// HandlerFunc is the function signature for SMTP handlers.
// Handlers return a *Response to send to the client.
// To pass control to the next handler, return c.Next().
// The final handler in the chain is guaranteed to return a response.
type HandlerFunc func(c *Context) *Response

// Context provides request-scoped values and methods for handlers.
type Context struct {
	// Connection is the current SMTP connection.
	Connection *Connection

	// Mail is the current mail transaction (available in OnMessage handlers).
	Mail *Mail

	// Request holds command-specific data for the current request.
	Request Request

	// Keys stores arbitrary key-value pairs for handler communication.
	Keys map[string]any

	// Server reference for accessing server configuration
	server *Server

	handlers []HandlerFunc
	index    int
}

// Request holds command-specific request data.
type Request struct {
	// Command is the SMTP command being processed.
	Command Command

	// Args contains the raw arguments string.
	Args string

	// From is the sender path (available in OnMailFrom).
	From *Path

	// To is the recipient path (available in OnRcptTo).
	To *Path

	// Params contains ESMTP parameters.
	Params map[string]string

	// Hostname is the client hostname (available in OnHelo/OnEhlo).
	Hostname string

	// Extensions is the map of extensions to advertise (available in OnEhlo).
	Extensions map[Extension]string
}

// Set stores a value in the context for later retrieval.
func (c *Context) Set(key string, value any) {
	if c.Keys == nil {
		c.Keys = make(map[string]any)
	}
	c.Keys[key] = value
}

// Get retrieves a value from the context.
func (c *Context) Get(key string) (any, bool) {
	if c.Keys == nil {
		return nil, false
	}
	val, ok := c.Keys[key]
	return val, ok
}

// MustGet retrieves a value or panics if not found.
func (c *Context) MustGet(key string) any {
	val, ok := c.Get(key)
	if !ok {
		panic("Key \"" + key + "\" does not exist in context")
	}
	return val
}

// GetString retrieves a string value from the context.
func (c *Context) GetString(key string) string {
	if val, ok := c.Get(key); ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

// Next executes the next handler in the chain and returns its response.
// If there are no more handlers, it returns nil.
func (c *Context) Next() *Response {
	c.index++
	if c.index < len(c.handlers) {
		return c.handlers[c.index](c)
	}
	return nil
}

// RemoteAddr returns the client's remote address as a string.
func (c *Context) RemoteAddr() string {
	return c.Connection.RemoteAddr().String()
}

// ClientHostname returns the hostname provided in HELO/EHLO.
func (c *Context) ClientHostname() string {
	c.Connection.mu.RLock()
	defer c.Connection.mu.RUnlock()
	return c.Connection.Trace.ClientHostname
}

// IsTLS returns whether the connection is using TLS.
func (c *Context) IsTLS() bool {
	return c.Connection.IsTLS()
}

// IsAuthenticated returns whether the client is authenticated.
func (c *Context) IsAuthenticated() bool {
	return c.Connection.IsAuthenticated()
}

// AuthIdentity returns the authenticated identity, or empty string if not authenticated.
func (c *Context) AuthIdentity() string {
	c.Connection.mu.RLock()
	defer c.Connection.mu.RUnlock()
	if c.Connection.Auth.Authenticated {
		return c.Connection.Auth.Identity
	}
	return ""
}

// ServerHostname returns the server's hostname.
func (c *Context) ServerHostname() string {
	return c.server.hostname
}

// OK returns a 250 OK response with a message.
func (c *Context) OK(message string) *Response {
	return &Response{Code: CodeOK, Message: message}
}

// OKf returns a 250 OK response with a formatted message.
func (c *Context) OKf(format string, args ...any) *Response {
	return &Response{Code: CodeOK, Message: fmt.Sprintf(format, args...)}
}

// Error returns an error response with the given code and message.
func (c *Context) Error(code SMTPCode, message string) *Response {
	return &Response{Code: code, Message: message}
}

// Errorf returns an error response with the given code and formatted message.
func (c *Context) Errorf(code SMTPCode, format string, args ...any) *Response {
	return &Response{Code: code, Message: fmt.Sprintf(format, args...)}
}

// TempError returns a 451 temporary error response.
func (c *Context) TempError(message string) *Response {
	return &Response{Code: CodeLocalError, EnhancedCode: string(ESCTempLocalError), Message: message}
}

// PermError returns a 550 permanent error response.
func (c *Context) PermError(message string) *Response {
	return &Response{Code: CodeMailboxNotFound, Message: message}
}

// Reject returns a 554 transaction failed response.
func (c *Context) Reject(message string) *Response {
	return &Response{Code: CodeTransactionFailed, EnhancedCode: string(ESCPermFailure), Message: message}
}

// ExtensionConfig holds configuration for an SMTP extension.
type ExtensionConfig struct {
	Name    Extension
	Enabled bool
	Params  map[string]any
}

type Command string

const (
	// SMTP command constants
	CmdHelo     Command = "HELO"
	CmdEhlo     Command = "EHLO"
	CmdMail     Command = "MAIL"
	CmdRcpt     Command = "RCPT"
	CmdData     Command = "DATA"
	CmdBdat     Command = "BDAT"
	CmdRset     Command = "RSET"
	CmdVrfy     Command = "VRFY"
	CmdExpn     Command = "EXPN"
	CmdHelp     Command = "HELP"
	CmdNoop     Command = "NOOP"
	CmdQuit     Command = "QUIT"
	CmdStartTLS Command = "STARTTLS"
	CmdAuth     Command = "AUTH"
)

// Server is an SMTP server with a handler-chain architecture similar to web frameworks.
// Use New() to create a server and configure it using the fluent builder methods.
//
// Handlers are functions that receive a Context and return a *Response.
// To pass control to the next handler, return c.Next().
// The server adds a default handler at the end of each chain that provides
// the standard SMTP behavior, so your handlers can focus on custom logic.
type Server struct {
	// Configuration
	hostname           string
	addr               string
	logger             *slog.Logger
	tlsConfig          *tls.Config
	requireTLS         bool
	readTimeout        time.Duration
	writeTimeout       time.Duration
	dataTimeout        time.Duration
	idleTimeout        time.Duration
	maxMessageSize     int64
	maxRecipients      int
	maxConnections     int
	maxCommands        int64
	maxErrors          int
	maxLineLength      int
	maxReceivedHeaders int
	gracefulShutdown   bool
	shutdownTimeout    time.Duration
	enableDSN          bool
	enableChunking     bool

	// Authentication
	authMechanisms  []string
	requireAuth     bool
	enableLoginAuth bool
	authHandler     func(c *Context, mechanism, identity, password string) *Response

	// Handlers - each is a chain ending with a default handler
	onConnect    []HandlerFunc
	onDisconnect []HandlerFunc
	onHelo       []HandlerFunc
	onEhlo       []HandlerFunc
	onMailFrom   []HandlerFunc
	onRcptTo     []HandlerFunc
	onData       []HandlerFunc
	onBdat       []HandlerFunc
	onMessage    []HandlerFunc
	onReset      []HandlerFunc
	onHelp       []HandlerFunc
	onVerify     []HandlerFunc
	onExpand     []HandlerFunc

	// Runtime state
	listener    net.Listener
	connMu      sync.Mutex
	connections map[*Connection]struct{}
	connCount   atomic.Int64
	ctx         context.Context
	cancel      context.CancelFunc
	shutdownWg  sync.WaitGroup
	closed      atomic.Bool
}

// New creates a new SMTP server with the given hostname.
// The hostname is used in the server greeting and various SMTP responses.
func New(hostname string) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		hostname:           hostname,
		addr:               ":25",
		readTimeout:        5 * time.Minute,
		writeTimeout:       5 * time.Minute,
		dataTimeout:        10 * time.Minute,
		idleTimeout:        5 * time.Minute,
		maxLineLength:      RecommendedLineLength,
		maxReceivedHeaders: 100,
		gracefulShutdown:   true,
		shutdownTimeout:    30 * time.Second,
		logger:             slog.Default(),
		connections:        make(map[*Connection]struct{}),
		ctx:                ctx,
		cancel:             cancel,
	}
}

// Addr sets the address to listen on (e.g., ":25", "0.0.0.0:587").
func (s *Server) Addr(addr string) *Server {
	s.addr = addr
	return s
}

// Logger sets the structured logger for the server.
func (s *Server) Logger(logger *slog.Logger) *Server {
	s.logger = logger
	return s
}

// TLS configures TLS for the server.
// This enables the STARTTLS extension.
func (s *Server) TLS(config *tls.Config) *Server {
	s.tlsConfig = config
	return s
}

// RequireTLS requires clients to use TLS before authentication.
func (s *Server) RequireTLS() *Server {
	s.requireTLS = true
	return s
}

// ReadTimeout sets the timeout for reading commands.
func (s *Server) ReadTimeout(d time.Duration) *Server {
	s.readTimeout = d
	return s
}

// WriteTimeout sets the timeout for writing responses.
func (s *Server) WriteTimeout(d time.Duration) *Server {
	s.writeTimeout = d
	return s
}

// DataTimeout sets the timeout for reading message data.
func (s *Server) DataTimeout(d time.Duration) *Server {
	s.dataTimeout = d
	return s
}

// IdleTimeout sets the maximum idle time before disconnect.
func (s *Server) IdleTimeout(d time.Duration) *Server {
	s.idleTimeout = d
	return s
}

// MaxMessageSize sets the maximum allowed message size in bytes.
// This enables the SIZE extension and advertises the limit.
func (s *Server) MaxMessageSize(size int64) *Server {
	s.maxMessageSize = size
	return s
}

// MaxRecipients sets the maximum recipients per message.
func (s *Server) MaxRecipients(n int) *Server {
	s.maxRecipients = n
	return s
}

// MaxConnections sets the maximum concurrent connections.
func (s *Server) MaxConnections(n int) *Server {
	s.maxConnections = n
	return s
}

// MaxCommands sets the maximum commands per connection.
func (s *Server) MaxCommands(n int64) *Server {
	s.maxCommands = n
	return s
}

// MaxErrors sets the maximum errors before disconnect.
func (s *Server) MaxErrors(n int) *Server {
	s.maxErrors = n
	return s
}

// MaxLineLength sets the maximum command line length.
func (s *Server) MaxLineLength(n int) *Server {
	s.maxLineLength = n
	return s
}

// MaxReceivedHeaders sets the maximum number of Received headers allowed
// before rejecting the message (loop detection).
// Recommended: at least 100. Default: 100 (0 = unlimited)
func (s *Server) MaxReceivedHeaders(n int) *Server {
	s.maxReceivedHeaders = n
	return s
}

// GracefulShutdown enables or disables automatic graceful shutdown on SIGINT/SIGTERM.
// When enabled (default), the server will automatically call Shutdown() when
// receiving interrupt signals, allowing active connections to complete.
// Disable this if you want to handle signals yourself.
func (s *Server) GracefulShutdown(enabled bool) *Server {
	s.gracefulShutdown = enabled
	return s
}

// ShutdownTimeout sets the timeout for graceful shutdown.
// After this duration, remaining connections will be forcefully closed.
// Default: 30 seconds.
func (s *Server) ShutdownTimeout(d time.Duration) *Server {
	s.shutdownTimeout = d
	return s
}

// Extension adds an opt-in SMTP extension.
// Use the extension helper functions like DSN(), Chunking(), etc.
func (s *Server) Extension(ext ExtensionConfig) *Server {
	switch ext.Name {
	case ExtDSN:
		s.enableDSN = true
	case ExtChunking:
		s.enableChunking = true
	}
	return s
}

// OnConnect adds handlers for new connections.
// Handlers are called in order. Return c.Next() to continue to the next handler.
// Return an error response to reject the connection.
func (s *Server) OnConnect(handlers ...HandlerFunc) *Server {
	s.onConnect = append(s.onConnect, handlers...)
	return s
}

// OnDisconnect adds handlers for disconnections.
// These are informational - responses are not sent.
func (s *Server) OnDisconnect(handlers ...HandlerFunc) *Server {
	s.onDisconnect = append(s.onDisconnect, handlers...)
	return s
}

// OnHelo adds handlers for HELO commands.
// c.Request.Hostname contains the client hostname.
func (s *Server) OnHelo(handlers ...HandlerFunc) *Server {
	s.onHelo = append(s.onHelo, handlers...)
	return s
}

// OnEhlo adds handlers for EHLO commands.
// c.Request.Hostname contains the client hostname.
// c.Request.Extensions can be modified to change advertised extensions.
func (s *Server) OnEhlo(handlers ...HandlerFunc) *Server {
	s.onEhlo = append(s.onEhlo, handlers...)
	return s
}

// OnMailFrom adds handlers for MAIL FROM commands.
// c.Request.From contains the sender path.
// c.Request.Params contains ESMTP parameters.
func (s *Server) OnMailFrom(handlers ...HandlerFunc) *Server {
	s.onMailFrom = append(s.onMailFrom, handlers...)
	return s
}

// OnRcptTo adds handlers for RCPT TO commands.
// c.Request.To contains the recipient path.
// c.Request.Params contains ESMTP parameters.
func (s *Server) OnRcptTo(handlers ...HandlerFunc) *Server {
	s.onRcptTo = append(s.onRcptTo, handlers...)
	return s
}

// OnData adds handlers for DATA commands.
// Called before message data is received.
func (s *Server) OnData(handlers ...HandlerFunc) *Server {
	s.onData = append(s.onData, handlers...)
	return s
}

// OnBdat adds handlers for BDAT commands (CHUNKING extension).
func (s *Server) OnBdat(handlers ...HandlerFunc) *Server {
	s.onBdat = append(s.onBdat, handlers...)
	return s
}

// OnMessage adds handlers for received messages.
// c.Mail contains the complete message.
// This is where you typically queue or process the message.
func (s *Server) OnMessage(handlers ...HandlerFunc) *Server {
	s.onMessage = append(s.onMessage, handlers...)
	return s
}

// OnReset adds handlers for RSET commands.
func (s *Server) OnReset(handlers ...HandlerFunc) *Server {
	s.onReset = append(s.onReset, handlers...)
	return s
}

// OnHelp adds handlers for HELP commands.
// c.Request.Args contains the help topic (may be empty).
func (s *Server) OnHelp(handlers ...HandlerFunc) *Server {
	s.onHelp = append(s.onHelp, handlers...)
	return s
}

// OnVerify adds handlers for VRFY commands.
// c.Request.Args contains the address to verify.
// Return c.OK(address) with the verified address, or an error response.
func (s *Server) OnVerify(handlers ...HandlerFunc) *Server {
	s.onVerify = append(s.onVerify, handlers...)
	return s
}

// OnExpand adds handlers for EXPN commands.
// c.Request.Args contains the list name to expand.
// Set c.Set("addresses", []string{...}) and return c.Next() for multiline response.
func (s *Server) OnExpand(handlers ...HandlerFunc) *Server {
	s.onExpand = append(s.onExpand, handlers...)
	return s
}

// Auth configures authentication for the server.
// The handler is called with the context, mechanism name, identity, and password.
// Return nil to accept, or an error response to reject.
func (s *Server) Auth(mechanisms []string, handler func(c *Context, mechanism, identity, password string) *Response) *Server {
	s.authMechanisms = mechanisms
	s.authHandler = handler
	return s
}

// RequireAuth requires authentication before sending mail.
// If no mechanisms are configured, this defaults to PLAIN only.
// Use EnableLoginAuth() to also enable the deprecated LOGIN mechanism.
func (s *Server) RequireAuth() *Server {
	if len(s.authMechanisms) == 0 {
		s.authMechanisms = []string{"PLAIN"}
	}
	s.requireAuth = true
	return s
}

// EnableLoginAuth enables the deprecated LOGIN authentication mechanism.
// LOGIN should only be used for compatibility with legacy clients that
// do not support PLAIN.
func (s *Server) EnableLoginAuth() *Server {
	if len(s.authMechanisms) == 0 {
		s.authMechanisms = []string{"PLAIN"}
	}
	s.enableLoginAuth = true
	return s
}

// ListenAndServe starts the SMTP server on the configured address.
func (s *Server) ListenAndServe() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("smtp: failed to listen: %w", err)
	}
	return s.Serve(listener)
}

// ListenAndServeTLS starts the SMTP server with implicit TLS.
func (s *Server) ListenAndServeTLS() error {
	if s.tlsConfig == nil {
		return errors.New("smtp: TLS config is required for TLS server")
	}
	listener, err := tls.Listen("tcp", s.addr, s.tlsConfig)
	if err != nil {
		return fmt.Errorf("smtp: failed to listen TLS: %w", err)
	}
	return s.Serve(listener)
}

// Serve accepts connections on the listener and handles them.
func (s *Server) Serve(listener net.Listener) error {
	s.listener = listener

	// Set up signal handling for graceful shutdown if enabled
	if s.gracefulShutdown {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			sig := <-sigChan
			s.logger.Info("received signal, shutting down", slog.String("signal", sig.String()))
			ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
			defer cancel()
			_ = s.Shutdown(ctx)
		}()
	}

	s.logger.Info("SMTP server started",
		slog.String("addr", listener.Addr().String()),
		slog.String("hostname", s.hostname),
	)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.closed.Load() {
				return ErrServerClosed
			}
			s.logger.Error("accept error", slog.Any("error", err))
			continue
		}

		if s.maxConnections > 0 && s.connCount.Load() >= int64(s.maxConnections) {
			s.logger.Warn("connection limit reached",
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

// Close immediately closes the server and all connections without sending shutdown responses.
// Use this for immediate termination. For graceful shutdown, use Shutdown() instead.
func (s *Server) Close() error {
	s.closed.Store(true)
	s.cancel()

	if s.listener != nil {
		_ = s.listener.Close()
	}

	s.connMu.Lock()
	for conn := range s.connections {
		_ = conn.Close()
	}
	s.connMu.Unlock()

	return nil
}

// sendShutdownResponse sends a 421 response to all connected clients and closes them.
func (s *Server) sendShutdownResponse() {
	s.connMu.Lock()
	defer s.connMu.Unlock()

	for conn := range s.connections {
		// Set a short write deadline to avoid blocking shutdown
		_ = conn.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		resp := ResponseServiceUnavailable(s.hostname, fmt.Sprintf("Service shutting down [%s]", conn.Trace.ID))
		line := resp.String() + "\r\n"
		_, _ = conn.writer.WriteString(line)
		_ = conn.writer.Flush()
		// Close the connection to unblock any pending reads
		_ = conn.conn.Close()
	}
}

// handleConnection processes a single client connection.
func (s *Server) handleConnection(netConn net.Conn) {
	defer s.shutdownWg.Done()

	limits := ConnectionLimits{
		MaxMessageSize: s.maxMessageSize,
		MaxRecipients:  s.maxRecipients,
		MaxCommands:    s.maxCommands,
		MaxErrors:      s.maxErrors,
		IdleTimeout:    s.idleTimeout,
		DataTimeout:    s.dataTimeout,
	}

	conn := NewConnection(s.ctx, netConn, s.hostname, limits, RecommendedLineLength+2) // +2 for CRLF
	conn.Trace.ID = utils.GenerateID()

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

		// Run disconnect handlers (no response needed)
		if len(s.onDisconnect) > 0 {
			ctx := s.newContext(conn, nil)
			s.runHandlers(ctx, s.onDisconnect, nil)
		}
	}()

	logger := s.logger.With(
		slog.String("conn_id", conn.Trace.ID),
		slog.String("remote", conn.RemoteAddr().String()),
	)

	logger.Info("client connected")

	// Run connect handlers
	connectHandlers := append(s.onConnect, s.defaultConnectHandler)
	ctx := s.newContext(conn, nil)
	resp := s.runHandlers(ctx, connectHandlers, nil)
	if resp != nil && resp.IsError() {
		logger.Warn("connection rejected", slog.Int("code", int(resp.Code)), slog.String("message", resp.Message))
		s.writeResponse(conn, *resp)
		return
	}

	// Send greeting
	greeting := ResponseServiceReady(s.hostname, fmt.Sprintf("ESMTP ready [%s]", conn.Trace.ID))
	s.writeResponse(conn, greeting)

	// Main command loop
	s.commandLoop(conn, logger)

	logger.Info("client disconnected",
		slog.Int64("commands", conn.Trace.CommandCount),
		slog.Int("errors", conn.ErrorCount()),
		slog.Int64("transactions", conn.Trace.TransactionCount),
	)
}

// newContext creates a new Context for handler execution.
func (s *Server) newContext(conn *Connection, mail *Mail) *Context {
	return &Context{
		Connection: conn,
		Mail:       mail,
		server:     s,
		index:      -1,
	}
}

// runHandlers executes the handler chain and returns the response.
// If defaultHandler is provided, it's appended to the chain.
func (s *Server) runHandlers(ctx *Context, handlers []HandlerFunc, defaultHandler HandlerFunc) *Response {
	if defaultHandler != nil {
		handlers = append(handlers, defaultHandler)
	}
	if len(handlers) == 0 {
		return nil
	}
	ctx.handlers = handlers
	ctx.index = -1
	return ctx.Next()
}

// defaultConnectHandler is the default handler for new connections (accepts all).
func (s *Server) defaultConnectHandler(c *Context) *Response {
	return c.OK("Connected")
}

// commandLoop processes commands from the client.
func (s *Server) commandLoop(conn *Connection, logger *slog.Logger) {
	for {
		select {
		case <-conn.Context().Done():
			return
		default:
		}

		// Use IdleTimeout for waiting between commands
		if err := conn.conn.SetReadDeadline(time.Now().Add(conn.Limits.IdleTimeout)); err != nil {
			return
		}

		line, err := ravenio.ReadLine(conn.reader, s.maxLineLength, false)
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
			if errors.Is(err, ravenio.ErrLineTooLong) {
				s.writeResponse(conn, Response{
					Code:    CodeSyntaxError,
					Message: fmt.Sprintf("Line exceeds maximum length of %d bytes", s.maxLineLength),
				})
				continue
			}
			if errors.Is(err, ravenio.ErrBadLineEnding) {
				s.writeResponse(conn, Response{
					Code:    CodeSyntaxError,
					Message: "Line must be terminated with CRLF (RFC 5321)",
				})
				continue
			}
			logger.Error("read error", slog.Any("error", err))
			return
		}

		conn.updateActivity()

		if conn.Limits.MaxCommands > 0 && conn.Trace.CommandCount > conn.Limits.MaxCommands {
			resp := ResponseServiceUnavailable(s.hostname, "Too many commands")
			s.writeResponse(conn, resp)
			return
		}

		if conn.Limits.MaxErrors > 0 && conn.ErrorCount() >= conn.Limits.MaxErrors {
			resp := ResponseServiceUnavailable(s.hostname, "Too many errors")
			s.writeResponse(conn, resp)
			return
		}

		cmd, args, err := parseCommand(line)
		if err != nil {
			resp := ResponseSyntaxError(fmt.Sprintf("Invalid command syntax: %s", line))
			s.writeResponse(conn, resp)
			continue
		}

		logger.Debug("command received", slog.String("cmd", string(cmd)), slog.String("args", args))

		response := s.handleCommand(conn, cmd, args, conn.reader, logger)
		if response != nil {
			s.writeResponse(conn, *response)
		}

		if conn.State() == StateQuit {
			return
		}
	}
}

func (s *Server) handleCommand(conn *Connection, cmd Command, args string, reader *bufio.Reader, logger *slog.Logger) *Response {
	switch cmd {
	case CmdHelo:
		return s.handleHelo(conn, args)
	case CmdEhlo:
		return s.handleEhlo(conn, args)
	case CmdMail:
		return s.handleMail(conn, args)
	case CmdRcpt:
		return s.handleRcpt(conn, args)
	case CmdData:
		return s.handleData(conn, reader, logger)
	case CmdBdat:
		return s.handleBDAT(conn, args, reader, logger)
	case CmdRset:
		return s.handleRset(conn)
	case CmdVrfy:
		return s.handleVrfy(conn, args)
	case CmdExpn:
		return s.handleExpn(conn, args)
	case CmdHelp:
		return s.handleHelp(conn, args)
	case CmdNoop:
		resp := ResponseOK("OK", "")
		return &resp
	case CmdQuit:
		return s.handleQuit(conn)
	case CmdStartTLS:
		return s.handleStartTLS(conn)
	case CmdAuth:
		return s.handleAuth(conn, args, reader)
	default:
		resp := ResponseCommandNotRecognized(string(cmd))
		return &resp
	}
}

// writeResponse sends a single response to the client.
// If the response is an error (4xx or 5xx), it is automatically recorded.
func (s *Server) writeResponse(conn *Connection, resp Response) {
	// Record error responses for session tracking
	if resp.IsError() {
		conn.recordError(resp.ToError())
	}

	if err := conn.conn.SetWriteDeadline(time.Now().Add(s.writeTimeout)); err != nil {
		return
	}

	line := resp.String() + "\r\n"
	_, err := conn.writer.WriteString(line)
	if err != nil {
		conn.recordError(err)
		return
	}
	_ = conn.writer.Flush()
}

// writeMultilineResponse sends a multiline response.
// If the response code is an error (4xx or 5xx), it is automatically recorded.
func (s *Server) writeMultilineResponse(conn *Connection, code SMTPCode, lines []string) {
	// Record error responses for session tracking
	if code >= 400 {
		msg := strings.Join(lines, "; ")
		conn.recordError(fmt.Errorf("SMTP %d: %s", code, msg))
	}

	if err := conn.conn.SetWriteDeadline(time.Now().Add(s.writeTimeout)); err != nil {
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
			conn.recordError(err)
			return
		}
	}
	_ = conn.writer.Flush()
}

// getEffectiveAuthMechanisms returns the list of auth mechanisms to advertise.
func (s *Server) getEffectiveAuthMechanisms() []string {
	if len(s.authMechanisms) == 0 {
		return nil
	}
	mechanisms := make([]string, 0, len(s.authMechanisms)+1)
	mechanisms = append(mechanisms, s.authMechanisms...)
	if s.enableLoginAuth {
		mechanisms = append(mechanisms, "LOGIN")
	}
	return mechanisms
}
