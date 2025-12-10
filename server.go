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
	"sync"
	"sync/atomic"
	"time"

	"github.com/synqronlabs/raven/dns"
	"github.com/synqronlabs/raven/utils"
)

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
