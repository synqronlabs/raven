package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ErrServerClosed is returned by Serve when the server is closed.
var ErrServerClosed = errors.New("smtp: server closed")

// Logger is the interface for server logging.
type Logger interface {
	Printf(format string, v ...any)
	Println(v ...any)
}

// ServerConfig contains configuration for the SMTP server.
type ServerConfig struct {
	// Domain is the server hostname used in greetings and responses.
	// Required.
	Domain string

	// Addr is the address to listen on (e.g., ":25", ":587").
	// Default: ":25"
	Addr string

	// TLSConfig enables STARTTLS if set.
	// For implicit TLS (port 465), use ListenAndServeTLS.
	TLSConfig *tls.Config

	// AllowInsecureAuth permits AUTH over unencrypted connections.
	// This is insecure and should only be used for testing.
	// Default: false
	AllowInsecureAuth bool

	// ReadTimeout is the timeout for reading a command.
	// Default: 5 minutes
	ReadTimeout time.Duration

	// WriteTimeout is the timeout for writing a response.
	// Default: 5 minutes
	WriteTimeout time.Duration

	// DataTimeout is the timeout for reading message data (DATA/BDAT).
	// Default: 10 minutes
	DataTimeout time.Duration

	// MaxMessageBytes is the maximum message size in bytes.
	// If zero, defaults to 25MB. Set to -1 for unlimited.
	MaxMessageBytes int64

	// MaxRecipients is the maximum number of recipients per message.
	// Default: 100
	MaxRecipients int

	// MaxLineLength is the maximum command line length.
	// Default: 2000 (per RFC 5321 section 4.5.3.1.6, doubled for safety)
	MaxLineLength int

	// EnableSMTPUTF8 advertises SMTPUTF8 extension (RFC 6531).
	// Default: true
	EnableSMTPUTF8 bool

	// EnableREQUIRETLS advertises REQUIRETLS extension (RFC 8689).
	// Only effective when TLSConfig is set.
	EnableREQUIRETLS bool

	// EnableBINARYMIME advertises BINARYMIME extension (RFC 3030).
	// Requires EnableCHUNKING.
	EnableBINARYMIME bool

	// EnableDSN advertises DSN extension (RFC 3461).
	EnableDSN bool

	// EnableCHUNKING advertises CHUNKING extension (RFC 3030).
	// Backend must implement ChunkingSession.
	EnableCHUNKING bool

	// MaxReceivedHeaders is the maximum number of Received headers allowed
	// before rejecting the message as a mail loop (RFC 5321 §6.3).
	// Default: 100
	MaxReceivedHeaders int

	// Debug writes protocol trace to this writer if set.
	Debug io.Writer

	// ErrorLog is used for logging server errors.
	// If nil, errors are discarded.
	ErrorLog Logger
}

// Server is an SMTP server.
type Server struct {
	config  ServerConfig
	backend Backend

	mu        sync.Mutex
	listeners []net.Listener
	conns     map[*Conn]struct{}
	connCount atomic.Int64

	done   chan struct{}
	closed atomic.Bool
}

// NewServer creates a new SMTP server with the given backend and configuration.
func NewServer(backend Backend, cfg ServerConfig) *Server {
	// Apply defaults
	if cfg.Addr == "" {
		cfg.Addr = ":25"
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 5 * time.Minute
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 5 * time.Minute
	}
	if cfg.DataTimeout == 0 {
		cfg.DataTimeout = 10 * time.Minute
	}
	if cfg.MaxMessageBytes == 0 {
		cfg.MaxMessageBytes = 25 * 1024 * 1024 // 25 MB
	}
	if cfg.MaxRecipients == 0 {
		cfg.MaxRecipients = 100
	}
	if cfg.MaxLineLength == 0 {
		cfg.MaxLineLength = 2000
	}
	if cfg.MaxReceivedHeaders == 0 {
		cfg.MaxReceivedHeaders = 100
	}

	return &Server{
		config:  cfg,
		backend: backend,
		conns:   make(map[*Conn]struct{}),
		done:    make(chan struct{}),
	}
}

// ListenAndServe listens on the configured address and serves SMTP connections.
// It blocks until the context is cancelled or an error occurs.
func (s *Server) ListenAndServe(ctx context.Context) error {
	addr := s.config.Addr
	if addr == "" {
		addr = ":25"
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}

	if err := s.Serve(ctx, l); err != nil {
		return fmt.Errorf("serving SMTP listener on %s: %w", addr, err)
	}
	return nil
}

// ListenAndServeTLS listens on the configured address with implicit TLS.
// This is typically used for port 465 (submissions).
func (s *Server) ListenAndServeTLS(ctx context.Context) error {
	if s.config.TLSConfig == nil {
		return errors.New("smtp: TLSConfig is required for TLS server")
	}

	addr := s.config.Addr
	if addr == "" {
		addr = ":465"
	}

	l, err := tls.Listen("tcp", addr, s.config.TLSConfig)
	if err != nil {
		return fmt.Errorf("listening with TLS on %s: %w", addr, err)
	}

	if err := s.Serve(ctx, l); err != nil {
		return fmt.Errorf("serving TLS SMTP listener on %s: %w", addr, err)
	}
	return nil
}

// Serve accepts connections on the listener and handles them.
// It blocks until the context is cancelled or an error occurs.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	s.mu.Lock()
	s.listeners = append(s.listeners, l)
	s.mu.Unlock()

	// Handle context cancellation
	go func() {
		select {
		case <-ctx.Done():
			if err := s.Shutdown(context.Background()); err != nil && !errors.Is(err, ErrServerClosed) {
				s.logf("shutdown after context cancellation: %v", err)
			}
		case <-s.done:
		}
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			if s.closed.Load() {
				return ErrServerClosed
			}
			// Temporary error handling
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return fmt.Errorf("accepting SMTP connection: %w", err)
		}

		go s.handleConn(ctx, conn)
	}
}

// Shutdown gracefully shuts down the server.
// It stops accepting new connections and waits for existing connections
// to complete until the context is cancelled.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.closed.Swap(true) {
		return ErrServerClosed
	}

	close(s.done)

	// Close all listeners
	s.mu.Lock()
	for _, l := range s.listeners {
		l.Close()
	}
	s.mu.Unlock()

	// Wait for connections to finish or context to cancel
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Force close remaining connections
			s.mu.Lock()
			for c := range s.conns {
				c.Close()
			}
			s.mu.Unlock()
			return fmt.Errorf("waiting for graceful SMTP shutdown: %w", ctx.Err())
		case <-ticker.C:
			if s.connCount.Load() == 0 {
				return nil
			}
		}
	}
}

// Close immediately closes the server and all connections.
func (s *Server) Close() error {
	return s.Shutdown(context.Background())
}

// handleConn handles a single connection.
func (s *Server) handleConn(ctx context.Context, netConn net.Conn) {
	// Track connection
	c := newConn(ctx, netConn, s)
	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()
	s.connCount.Add(1)

	defer func() {
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
		s.connCount.Add(-1)
		c.Close()
	}()

	// Serve the connection
	c.serve()
}

// logf logs a formatted message if ErrorLog is set.
func (s *Server) logf(format string, v ...any) {
	if s.config.ErrorLog != nil {
		s.config.ErrorLog.Printf(format, v...)
	}
}
