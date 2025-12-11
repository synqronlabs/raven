package raven

import (
	"crypto/tls"
	"log/slog"
	"time"
)

// ServerConfig contains configuration options for the SMTP server.
//
// For a more developer-friendly API, consider using the builder pattern:
//
//	server, err := raven.New("mail.example.com").
//	    Addr(":587").
//	    TLS(tlsConfig).
//	    OnMessage(handleMessage).
//	    Build()
//
// # Extensions
//
// Raven categorizes SMTP extensions into two types:
//
// Intrinsic Extensions (always enabled):
//   - ENHANCEDSTATUSCODES (RFC 2034) - Enhanced error codes
//   - 8BITMIME (RFC 6152) - 8-bit MIME transport
//   - SMTPUTF8 (RFC 6531) - Internationalized email
//   - PIPELINING (RFC 2920) - Command pipelining
//
// Opt-in Extensions (must be explicitly enabled):
//   - STARTTLS (RFC 3207) - Enable by setting TLSConfig
//   - AUTH (RFC 4954) - Enable by setting AuthMechanisms
//   - SIZE (RFC 1870) - Enable by setting MaxMessageSize > 0
//   - DSN (RFC 3461) - Enable by setting EnableDSN = true
//   - CHUNKING (RFC 3030) - Enable by setting EnableChunking = true
type ServerConfig struct {
	// Hostname is the server's hostname used in greetings and Received headers.
	// Required.
	Hostname string

	// Addr is the address to listen on (e.g., ":25", "0.0.0.0:587").
	// Default: ":25"
	Addr string

	// ---- TLS Configuration (Opt-in: STARTTLS extension) ----

	// TLSConfig is the TLS configuration for STARTTLS and implicit TLS.
	// If nil, STARTTLS will not be offered.
	// Setting this enables the STARTTLS extension (RFC 3207).
	TLSConfig *tls.Config

	// RequireTLS requires clients to use TLS before authentication.
	// Only effective if TLSConfig is set.
	RequireTLS bool

	// ---- Authentication (Opt-in: AUTH extension) ----

	// AuthMechanisms is the list of supported AUTH mechanisms.
	// Set to nil or empty to disable authentication.
	// Common mechanisms: "PLAIN", "LOGIN"
	// Setting this enables the AUTH extension (RFC 4954).
	AuthMechanisms []string

	// RequireAuth requires clients to authenticate before sending mail.
	// Only effective if AuthMechanisms is set.
	RequireAuth bool

	// ---- Resource Limits ----

	// MaxMessageSize is the maximum message size in bytes (0 = unlimited).
	// Setting this > 0 enables the SIZE extension (RFC 1870).
	MaxMessageSize int64

	// MaxRecipients is the maximum recipients per message (0 = unlimited).
	MaxRecipients int

	// MaxConnections is the maximum concurrent connections (0 = unlimited).
	MaxConnections int

	// MaxCommands is the maximum commands per connection (0 = unlimited).
	MaxCommands int64

	// MaxErrors is the maximum errors before disconnect (0 = unlimited).
	MaxErrors int

	// ---- Timeouts ----

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

	// ---- Intrinsic Extensions (always enabled, no configuration needed) ----
	// These are fundamental modern SMTP capabilities that are always available:
	//   - ENHANCEDSTATUSCODES (RFC 2034) - Detailed error codes
	//   - 8BITMIME (RFC 6152) - 8-bit content support
	//   - SMTPUTF8 (RFC 6531) - Internationalized email
	//   - PIPELINING (RFC 2920) - Command pipelining
	//
	// These extensions cannot be disabled and require no configuration.

	// ---- Opt-in Extensions ----

	// EnableDSN enables DSN extension (RFC 3461).
	// Delivery Status Notifications allow senders to request
	// notification of delivery success, failure, or delay.
	// Default: false
	EnableDSN bool

	// EnableChunking enables CHUNKING/BDAT extension (RFC 3030).
	// This allows clients to send message data in chunks using BDAT command
	// instead of the traditional DATA command. Also enables BINARYMIME.
	// Default: false
	EnableChunking bool

	// MaxReceivedHeaders is the maximum number of Received headers allowed
	// before rejecting the message (loop detection per RFC 5321 Section 6.3).
	// RFC 5321 recommends a large threshold, normally at least 100.
	// Default: 100 (0 = unlimited)
	MaxReceivedHeaders int

	// ---- Logging ----

	// Logger is the structured logger for the server.
	// Default: slog.Default()
	Logger *slog.Logger

	// ---- Callbacks ----

	// Callbacks contains the event callbacks.
	// For a more fluent API, use the builder pattern with OnConnect(), OnMessage(), etc.
	Callbacks *Callbacks
}

// DefaultServerConfig returns a ServerConfig with sensible defaults.
// Intrinsic extensions (8BITMIME, SMTPUTF8, ENHANCEDSTATUSCODES, PIPELINING)
// are always enabled and require no configuration.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Addr:               ":25",
		ReadTimeout:        5 * time.Minute,
		WriteTimeout:       5 * time.Minute,
		DataTimeout:        10 * time.Minute,
		IdleTimeout:        5 * time.Minute,
		MaxLineLength:      512,
		MaxReceivedHeaders: 100, // RFC 5321 Section 6.3 recommends at least 100
		// Opt-in extensions - disabled by default
		EnableDSN:      false,
		EnableChunking: false,
		// Auth disabled by default (set AuthMechanisms to enable)
		AuthMechanisms: nil,
		Logger:         slog.Default(),
	}
}

// SubmissionConfig returns a ServerConfig suitable for mail submission (port 587).
// This enables authentication and recommends TLS.
func SubmissionConfig() ServerConfig {
	config := DefaultServerConfig()
	config.Addr = ":587"
	config.AuthMechanisms = []string{"PLAIN", "LOGIN"}
	config.RequireAuth = true
	config.RequireTLS = true
	return config
}
