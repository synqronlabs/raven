package raven

import (
	"crypto/tls"
	"log/slog"
	"time"
)

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
