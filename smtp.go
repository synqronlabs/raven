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
	"context"
	"errors"
)

// Common SMTP errors.
var (
	ErrServerClosed     = errors.New("smtp: server closed")
	ErrLineTooLong      = errors.New("smtp: line too long")
	ErrTooManyRecipents = errors.New("smtp: too many recipients")
	ErrMessageTooLarge  = errors.New("smtp: message too large")
	Err8BitIn7BitMode   = errors.New("smtp: 8-bit data in 7BIT mode")
	ErrTimeout          = errors.New("smtp: timeout")
	ErrTLSRequired      = errors.New("smtp: TLS required")
	ErrAuthRequired     = errors.New("smtp: authentication required")
)

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
