// Package server provides an idiomatic Go SMTP server implementation
// using the Backend/Session pattern.
package server

import (
	"io"

	"github.com/synqronlabs/raven/sasl"
)

// Backend is the interface for SMTP server backends.
// It acts as a factory that creates a new Session for each connection.
type Backend interface {
	// NewSession is called after a client connects and sends EHLO/HELO.
	// The Conn provides connection metadata (remote addr, TLS state, etc.)
	// Return an error to reject the connection.
	NewSession(c *Conn) (Session, error)
}

// BackendFunc is an adapter to allow the use of ordinary functions as Backends.
type BackendFunc func(c *Conn) (Session, error)

// NewSession implements Backend.
func (f BackendFunc) NewSession(c *Conn) (Session, error) {
	return f(c)
}

// Session handles SMTP commands for a single connection.
// The methods are called when the remote client issues the matching command.
type Session interface {
	// Mail is called for the MAIL FROM command. It sets the reverse path
	// (sender) for the current message transaction.
	Mail(from string, opts *MailOptions) error

	// Rcpt is called for the RCPT TO command. It adds a forward path
	// (recipient) to the current message transaction.
	// This method may be called multiple times for multiple recipients.
	Rcpt(to string, opts *RcptOptions) error

	// Data is called for the DATA command. The reader r contains the message
	// content and MUST be fully consumed before Data returns.
	// After Data returns successfully, the message should be queued for delivery.
	Data(r io.Reader) error

	// Reset is called for the RSET command or when a new MAIL command is
	// received (implicit reset). It discards the current message transaction.
	Reset()

	// Logout is called when the connection is closed. It should free any
	// resources associated with the session.
	Logout() error
}

// AuthSession is an optional interface that Sessions can implement
// to support SMTP authentication (RFC 4954).
// Use type assertion to check if a Session supports authentication:
//
//	if authSess, ok := sess.(AuthSession); ok {
//	    mechs := authSess.AuthMechanisms()
//	    // ...
//	}
type AuthSession interface {
	Session

	// AuthMechanisms returns a list of supported SASL mechanisms.
	// Common mechanisms: "PLAIN", "LOGIN".
	// Return nil or empty slice to disable authentication.
	AuthMechanisms() []string

	// Auth is called when a client initiates authentication with AUTH command.
	// It should return a sasl.Server for the requested mechanism.
	// Return an error if the mechanism is not supported.
	Auth(mech string) (sasl.Server, error)
}

// ChunkingSession is an optional interface that Sessions can implement
// to support the CHUNKING extension (RFC 3030) for BDAT commands.
type ChunkingSession interface {
	Session

	// Chunk is called for each BDAT chunk.
	// The data contains the chunk bytes, and last indicates if this is
	// the final chunk (BDAT LAST).
	Chunk(data []byte, last bool) error
}

// VRFYSession is an optional interface that Sessions can implement
// to support the VRFY command (RFC 5321 §3.5.1).
// If not implemented, VRFY returns 502 "Command not implemented".
type VRFYSession interface {
	// Verify checks if an address is valid and returns a result string.
	// The result should be a mailbox name or "<user@domain>" per RFC 5321.
	Verify(address string) (string, error)
}

// EXPNSession is an optional interface that Sessions can implement
// to support the EXPN command (RFC 5321 §3.5.1).
// If not implemented, EXPN returns 502 "Command not implemented".
type EXPNSession interface {
	// Expand returns the members of a mailing list.
	// Each entry should be a mailbox name or "<user@domain>" per RFC 5321.
	Expand(list string) ([]string, error)
}
