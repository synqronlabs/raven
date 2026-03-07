package server

import (
	"fmt"
)

// BodyType specifies the encoding type of the message body (RFC 6152).
type BodyType string

const (
	Body7Bit       BodyType = "7BIT"
	Body8BitMIME   BodyType = "8BITMIME"
	BodyBinaryMIME BodyType = "BINARYMIME"
)

// DSNReturn specifies what to include in DSN failure reports.
type DSNReturn string

const (
	DSNReturnFull    DSNReturn = "FULL" // Return full message
	DSNReturnHeaders DSNReturn = "HDRS" // Return headers only
)

// DSNNotify specifies when to send delivery status notifications.
type DSNNotify string

const (
	DSNNotifyNever   DSNNotify = "NEVER"
	DSNNotifySuccess DSNNotify = "SUCCESS"
	DSNNotifyFailure DSNNotify = "FAILURE"
	DSNNotifyDelay   DSNNotify = "DELAY"
)

// MailOptions contains parameters for the MAIL FROM command.
type MailOptions struct {
	// Body specifies the body type: 7BIT, 8BITMIME, or BINARYMIME.
	Body BodyType

	// Size is the declared message size in bytes (SIZE extension).
	// Zero means not specified.
	Size int64

	// RequireTLS indicates the message requires TLS for transmission (RFC 8689).
	RequireTLS bool

	// UTF8 indicates the message contains UTF-8 content (SMTPUTF8 extension).
	UTF8 bool

	// Return specifies what to return in DSN failure reports (DSN extension).
	Return DSNReturn

	// EnvelopeID is the envelope identifier for DSN (DSN extension).
	EnvelopeID string

	// Auth is the authenticated sender identity (AUTH= parameter, RFC 4954).
	// nil means AUTH not specified, empty string means AUTH=<>.
	Auth *string
}

// RcptOptions contains parameters for the RCPT TO command.
type RcptOptions struct {
	// Notify specifies when to send DSN (DSN extension).
	// Valid values: NEVER, SUCCESS, FAILURE, DELAY.
	Notify []DSNNotify

	// OriginalRecipient is the original recipient address (ORCPT parameter).
	OriginalRecipient string
}

// EnhancedCode represents an enhanced status code (RFC 3463).
// Format: class.subject.detail (e.g., 5.7.1).
type EnhancedCode [3]int

// String returns the enhanced code as a string.
func (c EnhancedCode) String() string {
	return fmt.Sprintf("%d.%d.%d", c[0], c[1], c[2])
}

// NoEnhancedCode indicates that no enhanced code should be included.
var NoEnhancedCode = EnhancedCode{-1, -1, -1}

// SMTPError represents an SMTP protocol error.
// Session methods can return this to send specific SMTP response codes.
type SMTPError struct {
	Code         int          // 3-digit SMTP code (e.g., 550)
	EnhancedCode EnhancedCode // Enhanced status code (e.g., 5.7.1)
	Message      string       // Human-readable message
}

// Error implements the error interface.
func (e *SMTPError) Error() string {
	if e.EnhancedCode != NoEnhancedCode {
		return fmt.Sprintf("SMTP %d %s: %s", e.Code, e.EnhancedCode.String(), e.Message)
	}
	return fmt.Sprintf("SMTP %d: %s", e.Code, e.Message)
}

// Temporary returns true if this is a transient error (4xx).
func (e *SMTPError) Temporary() bool {
	return e.Code >= 400 && e.Code < 500
}

// Permanent returns true if this is a permanent error (5xx).
func (e *SMTPError) Permanent() bool {
	return e.Code >= 500 && e.Code < 600
}

// Common SMTP errors that can be returned by Session methods.
var (
	// ErrAuthRequired is returned when authentication is required.
	ErrAuthRequired = &SMTPError{
		Code:         530,
		EnhancedCode: EnhancedCode{5, 7, 0},
		Message:      "Authentication required",
	}

	// ErrAuthFailed is returned when authentication fails.
	ErrAuthFailed = &SMTPError{
		Code:         535,
		EnhancedCode: EnhancedCode{5, 7, 8},
		Message:      "Authentication credentials invalid",
	}

	// ErrAuthUnsupported is returned when AUTH is not supported.
	ErrAuthUnsupported = &SMTPError{
		Code:         502,
		EnhancedCode: EnhancedCode{5, 5, 1},
		Message:      "Authentication not supported",
	}

	// ErrTLSRequired is returned when TLS is required but not active.
	ErrTLSRequired = &SMTPError{
		Code:         530,
		EnhancedCode: EnhancedCode{5, 7, 0},
		Message:      "Must issue STARTTLS first",
	}

	// ErrMailboxNotFound is returned when the recipient doesn't exist.
	ErrMailboxNotFound = &SMTPError{
		Code:         550,
		EnhancedCode: EnhancedCode{5, 1, 1},
		Message:      "Mailbox not found",
	}

	// ErrMailboxUnavailable is returned when the mailbox is temporarily unavailable.
	ErrMailboxUnavailable = &SMTPError{
		Code:         450,
		EnhancedCode: EnhancedCode{4, 2, 1},
		Message:      "Mailbox temporarily unavailable",
	}

	// ErrTooManyRecipients is returned when recipient limit is exceeded.
	ErrTooManyRecipients = &SMTPError{
		Code:         452,
		EnhancedCode: EnhancedCode{4, 5, 3},
		Message:      "Too many recipients",
	}

	// ErrMessageTooLarge is returned when message size exceeds limit.
	ErrMessageTooLarge = &SMTPError{
		Code:         552,
		EnhancedCode: EnhancedCode{5, 3, 4},
		Message:      "Message size exceeds limit",
	}

	// ErrSenderDenied is returned when the sender is rejected.
	ErrSenderDenied = &SMTPError{
		Code:         550,
		EnhancedCode: EnhancedCode{5, 7, 1},
		Message:      "Sender denied",
	}

	// ErrRecipientDenied is returned when a recipient is rejected.
	ErrRecipientDenied = &SMTPError{
		Code:         550,
		EnhancedCode: EnhancedCode{5, 7, 1},
		Message:      "Recipient denied",
	}
)

// Internal protocol errors used by the connection handler.
var (
	errTimeout = &SMTPError{
		Code: 421, EnhancedCode: EnhancedCode{4, 4, 2},
		Message: "Timeout waiting for command",
	}
	errBadSequence = &SMTPError{
		Code: 503, EnhancedCode: EnhancedCode{5, 5, 1},
		Message: "Bad sequence of commands",
	}
	errAlreadyAuthenticated = &SMTPError{
		Code: 503, EnhancedCode: EnhancedCode{5, 5, 1},
		Message: "Already authenticated",
	}
	errHeloFirst = &SMTPError{
		Code: 503, EnhancedCode: EnhancedCode{5, 5, 1},
		Message: "EHLO/HELO first",
	}
	errNoRecipients = &SMTPError{
		Code: 503, EnhancedCode: EnhancedCode{5, 5, 1},
		Message: "No recipients",
	}
	errTLSNotAvailable = &SMTPError{
		Code: 502, EnhancedCode: EnhancedCode{5, 5, 1},
		Message: "TLS not available",
	}
	errTLSAlreadyActive = &SMTPError{
		Code: 503, EnhancedCode: EnhancedCode{5, 5, 1},
		Message: "TLS already active",
	}
	errCommandNotImplemented = &SMTPError{
		Code: 502, EnhancedCode: EnhancedCode{5, 5, 1},
		Message: "Command not implemented",
	}
	errUnrecognizedCommand = &SMTPError{
		Code: 500, EnhancedCode: EnhancedCode{5, 5, 1},
		Message: "Unrecognized command",
	}
	errEncryptionRequired = &SMTPError{
		Code: 538, EnhancedCode: EnhancedCode{5, 7, 11},
		Message: "Encryption required",
	}
	errHostnameRequired = &SMTPError{
		Code: 501, EnhancedCode: EnhancedCode{5, 5, 4},
		Message: "Hostname required",
	}
	errMailSyntax = &SMTPError{
		Code: 501, EnhancedCode: EnhancedCode{5, 5, 4},
		Message: "Syntax: MAIL FROM:<address> [parameters]",
	}
	errRcptSyntax = &SMTPError{
		Code: 501, EnhancedCode: EnhancedCode{5, 5, 4},
		Message: "Syntax: RCPT TO:<address> [parameters]",
	}
	errBdatSyntax = &SMTPError{
		Code: 501, EnhancedCode: EnhancedCode{5, 5, 4},
		Message: "Syntax: BDAT <size> [LAST]",
	}
	errInvalidBase64 = &SMTPError{
		Code: 501, EnhancedCode: EnhancedCode{5, 5, 2},
		Message: "Invalid base64",
	}
	errAuthCancelled = &SMTPError{
		Code: 501, EnhancedCode: EnhancedCode{5, 0, 0},
		Message: "Authentication cancelled",
	}
	errInvalidCharacters = &SMTPError{
		Code: 501, EnhancedCode: EnhancedCode{5, 5, 2},
		Message: "Invalid characters in response",
	}
	errInvalidChunkSize = &SMTPError{
		Code: 501, EnhancedCode: EnhancedCode{5, 5, 4},
		Message: "Invalid chunk size",
	}
	errChunkReadFailed = &SMTPError{
		Code: 451, EnhancedCode: EnhancedCode{4, 3, 0},
		Message: "Error reading chunk",
	}
	errChunkingNotSupported = &SMTPError{
		Code: 502, EnhancedCode: EnhancedCode{5, 5, 1},
		Message: "CHUNKING not supported",
	}
	errEmptyRecipient = &SMTPError{
		Code: 501, EnhancedCode: EnhancedCode{5, 1, 3},
		Message: "Invalid recipient address: empty path not allowed",
	}
	errTooManyHops = &SMTPError{
		Code: 554, EnhancedCode: EnhancedCode{5, 4, 6},
		Message: "Too many hops",
	}
	errMailingListNotFound = &SMTPError{
		Code: 550, EnhancedCode: EnhancedCode{5, 1, 2},
		Message: "Mailing list not found",
	}
)
