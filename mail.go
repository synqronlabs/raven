package raven

import (
	"net/mail"
	"time"
)

// BodyType specifies the encoding type of the message body per RFC 6152.
type BodyType string

const (
	// BodyType7Bit indicates a 7-bit ASCII message body (RFC 5321 compliant).
	BodyType7Bit BodyType = "7BIT"
	// BodyType8BitMIME indicates an 8-bit MIME message body (RFC 6152).
	BodyType8BitMIME BodyType = "8BITMIME"
)

// MailboxAddress represents an email address as per RFC 5321 Section 4.1.2.
// It supports both ASCII addresses (RFC 5321) and internationalized addresses (RFC 6531).
type MailboxAddress struct {
	// LocalPart is the portion before the @ sign.
	// May contain UTF-8 characters if SMTPUTF8 extension is used.
	LocalPart string

	// Domain is the portion after the @ sign.
	// May be an internationalized domain name (IDN) in U-label or A-label form.
	Domain string

	// DisplayName is an optional human-readable name associated with the address.
	DisplayName string
}

// String returns the address in the standard "local-part@domain" format.
func (m MailboxAddress) String() string {
	if m.LocalPart == "" && m.Domain == "" {
		return ""
	}
	return m.LocalPart + "@" + m.Domain
}

// Path represents an SMTP forward-path or reverse-path as per RFC 5321 Section 4.1.2.
type Path struct {
	// Mailbox is the actual email address.
	Mailbox MailboxAddress

	// SourceRoutes contains optional source routing information (deprecated per RFC 5321).
	// Included for completeness but SHOULD NOT be used for new implementations.
	SourceRoutes []string
}

// IsNull returns true if this is a null reverse-path (empty sender).
// Null reverse-paths are used for bounce messages per RFC 5321 Section 4.5.5.
func (p Path) IsNull() bool {
	return p.Mailbox.LocalPart == "" && p.Mailbox.Domain == ""
}

// String returns the path in angle bracket format as used in SMTP commands.
func (p Path) String() string {
	if p.IsNull() {
		return "<>"
	}
	return "<" + p.Mailbox.String() + ">"
}

// Recipient represents a single recipient with delivery status information.
type Recipient struct {
	// Address is the recipient's email address (forward-path).
	Address Path

	// DSNParams contains Delivery Status Notification parameters per RFC 3461.
	DSNParams *DSNRecipientParams
}

// DSNRecipientParams contains per-recipient DSN parameters per RFC 3461.
type DSNRecipientParams struct {
	// Notify specifies when notifications should be sent.
	// Valid values: NEVER, SUCCESS, FAILURE, DELAY (can be combined except NEVER).
	Notify []string

	// ORcpt is the original recipient address if different from the actual recipient.
	ORcpt string
}

// Envelope represents the SMTP envelope as per RFC 5321 Section 2.3.1.
// The envelope is distinct from the message content and is transmitted
// via MAIL FROM and RCPT TO commands.
type Envelope struct {
	// From is the reverse-path (originator) specified in the MAIL FROM command.
	// Used for error/bounce notifications. May be null for bounce messages.
	From Path

	// To is the list of recipients specified via RCPT TO commands.
	To []Recipient

	// BodyType indicates the body encoding type (RFC 6152 8BITMIME extension).
	// If empty, defaults to 7BIT.
	BodyType BodyType

	// Size is the declared message size in octets (RFC 1870 SIZE extension).
	// Zero means no size was declared.
	Size int64

	// SMTPUTF8 indicates whether the message requires SMTPUTF8 extension (RFC 6531).
	// This is set when the envelope or headers contain internationalized content.
	SMTPUTF8 bool

	// EnvID is the envelope identifier for DSN purposes (RFC 3461).
	EnvID string

	// DSNParams contains envelope-level DSN parameters.
	DSNParams *DSNEnvelopeParams

	// Auth contains authentication identity if SMTP AUTH was used.
	Auth string

	// ExtensionParams holds additional MAIL FROM parameters from other extensions.
	// Keys are parameter names (uppercase), values are parameter values.
	ExtensionParams map[string]string
}

// DSNEnvelopeParams contains envelope-level DSN parameters per RFC 3461.
type DSNEnvelopeParams struct {
	// RET specifies what to return in a DSN: FULL (entire message) or HDRS (headers only).
	RET string
}

// ContentTransferEncoding represents the Content-Transfer-Encoding header value.
type ContentTransferEncoding string

const (
	// Encoding7Bit is for 7-bit ASCII data.
	Encoding7Bit ContentTransferEncoding = "7bit"
	// Encoding8Bit is for 8-bit data (requires 8BITMIME).
	Encoding8Bit ContentTransferEncoding = "8bit"
	// EncodingBinary is for binary data (requires BINARYMIME/CHUNKING).
	EncodingBinary ContentTransferEncoding = "binary"
	// EncodingQuotedPrintable is for quoted-printable encoding.
	EncodingQuotedPrintable ContentTransferEncoding = "quoted-printable"
	// EncodingBase64 is for base64 encoding.
	EncodingBase64 ContentTransferEncoding = "base64"
)

// Header represents the message header section as per RFC 5322.
// Headers may contain internationalized content when SMTPUTF8 is used (RFC 6532).
type Header struct {
	// Name is the header field name (e.g., "From", "Subject").
	Name string
	// Value is the header field value.
	Value string
}

// Headers is a collection of message headers with helper methods.
type Headers []Header

// Get returns the first header value with the given name (case-insensitive).
func (h Headers) Get(name string) string {
	for _, hdr := range h {
		if equalFold(hdr.Name, name) {
			return hdr.Value
		}
	}
	return ""
}

// GetAll returns all header values with the given name (case-insensitive).
func (h Headers) GetAll(name string) []string {
	var values []string
	for _, hdr := range h {
		if equalFold(hdr.Name, name) {
			values = append(values, hdr.Value)
		}
	}
	return values
}

// equalFold is a simple ASCII case-insensitive comparison.
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// MIMEPart represents a MIME body part for multipart messages (RFC 2045, RFC 2046).
type MIMEPart struct {
	// Headers contains the MIME headers for this part.
	Headers Headers

	// ContentType is the MIME content type (e.g., "text/plain", "image/png").
	ContentType string

	// ContentTransferEncoding specifies how the body is encoded.
	ContentTransferEncoding ContentTransferEncoding

	// Charset is the character set for text parts (e.g., "utf-8", "iso-8859-1").
	Charset string

	// Filename is the suggested filename for attachment parts.
	Filename string

	// ContentID is the Content-ID for inline parts (used in multipart/related).
	ContentID string

	// Body is the decoded content of this part.
	Body []byte

	// Parts contains nested parts for multipart content types.
	Parts []*MIMEPart
}

// Content represents the message content (header section + body) as per RFC 5321 Section 2.3.1.
// This is what follows the DATA command.
type Content struct {
	// Headers contains all message header fields per RFC 5322.
	// Common headers include: From, To, Cc, Bcc, Subject, Date, Message-ID, etc.
	Headers Headers

	// Body is the raw message body (may be encoded).
	Body []byte

	// MIME contains parsed MIME structure if the message is MIME-formatted.
	// Nil for simple non-MIME messages.
	MIME *MIMEPart

	// Encoding indicates how the body is encoded per RFC 2045.
	Encoding ContentTransferEncoding

	// Charset is the primary character set of the message body.
	Charset string
}

// TraceField represents a Received or Return-Path header for message tracing (RFC 5321 Section 4.4).
type TraceField struct {
	// Type is either "Received" or "Return-Path".
	Type string

	// FromDomain is the domain of the sending host (for Received headers).
	FromDomain string

	// FromIP is the IP address of the sending host.
	FromIP string

	// ByDomain is the domain of the receiving host.
	ByDomain string

	// Via indicates the link type (e.g., "TCP").
	Via string

	// With indicates the protocol used (e.g., "SMTP", "ESMTP", "ESMTPS", "UTF8SMTP").
	With string

	// ID is the message identifier assigned by this host.
	ID string

	// For is the recipient address (for single-recipient messages).
	For string

	// Timestamp is when the message was received.
	Timestamp time.Time

	// TLS indicates if TLS was used for this hop.
	TLS bool

	// Raw is the raw header value if parsing is incomplete.
	Raw string
}

// Mail represents a complete mail object as per RFC 5321 Section 2.3.1.
// A mail object contains an envelope (transmitted via SMTP commands)
// and content (transmitted via the DATA command).
type Mail struct {
	// Envelope contains the SMTP envelope (MAIL FROM/RCPT TO information).
	// This is separate from the message headers and controls actual delivery.
	Envelope Envelope

	// Content contains the message header section and body.
	// This is what appears after the DATA command.
	Content Content

	// Trace contains the message trace information (Received/Return-Path headers).
	// Ordered from most recent (index 0) to oldest.
	Trace []TraceField

	// ReceivedAt is when this server received the message.
	ReceivedAt time.Time

	// ID is a unique identifier assigned to this message by the server.
	ID string

	// Raw contains the raw message data as received, if preserved.
	// This may be useful for exact re-transmission or archival.
	Raw []byte
}

// RequiresSMTPUTF8 determines if this mail requires the SMTPUTF8 extension.
// Returns true if any envelope address or header contains non-ASCII characters.
func (m *Mail) RequiresSMTPUTF8() bool {
	// Check explicit flag first
	if m.Envelope.SMTPUTF8 {
		return true
	}

	// Check envelope addresses
	if ContainsNonASCII(m.Envelope.From.Mailbox.LocalPart) ||
		ContainsNonASCII(m.Envelope.From.Mailbox.Domain) {
		return true
	}
	for _, rcpt := range m.Envelope.To {
		if ContainsNonASCII(rcpt.Address.Mailbox.LocalPart) ||
			ContainsNonASCII(rcpt.Address.Mailbox.Domain) {
			return true
		}
	}

	// Check headers for non-ASCII content
	for _, h := range m.Content.Headers {
		if ContainsNonASCII(h.Value) {
			return true
		}
	}

	return false
}

// Requires8BitMIME determines if this mail requires the 8BITMIME extension.
// Returns true if the body contains 8-bit data.
func (m *Mail) Requires8BitMIME() bool {
	if m.Envelope.BodyType == BodyType8BitMIME {
		return true
	}
	for _, b := range m.Content.Body {
		if b > 127 {
			return true
		}
	}
	return false
}

// ContainsNonASCII checks if a string contains any non-ASCII characters.
func ContainsNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return true
		}
	}
	return false
}

// NewMail creates a new empty Mail object with initialized fields.
func NewMail() *Mail {
	return &Mail{
		Envelope: Envelope{
			To:              make([]Recipient, 0),
			ExtensionParams: make(map[string]string),
		},
		Content: Content{
			Headers: make(Headers, 0),
		},
		Trace: make([]TraceField, 0),
	}
}

// AddRecipient adds a recipient to the envelope.
func (m *Mail) AddRecipient(address MailboxAddress) {
	m.Envelope.To = append(m.Envelope.To, Recipient{
		Address: Path{Mailbox: address},
	})
}

// SetFrom sets the envelope sender (reverse-path).
func (m *Mail) SetFrom(address MailboxAddress) {
	m.Envelope.From = Path{Mailbox: address}
}

// SetNullSender sets a null reverse-path (for bounce messages).
func (m *Mail) SetNullSender() {
	m.Envelope.From = Path{}
}

// AddHeader adds a header to the message content.
func (m *Mail) AddHeader(name, value string) {
	m.Content.Headers = append(m.Content.Headers, Header{Name: name, Value: value})
}

// ParseAddress parses an email address string into a MailboxAddress.
// Supports both simple "user@domain" and RFC 5322 formatted addresses.
func ParseAddress(addr string) (MailboxAddress, error) {
	parsed, err := mail.ParseAddress(addr)
	if err != nil {
		return MailboxAddress{}, err
	}

	// Split the address part
	address := parsed.Address
	var local, domain string
	for i := len(address) - 1; i >= 0; i-- {
		if address[i] == '@' {
			local = address[:i]
			domain = address[i+1:]
			break
		}
	}

	return MailboxAddress{
		LocalPart:   local,
		Domain:      domain,
		DisplayName: parsed.Name,
	}, nil
}
