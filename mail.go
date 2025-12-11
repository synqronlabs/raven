package raven

import (
	"encoding/json"
	"net/mail"
	"strings"
	"time"

	ravenmime "github.com/synqronlabs/raven/mime"
	"github.com/synqronlabs/raven/utils"
)

// BodyType specifies the encoding type of the message body per RFC 6152.
type BodyType string

const (
	// BodyType7Bit indicates a 7-bit ASCII message body (RFC 5321 compliant).
	BodyType7Bit BodyType = "7BIT"
	// BodyType8BitMIME indicates an 8-bit MIME message body (RFC 6152).
	BodyType8BitMIME BodyType = "8BITMIME"
	// BodyTypeBinaryMIME indicates a binary MIME message body (RFC 3030).
	BodyTypeBinaryMIME BodyType = "BINARYMIME"
)

// MailboxAddress represents an email address as per RFC 5321 Section 4.1.2.
// It supports both ASCII addresses (RFC 5321) and internationalized addresses (RFC 6531).
type MailboxAddress struct {
	// LocalPart is the portion before the @ sign.
	// May contain UTF-8 characters if SMTPUTF8 extension is used.
	LocalPart string `json:"local_part"`

	// Domain is the portion after the @ sign.
	// May be an internationalized domain name (IDN) in U-label or A-label form.
	Domain string `json:"domain"`

	// DisplayName is an optional human-readable name associated with the address.
	DisplayName string `json:"display_name,omitempty"`
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
	Mailbox MailboxAddress `json:"mailbox"`

	// SourceRoutes contains optional source routing information (deprecated per RFC 5321).
	// Included for completeness but SHOULD NOT be used for new implementations.
	SourceRoutes []string `json:"source_routes,omitempty"`
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
	Address Path `json:"address"`

	// DSNParams contains Delivery Status Notification parameters per RFC 3461.
	DSNParams *DSNRecipientParams `json:"dsn_params,omitempty"`
}

// DSNRecipientParams contains per-recipient DSN parameters per RFC 3461.
type DSNRecipientParams struct {
	// Notify specifies when notifications should be sent.
	// Valid values: NEVER, SUCCESS, FAILURE, DELAY (can be combined except NEVER).
	Notify []string `json:"notify,omitempty"`

	// ORcpt is the original recipient address if different from the actual recipient.
	ORcpt string `json:"orcpt,omitempty"`
}

// Envelope represents the SMTP envelope as per RFC 5321 Section 2.3.1.
// The envelope is distinct from the message content and is transmitted
// via MAIL FROM and RCPT TO commands.
type Envelope struct {
	// From is the reverse-path (originator) specified in the MAIL FROM command.
	// Used for error/bounce notifications. May be null for bounce messages.
	From Path `json:"from"`

	// To is the list of recipients specified via RCPT TO commands.
	To []Recipient `json:"to"`

	// BodyType indicates the body encoding type (RFC 6152 8BITMIME extension).
	// If empty, defaults to 7BIT.
	BodyType BodyType `json:"body_type,omitempty"`

	// Size is the declared message size in octets (RFC 1870 SIZE extension).
	// Zero means no size was declared.
	Size int64 `json:"size,omitempty"`

	// SMTPUTF8 indicates whether the message requires SMTPUTF8 extension (RFC 6531).
	// This is set when the envelope or headers contain internationalized content.
	SMTPUTF8 bool `json:"smtputf8,omitempty"`

	// EnvID is the envelope identifier for DSN purposes (RFC 3461).
	EnvID string `json:"env_id,omitempty"`

	// DSNParams contains envelope-level DSN parameters.
	DSNParams *DSNEnvelopeParams `json:"dsn_params,omitempty"`

	// Auth contains authentication identity if SMTP AUTH was used.
	Auth string `json:"auth,omitempty"`

	// ExtensionParams holds additional MAIL FROM parameters from other extensions.
	// Keys are parameter names (uppercase), values are parameter values.
	ExtensionParams map[string]string `json:"extension_params,omitempty"`
}

// DSNEnvelopeParams contains envelope-level DSN parameters per RFC 3461.
type DSNEnvelopeParams struct {
	// RET specifies what to return in a DSN: FULL (entire message) or HDRS (headers only).
	RET string `json:"ret"`
}

// Header represents the message header section as per RFC 5322.
// Headers may contain internationalized content when SMTPUTF8 is used (RFC 6532).
type Header struct {
	// Name is the header field name (e.g., "From", "Subject").
	Name string `json:"name"`
	// Value is the header field value.
	Value string `json:"value"`
}

// Headers is a collection of message headers with helper methods.
type Headers []Header

// Get returns the first header value with the given name (case-insensitive).
func (h Headers) Get(name string) string {
	for _, hdr := range h {
		if strings.EqualFold(hdr.Name, name) {
			return hdr.Value
		}
	}
	return ""
}

// GetAll returns all header values with the given name (case-insensitive).
func (h Headers) GetAll(name string) []string {
	var values []string
	for _, hdr := range h {
		if strings.EqualFold(hdr.Name, name) {
			values = append(values, hdr.Value)
		}
	}
	return values
}

// Count returns the number of headers with the given name (case-insensitive).
func (h Headers) Count(name string) int {
	count := 0
	for _, hdr := range h {
		if strings.EqualFold(hdr.Name, name) {
			count++
		}
	}
	return count
}

// Content represents the message content (header section + body) as per RFC 5321 Section 2.3.1.
// This is what follows the DATA command.
type Content struct {
	// Headers contains all message header fields per RFC 5322.
	// Common headers include: From, To, Cc, Bcc, Subject, Date, Message-ID, etc.
	Headers Headers `json:"headers"`

	// Body is the raw message body (may be encoded).
	Body []byte `json:"body,omitempty"`

	// Encoding indicates how the body is encoded per RFC 2045.
	// Defaults to "7bit" if not specified.
	Encoding ravenmime.ContentTransferEncoding `json:"encoding"`

	// Charset is the primary character set of the message body.
	Charset string `json:"charset,omitempty"`

	// Raw contains the raw message data as received, if preserved.
	// This may be useful for exact re-transmission or archival.
	// Use FromRaw() to populate Headers and Body from raw data,
	// and ToRaw() to serialize back to raw format.
	Raw []byte `json:"raw,omitempty"`
}

// TraceField represents a Received or Return-Path header for message tracing (RFC 5321 Section 4.4).
type TraceField struct {
	// Type is either "Received" or "Return-Path".
	Type string `json:"type"`

	// FromDomain is the domain of the sending host (for Received headers).
	FromDomain string `json:"from_domain,omitempty"`

	// FromIP is the IP address of the sending host.
	FromIP string `json:"from_ip,omitempty"`

	// ByDomain is the domain of the receiving host.
	ByDomain string `json:"by_domain,omitempty"`

	// Via indicates the link type (e.g., "TCP").
	Via string `json:"via,omitempty"`

	// With indicates the protocol used (e.g., "SMTP", "ESMTP", "ESMTPS", "UTF8SMTP").
	With string `json:"with,omitempty"`

	// ID is the message identifier assigned by this host.
	ID string `json:"id,omitempty"`

	// For is the recipient address (for single-recipient messages).
	For string `json:"for,omitempty"`

	// Timestamp is when the message was received.
	Timestamp time.Time `json:"timestamp"`

	// TLS indicates if TLS was used for this hop.
	TLS bool `json:"tls,omitempty"`

	// Raw is the raw header value if parsing is incomplete.
	Raw string `json:"raw,omitempty"`
}

// String formats the TraceField as an RFC 5321 compliant header value.
// For Received headers, it follows the format:
//
//	from <domain> (<ip>) by <domain> [via <link>] [with <protocol>] [id <id>] [for <recipient>]; <date-time>
//
// Per RFC 5321 Section 4.4, the date-time MUST use explicit offsets (e.g., -0800)
// rather than time zone names. FROM and BY clauses are required.
func (t TraceField) String() string {
	if t.Raw != "" {
		return t.Raw
	}

	if t.Type == "Return-Path" {
		return t.For
	}

	// Build RFC 5321 Section 4.4 compliant Received header value
	var parts []string

	// FROM clause (required) - RFC 5321 Section 4.4: Extended-Domain with TCP-info
	from := "from " + t.FromDomain
	if t.FromIP != "" {
		from += " (" + t.FromIP + ")"
	}
	parts = append(parts, from)

	// BY clause (required)
	if t.ByDomain != "" {
		parts = append(parts, "by "+t.ByDomain)
	}

	// VIA clause (optional)
	if t.Via != "" {
		parts = append(parts, "via "+t.Via)
	}

	// WITH clause (optional) - protocol
	if t.With != "" {
		parts = append(parts, "with "+t.With)
	}

	// ID clause (optional)
	if t.ID != "" {
		parts = append(parts, "id "+t.ID)
	}

	// FOR clause (optional) - should only appear for single-recipient messages
	if t.For != "" {
		parts = append(parts, "for <"+t.For+">")
	}

	// Date-time with explicit offset per RFC 5321 Section 4.4
	// Format: "Mon, 02 Jan 2006 15:04:05 -0700"
	timestamp := t.Timestamp.Format(time.RFC1123Z)

	return strings.Join(parts, " ") + "; " + timestamp
}

// Mail represents a complete mail object as per RFC 5321 Section 2.3.1.
// A mail object contains an envelope (transmitted via SMTP commands)
// and content (transmitted via the DATA command).
type Mail struct {
	// Envelope contains the SMTP envelope (MAIL FROM/RCPT TO information).
	// This is separate from the message headers and controls actual delivery.
	Envelope Envelope `json:"envelope"`

	// Content contains the message header section and body.
	// This is what appears after the DATA command.
	Content Content `json:"content"`

	// Trace contains the message trace information (Received/Return-Path headers).
	// Ordered from most recent (index 0) to oldest.
	Trace []TraceField `json:"trace,omitempty"`

	// ReceivedAt is when this server received the message.
	ReceivedAt time.Time `json:"received_at"`

	// ID is a unique identifier assigned to this message by the server.
	ID string `json:"id"`
}

// RequiresSMTPUTF8 determines if this mail requires the SMTPUTF8 extension.
// Returns true if any envelope address or header contains non-ASCII characters.
func (m *Mail) RequiresSMTPUTF8() bool {
	// Check explicit flag first
	if m.Envelope.SMTPUTF8 {
		return true
	}

	// Check envelope addresses
	if utils.ContainsNonASCII(m.Envelope.From.Mailbox.LocalPart) ||
		utils.ContainsNonASCII(m.Envelope.From.Mailbox.Domain) {
		return true
	}
	for _, rcpt := range m.Envelope.To {
		if utils.ContainsNonASCII(rcpt.Address.Mailbox.LocalPart) ||
			utils.ContainsNonASCII(rcpt.Address.Mailbox.Domain) {
			return true
		}
	}

	// Check headers for non-ASCII content
	for _, h := range m.Content.Headers {
		if utils.ContainsNonASCII(h.Value) {
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

// ToJSON serializes the Mail object to JSON bytes.
func (m *Mail) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// ToJSONIndent serializes the Mail object to pretty-printed JSON bytes.
func (m *Mail) ToJSONIndent() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

// FromJSON deserializes a Mail object from JSON bytes.
func FromJSON(data []byte) (*Mail, error) {
	var m Mail
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// ToMIME parses and returns the MIME structure of the message content.
// It validates Content-Type headers and parses multipart boundaries.
//
// For multipart messages, it recursively parses all parts and their boundaries.
// Returns the parsed Part structure or an error if the MIME structure is invalid.
func (c *Content) ToMIME() (*ravenmime.Part, error) {
	return ravenmime.Parse(c.Headers, c.Body)
}

// FromMIME populates the Content's Body from a MIME Part.
// For multipart messages, it serializes the entire MIME structure back to bytes.
// It also updates the Encoding and Charset fields based on the Part's properties.
// Encoding will default to "7bit" if the Part's encoding is empty.
func (c *Content) FromMIME(part *ravenmime.Part) error {
	if part.IsMultipart() {
		// For multipart, serialize the entire structure
		body, err := part.ToBytes()
		if err != nil {
			return err
		}
		c.Body = body
	} else {
		c.Body = part.Body
	}
	c.Encoding = part.ContentTransferEncoding
	if c.Encoding == "" {
		c.Encoding = ravenmime.Encoding7Bit
	}
	c.Charset = part.Charset
	return nil
}

// FromRaw parses raw message data and populates Headers, Body, and Raw fields.
// The raw data is stored for exact re-transmission or archival.
// This also sets the Encoding field based on Content-Transfer-Encoding header,
// defaulting to "7bit" per RFC 2045 if not specified.
func (c *Content) FromRaw(data []byte) {
	c.Raw = data

	// Parse headers and body from raw data
	c.Headers, c.Body = parseRawContent(data)

	// Set encoding from Content-Transfer-Encoding header, default to 7bit
	cte := c.Headers.Get("Content-Transfer-Encoding")
	if cte != "" {
		c.Encoding = ravenmime.ContentTransferEncoding(strings.ToLower(cte))
	} else {
		c.Encoding = ravenmime.Encoding7Bit
	}

	// Set charset from Content-Type header if present
	contentType := c.Headers.Get("Content-Type")
	if contentType != "" {
		// Simple charset extraction - look for charset parameter
		if idx := strings.Index(strings.ToLower(contentType), "charset="); idx != -1 {
			charset := contentType[idx+8:]
			// Handle quoted charset values
			if len(charset) > 0 && charset[0] == '"' {
				if endQuote := strings.Index(charset[1:], "\""); endQuote != -1 {
					c.Charset = charset[1 : endQuote+1]
				}
			} else {
				// Unquoted - extract until semicolon or end
				if semiIdx := strings.Index(charset, ";"); semiIdx != -1 {
					c.Charset = strings.TrimSpace(charset[:semiIdx])
				} else {
					c.Charset = strings.TrimSpace(charset)
				}
			}
		}
	}
}

// ToRaw serializes the Content back to raw RFC 5322 format.
// If Raw is already set (from FromRaw), it returns that.
// Otherwise, it reconstructs the message from Headers and Body.
func (c *Content) ToRaw() []byte {
	// If we have cached raw data, return it
	if len(c.Raw) > 0 {
		return c.Raw
	}

	// Estimate size: headers + blank line + body
	estimatedSize := len(c.Body) + 2 // +2 for CRLF before body
	for _, h := range c.Headers {
		estimatedSize += len(h.Name) + 2 + len(h.Value) + 2 // "Name: Value\r\n"
	}

	buf := make([]byte, 0, estimatedSize)

	// Write headers
	for _, h := range c.Headers {
		buf = append(buf, h.Name...)
		buf = append(buf, ':', ' ')
		buf = append(buf, h.Value...)
		buf = append(buf, '\r', '\n')
	}

	// Write blank line separating headers from body
	buf = append(buf, '\r', '\n')

	// Write body
	buf = append(buf, c.Body...)

	return buf
}

// parseRawContent parses raw message data into headers and body per RFC 5322.
// The header section is separated from the body by an empty line (CRLF CRLF).
func parseRawContent(data []byte) (Headers, []byte) {
	// Find the header/body separator (empty line)
	// Per RFC 5322, headers and body are separated by an empty line
	var headerEnd int
	dataLen := len(data)

	for i := 0; i < dataLen-3; i++ {
		// Look for CRLF CRLF (end of headers)
		if data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n' {
			headerEnd = i + 2 // Points to the second CRLF
			break
		}
	}

	// If no empty line found, treat entire data as body (malformed message)
	if headerEnd == 0 {
		return nil, data
	}

	// Parse headers directly from bytes to avoid string conversion of entire header section
	// Estimate header count (average ~50 bytes per header)
	estimatedHeaders := headerEnd / 50
	if estimatedHeaders < 8 {
		estimatedHeaders = 8
	}
	headers := make(Headers, 0, estimatedHeaders)

	var currentName, currentValue string
	lineStart := 0

	for i := 0; i < headerEnd; i++ {
		// Find end of line (CRLF)
		if data[i] == '\r' && i+1 < headerEnd && data[i+1] == '\n' {
			line := string(data[lineStart:i])
			lineStart = i + 2
			i++ // Skip the \n

			if line == "" {
				continue
			}

			// Check for continuation line (starts with whitespace)
			if line[0] == ' ' || line[0] == '\t' {
				// Continuation of previous header (folded header per RFC 5322)
				if currentName != "" {
					currentValue += " " + strings.TrimSpace(line)
				}
				continue
			}

			// Save previous header if exists
			if currentName != "" {
				headers = append(headers, Header{Name: currentName, Value: currentValue})
			}

			// Parse new header using strings.Cut
			if name, value, found := strings.Cut(line, ":"); found {
				currentName = strings.TrimSpace(name)
				currentValue = strings.TrimSpace(value)
			} else {
				// Malformed header line, skip it
				currentName = ""
				currentValue = ""
			}
		}
	}

	// Don't forget the last header
	if currentName != "" {
		headers = append(headers, Header{Name: currentName, Value: currentValue})
	}

	// Body starts after the empty line (CRLF CRLF)
	var body []byte
	if headerEnd+2 < dataLen {
		body = data[headerEnd+2:]
	}

	return headers, body
}
