package raven

//go:generate msgp

import (
	"encoding/json"
	"errors"
	"net/mail"
	"strings"
	"time"

	ravenmime "github.com/synqronlabs/raven/mime"
	"github.com/synqronlabs/raven/utils"
)

// RFC 5322 line length limits.
const (
	MaxLineLength         = 998
	RecommendedLineLength = 78
)

// RFC 5322 validation errors.
var (
	ErrMissingDateHeader     = errors.New("rfc5322: missing required Date header")
	ErrMissingFromHeader     = errors.New("rfc5322: missing required From header")
	ErrMultipleFromNoSender  = errors.New("rfc5322: multiple From addresses require Sender header")
	ErrDuplicateSingleHeader = errors.New("rfc5322: header field appears more than once")
	ErrLineTooLong           = errors.New("rfc5322: line exceeds maximum length of 998 characters")
	ErrInvalidLineEnding     = errors.New("rfc5322: lines must be terminated with CRLF, not bare LF")
)

// BodyType specifies the encoding type of the message body (RFC 6152).
type BodyType string

const (
	BodyType7Bit       BodyType = "7BIT"
	BodyType8BitMIME   BodyType = "8BITMIME"
	BodyTypeBinaryMIME BodyType = "BINARYMIME"
)

// MailboxAddress represents an email address.
// Supports ASCII and internationalized addresses.
type MailboxAddress struct {
	LocalPart   string `json:"local_part"`
	Domain      string `json:"domain"`
	DisplayName string `json:"display_name,omitempty"`
}

// String returns the address in the standard "local-part@domain" format.
func (m MailboxAddress) String() string {
	if m.LocalPart == "" && m.Domain == "" {
		return ""
	}
	return m.LocalPart + "@" + m.Domain
}

// Path represents an SMTP forward-path or reverse-path.
type Path struct {
	Mailbox      MailboxAddress `json:"mailbox"`
	SourceRoutes []string       `json:"source_routes,omitempty"` // Deprecated
}

// IsNull returns true if this is a null reverse-path (used for bounce messages).
func (p Path) IsNull() bool {
	return p.Mailbox.LocalPart == "" && p.Mailbox.Domain == ""
}

// String returns the path in angle bracket format.
func (p Path) String() string {
	if p.IsNull() {
		return "<>"
	}
	return "<" + p.Mailbox.String() + ">"
}

// Recipient represents a single recipient with delivery status information.
type Recipient struct {
	Address Path `json:"address"`

	// DSNParams contains Delivery Status Notification parameters.
	DSNParams *DSNRecipientParams `json:"dsn_params,omitempty"`
}

// DSNRecipientParams contains per-recipient DSN parameters.
type DSNRecipientParams struct {
	Notify []string `json:"notify,omitempty"` // NEVER, SUCCESS, FAILURE, DELAY
	ORcpt  string   `json:"orcpt,omitempty"`  // Original recipient
}

// Envelope represents the SMTP envelope.
// The envelope is transmitted via MAIL FROM and RCPT TO commands.
type Envelope struct {
	From            Path               `json:"from"`
	To              []Recipient        `json:"to"`
	BodyType        BodyType           `json:"body_type,omitempty"`
	Size            int64              `json:"size,omitempty"`
	SMTPUTF8        bool               `json:"smtputf8,omitempty"`
	RequireTLS      bool               `json:"requiretls,omitempty"`
	EnvID           string             `json:"env_id,omitempty"`
	DSNParams       *DSNEnvelopeParams `json:"dsn_params,omitempty"`
	Auth            string             `json:"auth,omitempty"`
	ExtensionParams map[string]string  `json:"extension_params,omitempty"`

	// SPFResult contains the result of SPF verification performed during MAIL FROM.
	// This is nil if SPF checking was not performed.
	SPFResult *SPFCheckResult `json:"spf_result,omitempty"`
}

// DSNEnvelopeParams contains envelope-level DSN parameters.
type DSNEnvelopeParams struct {
	RET string `json:"ret"` // FULL or HDRS
}

// Header represents a message header field.
type Header struct {
	Name  string `json:"name"`
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

// singleOccurrenceHeaders lists headers that must appear at most once.
var singleOccurrenceHeaders = map[string]bool{
	"date":        true,
	"from":        true,
	"sender":      true,
	"reply-to":    true,
	"to":          true,
	"cc":          true,
	"bcc":         true,
	"message-id":  true,
	"in-reply-to": true,
	"references":  true,
	"subject":     true,
}

// Validate validates headers according to RFC 5322 requirements.
// It checks for required headers, single-occurrence constraints, and line length limits.
func (h Headers) Validate() error {
	if h.Count("Date") == 0 {
		return ErrMissingDateHeader
	}

	fromCount := h.Count("From")
	if fromCount == 0 {
		return ErrMissingFromHeader
	}

	for name := range singleOccurrenceHeaders {
		if h.Count(name) > 1 {
			return ErrDuplicateSingleHeader
		}
	}

	// If From contains multiple mailboxes, Sender MUST be present
	// This is a simplified check - a full implementation would parse the From header
	fromValue := h.Get("From")
	if strings.Contains(fromValue, ",") && h.Count("Sender") == 0 {
		return ErrMultipleFromNoSender
	}

	// Validate header line lengths per RFC 5322
	// Each header field line must not exceed 998 characters (excluding CRLF)
	// Also reject bare LF (must use CRLF)
	for _, hdr := range h {
		// Check for bare LF in header value (LF not preceded by CR)
		for i := 0; i < len(hdr.Value); i++ {
			if hdr.Value[i] == '\n' && (i == 0 || hdr.Value[i-1] != '\r') {
				return ErrInvalidLineEnding
			}
		}

		headerLine := hdr.Name + ": " + hdr.Value
		// Check each line in case value contains folded lines (CRLF followed by whitespace)
		lines := strings.SplitSeq(headerLine, "\r\n")
		for line := range lines {
			if len(line) > MaxLineLength {
				return ErrLineTooLong
			}
		}
	}

	return nil
}

// Content represents the message content (headers + body).
type Content struct {
	Headers  Headers                           `json:"headers"`
	Body     []byte                            `json:"body,omitempty"`
	Encoding ravenmime.ContentTransferEncoding `json:"encoding"`
	Charset  string                            `json:"charset,omitempty"`
}

// TraceField represents a Received or Return-Path header.
type TraceField struct {
	Type       string `json:"type"` // "Received" or "Return-Path"
	FromDomain string `json:"from_domain,omitempty"`
	FromIP     string `json:"from_ip,omitempty"`
	ByDomain   string `json:"by_domain,omitempty"`
	Via        string `json:"via,omitempty"` // e.g., "TCP"
	// With indicates the protocol used (e.g., "SMTP", "ESMTP", "ESMTPS", "ESMTPA").
	//   - "ESMTP": extended SMTP (EHLO)
	//   - "ESMTPS": ESMTP with TLS
	//   - "ESMTPA": ESMTP with AUTH
	//   - "ESMTPSA": ESMTP with TLS and AUTH
	// RFC 6531 adds:
	//   - "UTF8SMTP": SMTP with SMTPUTF8
	//   - "UTF8SMTPS": UTF8SMTP with TLS
	//   - "UTF8SMTPA": UTF8SMTP with AUTH
	//   - "UTF8SMTPSA": UTF8SMTP with TLS and AUTH
	With string `json:"with,omitempty"`

	// ID is the message identifier assigned by this host.
	ID string `json:"id,omitempty"`

	// For is the recipient address (for single-recipient messages).
	// Per RFC 5321, the FOR clause MUST contain exactly one path
	// when present, even if multiple RCPT TO commands were given.
	// For security, this should be omitted for multi-recipient messages.
	For string `json:"for,omitempty"`

	// Timestamp is when the message was received.
	Timestamp time.Time `json:"timestamp"`

	// TLS indicates if TLS was used for this hop.
	TLS bool `json:"tls,omitempty"`

	// Raw is the raw header value if parsing is incomplete.
	Raw string `json:"raw,omitempty"`
}

// For Received headers, the format is:
//
//	from <domain> (<ip>) by <domain> [via <link>] [with <protocol>] [id <id>] [for <recipient>]; <date-time>
//
// For Return-Path headers, the format is:
//
//	<reverse-path>
//
// Return-Path preserves the MAIL FROM address and
// is added when making final delivery.
func (t TraceField) String() string {
	if t.Raw != "" {
		return t.Raw
	}

	if t.Type == "Return-Path" {
		// Format: <reverse-path>
		// Empty path is valid for bounce messages
		if t.For == "" {
			return "<>"
		}
		return "<" + t.For + ">"
	}

	// Build Received header value
	var parts []string

	// FROM clause (required) - Extended-Domain with TCP-info
	// Format: "from domain (TCP-info)" where TCP-info is "address-literal" or "domain address-literal"
	from := "from " + t.FromDomain
	if t.FromIP != "" {
		from += " (" + t.FromIP + ")"
	}
	parts = append(parts, from)

	// BY clause (required)
	if t.ByDomain != "" {
		parts = append(parts, "by "+t.ByDomain)
	}

	// VIA clause (optional) - primarily for non-Internet transports
	if t.Via != "" {
		parts = append(parts, "via "+t.Via)
	}

	// WITH clause (optional) - protocol per RFC 5321 and RFC 3848
	if t.With != "" {
		parts = append(parts, "with "+t.With)
	}

	// ID clause (optional)
	if t.ID != "" {
		parts = append(parts, "id "+t.ID)
	}

	// FOR clause (optional) - per RFC 5321, MUST contain exactly one path
	// For security, should be omitted for multi-recipient messages
	if t.For != "" {
		parts = append(parts, "for <"+t.For+">")
	}

	// Date-time with explicit offset
	// Format: "Mon, 02 Jan 2006 15:04:05 -0700"
	// MUST NOT use obs- date forms, especially two-digit years
	timestamp := t.Timestamp.Format(time.RFC1123Z)

	return strings.Join(parts, " ") + "; " + timestamp
}

// NewReturnPathTrace creates a Return-Path trace field from the envelope's reverse-path.
// Return-Path is added when making final delivery
// to preserve the MAIL FROM address for bounce messages.
func NewReturnPathTrace(reversePath Path) TraceField {
	return TraceField{
		Type: "Return-Path",
		For:  reversePath.Mailbox.String(),
	}
}

// A mail object contains an envelope (transmitted via SMTP commands)
// and content (transmitted via the DATA command).
type Mail struct {
	// Envelope contains the SMTP envelope (MAIL FROM/RCPT TO information).
	Envelope Envelope `json:"envelope"`

	// Content contains the message header section and body.
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

// AddReturnPath adds a Return-Path header for final delivery.
// Per RFC 5321, the SMTP server making final delivery
// MUST insert a Return-Path line at the beginning of the mail data.
// This preserves the reverse-path from MAIL FROM for bounce messages.
//
// This method should be called by the application when making final
// delivery (i.e., when the message leaves the SMTP environment).
func (m *Mail) AddReturnPath() {
	returnPath := NewReturnPathTrace(m.Envelope.From)

	// Prepend to trace
	m.Trace = append([]TraceField{returnPath}, m.Trace...)

	// Prepend Return-Path header to content
	m.Content.Headers = append(Headers{{
		Name:  "Return-Path",
		Value: returnPath.String(),
	}}, m.Content.Headers...)
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

// ToMessagePack serializes the Mail object to MessagePack bytes.
func (m *Mail) ToMessagePack() ([]byte, error) {
	return m.MarshalMsg(nil)
}

// FromMessagePack deserializes a Mail object from MessagePack bytes.
func FromMessagePack(data []byte) (*Mail, error) {
	var m Mail
	_, err := m.UnmarshalMsg(data)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate validates the Content according to RFC 5322 requirements.
// It checks headers and body line lengths, and ensures CRLF line endings.
func (c *Content) Validate() error {
	if err := c.Headers.Validate(); err != nil {
		return err
	}

	// Validate body line lengths and line endings per RFC 5322
	if len(c.Body) > 0 {
		lineStart := 0
		for i := 0; i < len(c.Body); i++ {
			if c.Body[i] == '\n' {
				// Check for bare LF (LF not preceded by CR)
				if i == 0 || c.Body[i-1] != '\r' {
					return ErrInvalidLineEnding
				}
				// Line length excluding CRLF
				lineLen := i - lineStart - 1 // -1 for CR
				if lineLen > MaxLineLength {
					return ErrLineTooLong
				}
				lineStart = i + 1
			}
		}
		// Check final line (if no trailing CRLF)
		if lineStart < len(c.Body) {
			lineLen := len(c.Body) - lineStart
			if lineLen > MaxLineLength {
				return ErrLineTooLong
			}
		}
	}

	return nil
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

// FromRaw parses raw message data and populates Headers and Body fields.
// This also sets the Encoding field based on Content-Transfer-Encoding header,
// defaulting to "7bit" per RFC 2045 if not specified.
func (c *Content) FromRaw(data []byte) {
	c.Headers, c.Body = parseRawContent(data)

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
// It reconstructs the message from Headers and Body.
// Header lines are folded per RFC 5322 to comply with line length limits.
func (c *Content) ToRaw() []byte {
	// Estimate size: headers + blank line + body (with some extra for folding)
	estimatedSize := len(c.Body) + 2 // +2 for CRLF before body
	for _, h := range c.Headers {
		estimatedSize += len(h.Name) + 2 + len(h.Value) + 10 // Extra for potential folding
	}

	buf := make([]byte, 0, estimatedSize)

	// Write headers with folding
	for _, h := range c.Headers {
		headerLine := foldHeader(h.Name, h.Value)
		buf = append(buf, headerLine...)
	}

	// Write blank line separating headers from body
	buf = append(buf, '\r', '\n')

	// Write body
	buf = append(buf, c.Body...)

	return buf
}

// foldHeader folds a header line per RFC 5322.
// Lines MUST be no more than 998 characters, SHOULD be no more than 78.
// Folding is done by inserting CRLF before whitespace.
func foldHeader(name, value string) []byte {
	// Build initial header line: "Name: Value"
	prefix := name + ": "
	prefixLen := len(prefix)

	// If the entire header fits within recommended length, no folding needed
	totalLen := prefixLen + len(value)
	if totalLen <= RecommendedLineLength {
		result := make([]byte, 0, totalLen+2)
		result = append(result, prefix...)
		result = append(result, value...)
		result = append(result, '\r', '\n')
		return result
	}

	// Need to fold - find appropriate break points
	result := make([]byte, 0, totalLen+20) // Extra for CRLF insertions
	result = append(result, prefix...)

	currentLineLen := prefixLen
	valueBytes := []byte(value)
	lastBreak := 0

	for i := range valueBytes {
		currentLineLen++

		// Check if we need to fold
		if currentLineLen >= RecommendedLineLength {
			// Find the last whitespace before current position to break at
			breakPoint := -1
			for j := i; j > lastBreak; j-- {
				if valueBytes[j] == ' ' || valueBytes[j] == '\t' {
					breakPoint = j
					break
				}
			}

			if breakPoint > lastBreak {
				result = append(result, valueBytes[lastBreak:breakPoint]...)
				// Insert fold (CRLF + WSP)
				result = append(result, '\r', '\n', ' ')
				lastBreak = breakPoint + 1
				// Skip any consecutive whitespace after the break point
				for lastBreak < len(valueBytes) && (valueBytes[lastBreak] == ' ' || valueBytes[lastBreak] == '\t') {
					lastBreak++
				}
				currentLineLen = 1 + (i - lastBreak + 1) // 1 for the leading space
			} else if currentLineLen >= MaxLineLength {
				// No good break point found, force break at max length
				// This is a last resort - RFC says MUST not exceed 998
				result = append(result, valueBytes[lastBreak:i]...)
				result = append(result, '\r', '\n', ' ')
				lastBreak = i
				currentLineLen = 1
			}
		}
	}

	if lastBreak < len(valueBytes) {
		result = append(result, valueBytes[lastBreak:]...)
	}

	result = append(result, '\r', '\n')
	return result
}

// parseRawContent parses raw message data into headers and body per RFC 5322.
// The header section is separated from the body by an empty line (CRLF CRLF).
func parseRawContent(data []byte) (Headers, []byte) {
	// Find the header/body separator (empty line)
	// headers and body are separated by an empty line
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
	estimatedHeaders := max(headerEnd/50, 8)
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
				// Continuation of previous header (folded header)
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
