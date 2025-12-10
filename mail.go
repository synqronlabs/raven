package raven

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"time"

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
		if utils.EqualFoldASCII(hdr.Name, name) {
			return hdr.Value
		}
	}
	return ""
}

// GetAll returns all header values with the given name (case-insensitive).
func (h Headers) GetAll(name string) []string {
	var values []string
	for _, hdr := range h {
		if utils.EqualFoldASCII(hdr.Name, name) {
			values = append(values, hdr.Value)
		}
	}
	return values
}

// ContentTransferEncoding represents the encoding used for the MIME part's body.
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

// MIMEHeaders represents a collection of MIME header fields.
type MIMEHeader struct {
	// Name is the header field name (e.g., "From", "Subject").
	Name string `json:"name"`
	// Value is the header field value.
	Value string `json:"value"`
}

// MIMEPart represents a MIME body part for multipart messages (RFC 2045, RFC 2046).
type MIMEPart struct {
	// Headers contains the MIME headers for this part.
	Headers []MIMEHeader `json:"headers,omitempty"`

	// ContentType is the MIME content type (e.g., "text/plain", "image/png").
	ContentType string `json:"content_type,omitempty"`

	// ContentTransferEncoding specifies how the body is encoded.
	ContentTransferEncoding ContentTransferEncoding `json:"content_transfer_encoding,omitempty"`

	// Charset is the character set for text parts (e.g., "utf-8", "iso-8859-1").
	Charset string `json:"charset,omitempty"`

	// Filename is the suggested filename for attachment parts.
	Filename string `json:"filename,omitempty"`

	// ContentID is the Content-ID for inline parts (used in multipart/related).
	ContentID string `json:"content_id,omitempty"`

	// Body is the decoded content of this part.
	Body []byte `json:"body,omitempty"`

	// Parts contains nested parts for multipart content types.
	Parts []*MIMEPart `json:"parts,omitempty"`
}

// parseSinglePartMIME handles non-multipart MIME messages
func (m *Mail) ParseSinglePartMIME(mediaType string, params map[string]string) error {
	mimePart := MIMEPart{
		ContentType: mediaType,
		Body:        m.Content.Body,
	}

	// Extract charset if present
	if charset, ok := params["charset"]; ok {
		mimePart.Charset = charset
		m.Content.Charset = charset
	}

	// Get Content-Transfer-Encoding
	cte := m.Content.Headers.Get("Content-Transfer-Encoding")
	if cte != "" {
		mimePart.ContentTransferEncoding = ContentTransferEncoding(strings.ToLower(cte))
		m.Content.Encoding = mimePart.ContentTransferEncoding
	}

	// Get Content-ID
	contentID := m.Content.Headers.Get("Content-ID")
	if contentID != "" {
		mimePart.ContentID = strings.Trim(contentID, "<>")
	}

	// Check for Content-Disposition (for attachments)
	contentDisp := m.Content.Headers.Get("Content-Disposition")
	if contentDisp != "" {
		_, dispParams, err := mime.ParseMediaType(contentDisp)
		if err == nil {
			if filename, ok := dispParams["filename"]; ok {
				mimePart.Filename = filename
			}
		}
	}

	m.Content.MIME = mimePart
	return nil
}

// parseMultipartMIME handles multipart MIME messages
func (m *Mail) ParseMultipartMIME(mediaType string, params map[string]string) error {
	// Get boundary parameter (required for multipart)
	boundary, ok := params["boundary"]
	if !ok || boundary == "" {
		return errors.New("multipart Content-Type missing boundary parameter")
	}

	// Create the root MIME part
	rootPart := MIMEPart{
		ContentType: mediaType,
		Parts:       make([]*MIMEPart, 0),
	}

	// Create multipart reader
	reader := multipart.NewReader(bytes.NewReader(m.Content.Body), boundary)

	// Parse each part
	for {
		part, err := reader.NextPart()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return fmt.Errorf("error reading multipart section: %w", err)
		}

		// Parse this part
		mimePart, err := ParseMultipartSection(part)
		if err != nil {
			return fmt.Errorf("error parsing multipart section: %w", err)
		}

		rootPart.Parts = append(rootPart.Parts, mimePart)
	}

	// Validate that we have at least one part
	if len(rootPart.Parts) == 0 {
		return errors.New("multipart message contains no parts")
	}

	m.Content.MIME = rootPart
	return nil
}

// parseMultipartSection parses a single part of a multipart message
func ParseMultipartSection(part *multipart.Part) (*MIMEPart, error) {
	mimePart := &MIMEPart{
		Headers: make([]MIMEHeader, 0),
	}

	// Convert textproto.MIMEHeader to our Headers type
	for name, values := range part.Header {
		for _, value := range values {
			mimePart.Headers = append(mimePart.Headers, MIMEHeader{
				Name:  name,
				Value: value,
			})
		}
	}

	// Get Content-Type
	contentType := part.Header.Get("Content-Type")
	if contentType == "" {
		// Default to text/plain per RFC 2045
		mimePart.ContentType = "text/plain"
		mimePart.Charset = "us-ascii"
	} else {
		mediaType, params, err := mime.ParseMediaType(contentType)
		if err != nil {
			return nil, fmt.Errorf("invalid Content-Type in part: %w", err)
		}
		mimePart.ContentType = mediaType

		if charset, ok := params["charset"]; ok {
			mimePart.Charset = charset
		}

		// Check if this part is itself multipart (nested multipart)
		if strings.HasPrefix(mediaType, "multipart/") {
			boundary, ok := params["boundary"]
			if !ok || boundary == "" {
				return nil, errors.New("nested multipart missing boundary parameter")
			}

			// Read the body first
			body := new(bytes.Buffer)
			_, err := body.ReadFrom(part)
			if err != nil {
				return nil, fmt.Errorf("error reading nested multipart body: %w", err)
			}

			// Parse nested multipart
			nestedReader := multipart.NewReader(bytes.NewReader(body.Bytes()), boundary)
			mimePart.Parts = make([]*MIMEPart, 0)

			for {
				nestedPart, err := nestedReader.NextPart()
				if err != nil {
					if err.Error() == "EOF" {
						break
					}
					return nil, fmt.Errorf("error reading nested multipart section: %w", err)
				}

				nestedMIME, err := ParseMultipartSection(nestedPart)
				if err != nil {
					return nil, err
				}
				mimePart.Parts = append(mimePart.Parts, nestedMIME)
			}

			mimePart.Body = body.Bytes()
			return mimePart, nil
		}
	}

	// Get Content-Transfer-Encoding
	cte := part.Header.Get("Content-Transfer-Encoding")
	if cte != "" {
		mimePart.ContentTransferEncoding = ContentTransferEncoding(strings.ToLower(cte))
	}

	// Get Content-ID
	contentID := part.Header.Get("Content-ID")
	if contentID != "" {
		mimePart.ContentID = strings.Trim(contentID, "<>")
	}

	// Get Content-Disposition (for filename)
	contentDisp := part.Header.Get("Content-Disposition")
	if contentDisp != "" {
		_, dispParams, err := mime.ParseMediaType(contentDisp)
		if err == nil {
			if filename, ok := dispParams["filename"]; ok {
				mimePart.Filename = filename
			}
		}
	}

	// Read the body
	body := new(bytes.Buffer)
	_, err := body.ReadFrom(part)
	if err != nil {
		return nil, fmt.Errorf("error reading part body: %w", err)
	}
	mimePart.Body = body.Bytes()

	return mimePart, nil
}

// Content represents the message content (header section + body) as per RFC 5321 Section 2.3.1.
// This is what follows the DATA command.
type Content struct {
	// Headers contains all message header fields per RFC 5322.
	// Common headers include: From, To, Cc, Bcc, Subject, Date, Message-ID, etc.
	Headers Headers `json:"headers"`

	// Body is the raw message body (may be encoded).
	Body []byte `json:"body,omitempty"`

	// MIME contains parsed MIME structure if the message is MIME-formatted.
	// Nil for simple non-MIME messages.
	MIME MIMEPart `json:"mime,omitzero"`

	// Encoding indicates how the body is encoded per RFC 2045.
	Encoding ContentTransferEncoding `json:"encoding,omitempty"`

	// Charset is the primary character set of the message body.
	Charset string `json:"charset,omitempty"`
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

	// Raw contains the raw message data as received, if preserved.
	// This may be useful for exact re-transmission or archival.
	Raw []byte `json:"raw,omitempty"`
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

// ValidateAndParseMIME validates the MIME structure of the mail message and populates
// the Content.MIME field if successful. It checks Content-Type headers and validates
// multipart boundaries.
//
// For multipart messages, it recursively validates all parts and their boundaries.
// Returns an error if the MIME structure is invalid.
func (m *Mail) ValidateAndParseMIME() error {
	// Get Content-Type header
	contentType := m.Content.Headers.Get("Content-Type")
	if contentType == "" {
		// No Content-Type header - treat as text/plain (RFC 2045 default)
		m.Content.MIME = MIMEPart{
			ContentType: "text/plain",
			Charset:     "us-ascii",
			Body:        m.Content.Body,
		}
		return nil
	}

	// Parse Content-Type header
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return fmt.Errorf("invalid Content-Type header: %w", err)
	}

	// Check if this is a multipart message
	if strings.HasPrefix(mediaType, "multipart/") {
		return m.ParseMultipartMIME(mediaType, params)
	}

	// Single-part message
	return m.ParseSinglePartMIME(mediaType, params)
}
