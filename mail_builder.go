package raven

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	ravenmime "github.com/synqronlabs/raven/mime"
	"github.com/synqronlabs/raven/utils"
)

// MailBuilder provides a fluent API for constructing Mail objects.
type MailBuilder struct {
	mail   *Mail
	errors []error
}

// NewMailBuilder creates a new MailBuilder instance.
func NewMailBuilder() *MailBuilder {
	return &MailBuilder{
		mail:   NewMail(),
		errors: make([]error, 0),
	}
}

// From sets the envelope sender and adds a From header.
func (b *MailBuilder) From(address string) *MailBuilder {
	parsed, err := ParseAddress(address)
	if err != nil {
		b.errors = append(b.errors, fmt.Errorf("invalid from address %q: %w", address, err))
		return b
	}
	b.mail.SetFrom(parsed)
	b.mail.AddHeader("From", formatAddress(parsed))
	return b
}

// FromMailbox sets the envelope sender from a MailboxAddress.
func (b *MailBuilder) FromMailbox(address MailboxAddress) *MailBuilder {
	b.mail.SetFrom(address)
	b.mail.AddHeader("From", formatAddress(address))
	return b
}

// NullSender sets a null reverse-path (for bounce messages).
func (b *MailBuilder) NullSender() *MailBuilder {
	b.mail.SetNullSender()
	return b
}

// Sender sets the Sender header (required if From has multiple addresses).
func (b *MailBuilder) Sender(address string) *MailBuilder {
	parsed, err := ParseAddress(address)
	if err != nil {
		b.errors = append(b.errors, fmt.Errorf("invalid sender address %q: %w", address, err))
		return b
	}
	b.mail.AddHeader("Sender", formatAddress(parsed))
	return b
}

// To adds recipients to the envelope and To header.
func (b *MailBuilder) To(addresses ...string) *MailBuilder {
	for _, addr := range addresses {
		parsed, err := ParseAddress(addr)
		if err != nil {
			b.errors = append(b.errors, fmt.Errorf("invalid to address %q: %w", addr, err))
			continue
		}
		b.mail.AddRecipient(parsed)
	}
	// Update To header with all recipients
	b.updateAddressHeader("To", b.mail.Envelope.To)
	return b
}

// ToMailbox adds a recipient using a MailboxAddress.
func (b *MailBuilder) ToMailbox(addresses ...MailboxAddress) *MailBuilder {
	for _, addr := range addresses {
		b.mail.AddRecipient(addr)
	}
	b.updateAddressHeader("To", b.mail.Envelope.To)
	return b
}

// Cc adds CC recipients (adds to envelope and Cc header).
func (b *MailBuilder) Cc(addresses ...string) *MailBuilder {
	var parsed []MailboxAddress
	for _, addr := range addresses {
		p, err := ParseAddress(addr)
		if err != nil {
			b.errors = append(b.errors, fmt.Errorf("invalid cc address %q: %w", addr, err))
			continue
		}
		b.mail.AddRecipient(p)
		parsed = append(parsed, p)
	}
	if len(parsed) > 0 {
		b.mail.AddHeader("Cc", formatAddressList(parsed))
	}
	return b
}

// Bcc adds BCC recipients (envelope only, no header).
func (b *MailBuilder) Bcc(addresses ...string) *MailBuilder {
	for _, addr := range addresses {
		parsed, err := ParseAddress(addr)
		if err != nil {
			b.errors = append(b.errors, fmt.Errorf("invalid bcc address %q: %w", addr, err))
			continue
		}
		b.mail.AddRecipient(parsed)
	}
	return b
}

// ReplyTo sets the Reply-To header.
func (b *MailBuilder) ReplyTo(address string) *MailBuilder {
	parsed, err := ParseAddress(address)
	if err != nil {
		b.errors = append(b.errors, fmt.Errorf("invalid reply-to address %q: %w", address, err))
		return b
	}
	b.mail.AddHeader("Reply-To", formatAddress(parsed))
	return b
}

// Subject sets the Subject header.
func (b *MailBuilder) Subject(subject string) *MailBuilder {
	if utils.ContainsNonASCII(subject) {
		subject = encodeRFC2047(subject)
	}
	b.mail.AddHeader("Subject", subject)
	return b
}

// Header adds a custom header to the message.
func (b *MailBuilder) Header(name, value string) *MailBuilder {
	b.mail.AddHeader(name, value)
	return b
}

// MessageID sets the Message-ID header.
func (b *MailBuilder) MessageID(id string) *MailBuilder {
	if !strings.HasPrefix(id, "<") {
		id = "<" + id + ">"
	}
	b.mail.AddHeader("Message-ID", id)
	return b
}

// InReplyTo sets the In-Reply-To header for threading.
func (b *MailBuilder) InReplyTo(messageID string) *MailBuilder {
	if !strings.HasPrefix(messageID, "<") {
		messageID = "<" + messageID + ">"
	}
	b.mail.AddHeader("In-Reply-To", messageID)
	return b
}

// References sets the References header for threading.
func (b *MailBuilder) References(messageIDs ...string) *MailBuilder {
	formatted := make([]string, len(messageIDs))
	for i, id := range messageIDs {
		if !strings.HasPrefix(id, "<") {
			formatted[i] = "<" + id + ">"
		} else {
			formatted[i] = id
		}
	}
	b.mail.AddHeader("References", strings.Join(formatted, " "))
	return b
}

// Date sets the Date header. If not called, Build() will use the current time.
func (b *MailBuilder) Date(t time.Time) *MailBuilder {
	b.mail.AddHeader("Date", t.Format(time.RFC1123Z))
	return b
}

// Priority sets the X-Priority header.
// Values: 1 (highest), 2 (high), 3 (normal), 4 (low), 5 (lowest).
func (b *MailBuilder) Priority(level int) *MailBuilder {
	if level < 1 || level > 5 {
		level = 3 // Default to normal
	}
	b.mail.AddHeader("X-Priority", fmt.Sprintf("%d", level))
	return b
}

// TextBody sets a plain text body for the message.
// Line endings are normalized to CRLF.
func (b *MailBuilder) TextBody(body string) *MailBuilder {
	normalizedBody := normalizeLineEndings(body)
	b.mail.Content.Body = []byte(normalizedBody)
	b.mail.Content.Charset = "utf-8"
	b.mail.AddHeader("Content-Type", "text/plain; charset=utf-8")

	// Check if we need 8-bit encoding
	if utils.ContainsNonASCII(normalizedBody) {
		b.mail.Content.Encoding = ravenmime.Encoding8Bit
		b.mail.AddHeader("Content-Transfer-Encoding", "8bit")
		b.mail.Envelope.BodyType = BodyType8BitMIME
	} else {
		b.mail.Content.Encoding = ravenmime.Encoding7Bit
		b.mail.AddHeader("Content-Transfer-Encoding", "7bit")
	}

	return b
}

// HTMLBody sets an HTML body for the message.
// Line endings are normalized to CRLF.
func (b *MailBuilder) HTMLBody(body string) *MailBuilder {
	normalizedBody := normalizeLineEndings(body)
	b.mail.Content.Body = []byte(normalizedBody)
	b.mail.Content.Charset = "utf-8"
	b.mail.AddHeader("Content-Type", "text/html; charset=utf-8")

	if utils.ContainsNonASCII(normalizedBody) {
		b.mail.Content.Encoding = ravenmime.Encoding8Bit
		b.mail.AddHeader("Content-Transfer-Encoding", "8bit")
		b.mail.Envelope.BodyType = BodyType8BitMIME
	} else {
		b.mail.Content.Encoding = ravenmime.Encoding7Bit
		b.mail.AddHeader("Content-Transfer-Encoding", "7bit")
	}

	return b
}

// Body sets the raw body with explicit content type and encoding.
func (b *MailBuilder) Body(body []byte, contentType string, encoding ravenmime.ContentTransferEncoding) *MailBuilder {
	b.mail.Content.Body = body
	b.mail.Content.Encoding = encoding
	b.mail.AddHeader("Content-Type", contentType)
	b.mail.AddHeader("Content-Transfer-Encoding", string(encoding))
	return b
}

// Attachment represents an email attachment.
type Attachment struct {
	Filename    string
	ContentType string
	Data        []byte
	Inline      bool
	ContentID   string // For inline attachments
}

// AttachFile adds a file attachment.
// The content type is determined from the filename if not specified.
func (b *MailBuilder) AttachFile(filename string, data []byte, contentType string) *MailBuilder {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	b.addAttachment(Attachment{
		Filename:    filename,
		ContentType: contentType,
		Data:        data,
	})
	return b
}

// AttachInline adds an inline attachment (for embedding images in HTML).
func (b *MailBuilder) AttachInline(filename, contentID string, data []byte, contentType string) *MailBuilder {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	b.addAttachment(Attachment{
		Filename:    filename,
		ContentType: contentType,
		Data:        data,
		Inline:      true,
		ContentID:   contentID,
	})
	return b
}

// DSN configures Delivery Status Notification parameters.
func (b *MailBuilder) DSN(notify []string, ret string) *MailBuilder {
	// Validate notify values
	validNotify := make([]string, 0, len(notify))
	for _, n := range notify {
		n = strings.ToUpper(n)
		switch n {
		case "NEVER", "SUCCESS", "FAILURE", "DELAY":
			validNotify = append(validNotify, n)
		}
	}

	// Set envelope DSN params
	b.mail.Envelope.DSNParams = &DSNEnvelopeParams{
		RET: strings.ToUpper(ret),
	}

	// Set DSN params for all recipients
	for i := range b.mail.Envelope.To {
		b.mail.Envelope.To[i].DSNParams = &DSNRecipientParams{
			Notify: validNotify,
		}
	}

	return b
}

// RecipientDSN sets DSN parameters for a specific recipient by index.
func (b *MailBuilder) RecipientDSN(recipientIndex int, notify []string, orcpt string) *MailBuilder {
	if recipientIndex < 0 || recipientIndex >= len(b.mail.Envelope.To) {
		b.errors = append(b.errors, fmt.Errorf("recipient index %d out of range", recipientIndex))
		return b
	}

	validNotify := make([]string, 0, len(notify))
	for _, n := range notify {
		n = strings.ToUpper(n)
		switch n {
		case "NEVER", "SUCCESS", "FAILURE", "DELAY":
			validNotify = append(validNotify, n)
		}
	}

	b.mail.Envelope.To[recipientIndex].DSNParams = &DSNRecipientParams{
		Notify: validNotify,
		ORcpt:  orcpt,
	}

	return b
}

// EnvID sets the envelope identifier for DSN purposes (RFC 3461).
func (b *MailBuilder) EnvID(envID string) *MailBuilder {
	b.mail.Envelope.EnvID = envID
	return b
}

// SMTPUTF8 explicitly marks this message as requiring SMTPUTF8 extension.
func (b *MailBuilder) SMTPUTF8() *MailBuilder {
	b.mail.Envelope.SMTPUTF8 = true
	return b
}

// RequireTLS marks this message as requiring TLS for all transmission hops (RFC 8689).
// When set, the client will include the REQUIRETLS parameter in MAIL FROM,
// and the server MUST ensure TLS is used for the entire delivery path.
// The receiving server must also support the REQUIRETLS extension.
func (b *MailBuilder) RequireTLS() *MailBuilder {
	b.mail.Envelope.RequireTLS = true
	return b
}

// TLSOptional adds the "TLS-Required: No" header field to the message (RFC 8689).
// This indicates that the sender requests recipient-side TLS policy mechanisms
// (such as MTA-STS and DANE) be ignored, prioritizing delivery over TLS.
// Use this when you need to deliver a message even if TLS cannot be established,
// such as when reporting TLS certificate problems to administrators.
func (b *MailBuilder) TLSOptional() *MailBuilder {
	b.mail.AddHeader("TLS-Required", "No")
	return b
}

// Size declares the message size (for SIZE extension).
func (b *MailBuilder) Size(size int64) *MailBuilder {
	b.mail.Envelope.Size = size
	return b
}

// Auth sets the AUTH parameter for the envelope (authenticated sender identity).
func (b *MailBuilder) Auth(identity string) *MailBuilder {
	b.mail.Envelope.Auth = identity
	return b
}

// ExtensionParam sets a custom MAIL FROM extension parameter.
func (b *MailBuilder) ExtensionParam(name, value string) *MailBuilder {
	if b.mail.Envelope.ExtensionParams == nil {
		b.mail.Envelope.ExtensionParams = make(map[string]string)
	}
	b.mail.Envelope.ExtensionParams[strings.ToUpper(name)] = value
	return b
}

// Build finalizes the Mail object and returns it.
// Returns an error if any validation fails or if required fields are missing.
// The builder ensures RFC 5322 compliance by:
// - Adding Date header if missing
// - Generating Message-ID if missing
// - Validating required From header
// - Auto-detecting SMTPUTF8 requirements
func (b *MailBuilder) Build() (*Mail, error) {
	if len(b.errors) > 0 {
		return nil, fmt.Errorf("mail builder errors: %v", b.errors)
	}

	if b.mail.Envelope.From.IsNull() {
		// Allow null sender for bounces, but ensure From header exists
		if b.mail.Content.Headers.Get("From") == "" {
			return nil, fmt.Errorf("from address is required")
		}
	}

	if len(b.mail.Envelope.To) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}

	if b.mail.Content.Headers.Get("Date") == "" {
		b.mail.AddHeader("Date", time.Now().Format(time.RFC1123Z))
	}

	if b.mail.Content.Headers.Get("Message-ID") == "" {
		domain := b.mail.Envelope.From.Mailbox.Domain
		if domain == "" && len(b.mail.Envelope.To) > 0 {
			domain = b.mail.Envelope.To[0].Address.Mailbox.Domain
		}
		if domain == "" {
			domain = "localhost"
		}
		msgID := fmt.Sprintf("<%d.%s@%s>", time.Now().UnixNano(), utils.GenerateID(), domain)
		b.mail.AddHeader("Message-ID", msgID)
	}

	// If From contains multiple addresses, Sender MUST be present
	// Check if From header contains multiple addresses (comma-separated)
	fromHeader := b.mail.Content.Headers.Get("From")
	if strings.Contains(fromHeader, ",") && b.mail.Content.Headers.Get("Sender") == "" {
		// Auto-add Sender as the first From address for compliance
		if !b.mail.Envelope.From.IsNull() {
			b.mail.AddHeader("Sender", formatAddress(b.mail.Envelope.From.Mailbox))
		}
	}

	// Add MIME-Version header if content type is set
	if b.mail.Content.Headers.Get("Content-Type") != "" && b.mail.Content.Headers.Get("MIME-Version") == "" {
		// Prepend MIME-Version before Content-Type
		headers := make(Headers, 0, len(b.mail.Content.Headers)+1)
		for _, h := range b.mail.Content.Headers {
			if h.Name == "Content-Type" {
				headers = append(headers, Header{Name: "MIME-Version", Value: "1.0"})
			}
			headers = append(headers, h)
		}
		b.mail.Content.Headers = headers
	}

	// Detect SMTPUTF8 requirement
	if b.mail.RequiresSMTPUTF8() {
		b.mail.Envelope.SMTPUTF8 = true
	}

	// Calculate size if not set
	if b.mail.Envelope.Size == 0 {
		raw := b.mail.Content.ToRaw()
		b.mail.Envelope.Size = int64(len(raw))
	}

	// Set received time
	b.mail.ReceivedAt = time.Now()

	// Generate ID
	b.mail.ID = utils.GenerateID()

	return b.mail, nil
}

// MustBuild is like Build but panics on error.
func (b *MailBuilder) MustBuild() *Mail {
	mail, err := b.Build()
	if err != nil {
		panic(err)
	}
	return mail
}

// attachments is a temporary storage for attachments during building.
var attachmentStore = make(map[*MailBuilder][]Attachment)

func (b *MailBuilder) addAttachment(a Attachment) {
	attachmentStore[b] = append(attachmentStore[b], a)
}

// updateAddressHeader updates or adds an address header.
func (b *MailBuilder) updateAddressHeader(name string, recipients []Recipient) {
	addresses := make([]MailboxAddress, len(recipients))
	for i, r := range recipients {
		addresses[i] = r.Address.Mailbox
	}

	// Remove existing header
	newHeaders := make(Headers, 0, len(b.mail.Content.Headers))
	for _, h := range b.mail.Content.Headers {
		if !strings.EqualFold(h.Name, name) {
			newHeaders = append(newHeaders, h)
		}
	}
	b.mail.Content.Headers = newHeaders

	// Add updated header
	b.mail.AddHeader(name, formatAddressList(addresses))
}

// formatAddress formats a MailboxAddress for use in headers.
func formatAddress(addr MailboxAddress) string {
	email := addr.String()
	if addr.DisplayName != "" {
		// Check if display name needs encoding
		displayName := addr.DisplayName
		if utils.ContainsNonASCII(displayName) {
			displayName = encodeRFC2047(displayName)
		} else if strings.ContainsAny(displayName, `"(),.:;<>@[\]`) {
			displayName = `"` + strings.ReplaceAll(displayName, `"`, `\"`) + `"`
		}
		return displayName + " <" + email + ">"
	}
	return email
}

// formatAddressList formats multiple addresses for use in headers.
func formatAddressList(addresses []MailboxAddress) string {
	formatted := make([]string, len(addresses))
	for i, addr := range addresses {
		formatted[i] = formatAddress(addr)
	}
	return strings.Join(formatted, ", ")
}

// encodeRFC2047 encodes a string using RFC 2047 Base64 encoding.
func encodeRFC2047(s string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(s))
	return "=?UTF-8?B?" + encoded + "?="
}

// normalizeLineEndings converts all line endings to CRLF.
// Handles LF, CR, and CRLF inputs.
func normalizeLineEndings(s string) string {
	// First, normalize CRLF and bare CR to LF
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	// Then convert all LF to CRLF
	s = strings.ReplaceAll(s, "\n", "\r\n")
	return s
}
