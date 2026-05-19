// Package mail provides Raven's core email model, builder APIs, and MIME helpers.
//
// The package defines the fundamental structures used across the module:
// Mail, Envelope, Content, Headers, MIMEPart, and related builder and
// serialization helpers. SMTP transport packages and authentication packages
// (dkim, spf, dmarc, arc) can share these types without circular dependencies.
package mail

//go:generate msgp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	ravenio "github.com/synqronlabs/raven/io"
)

// RFC 5322 line length limits.
const (
	MaxLineLength         = 998
	RecommendedLineLength = 78
)

// RFC 5322 validation errors.
var (
	ErrMissingDateHeader      = errors.New("rfc5322: missing required Date header")
	ErrMissingFromHeader      = errors.New("rfc5322: missing required From header")
	ErrMultipleFromNoSender   = errors.New("rfc5322: multiple From addresses require Sender header")
	ErrDuplicateSingleHeader  = errors.New("rfc5322: header field appears more than once")
	ErrInvalidHeaderName      = errors.New("rfc5322: invalid header field name")
	ErrLineTooLong            = errors.New("rfc5322: line exceeds maximum length of 998 characters")
	ErrInvalidLineEnding      = errors.New("rfc5322: lines must be terminated with CRLF, not bare LF")
	ErrUnsupportedHeaderParse = errors.New("rfc5322: structured parsing not supported for header")
	ErrInvalidHeaderValue     = errors.New("rfc5322: invalid structured header value")
)

// BodyType specifies the encoding type of the message body (RFC 6152).
type BodyType string

const (
	BodyType7Bit       BodyType = "7BIT"
	BodyType8BitMIME   BodyType = "8BITMIME"
	BodyTypeBinaryMIME BodyType = "BINARYMIME"
)

// ContentTransferEncoding represents the wire-level MIME transfer encoding.
type ContentTransferEncoding string

const (
	Encoding7Bit            ContentTransferEncoding = "7bit"
	Encoding8Bit            ContentTransferEncoding = "8bit"
	EncodingBinary          ContentTransferEncoding = "binary"
	EncodingQuotedPrintable ContentTransferEncoding = "quoted-printable"
	EncodingBase64          ContentTransferEncoding = "base64"
)

// MailboxAddress represents an email address.
// Supports ASCII and internationalized addresses.
type MailboxAddress struct {
	LocalPart   string `json:"local_part"`
	Domain      string `json:"domain"`
	DisplayName string `json:"display_name,omitempty"`
}

// String returns the address in the standard "local-part@domain" format.
func (m *MailboxAddress) String() string {
	if m == nil {
		return ""
	}
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
func (p *Path) IsNull() bool {
	if p == nil {
		return true
	}
	return p.Mailbox.LocalPart == "" && p.Mailbox.Domain == ""
}

// String returns the path in angle bracket format.
func (p *Path) String() string {
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

// DeliveryByMode controls how the server handles messages that miss the
// requested delivery deadline (RFC 2852).
type DeliveryByMode string

const (
	// DeliveryByModeNotify requests a delayed notification if the deadline passes.
	DeliveryByModeNotify DeliveryByMode = "N"

	// DeliveryByModeReturn requests the message be returned if the deadline passes.
	DeliveryByModeReturn DeliveryByMode = "R"
)

// DeliveryBy requests delivery within a bounded time window (RFC 2852).
type DeliveryBy struct {
	Seconds int64          `json:"seconds"`
	Mode    DeliveryByMode `json:"mode"`
	Trace   bool           `json:"trace,omitempty"`
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
	DeliveryBy      *DeliveryBy        `json:"delivery_by,omitempty"`
	EnvID           string             `json:"env_id,omitempty"`
	DSNParams       *DSNEnvelopeParams `json:"dsn_params,omitempty"`
	Auth            string             `json:"auth,omitempty"`
	ExtensionParams map[string]string  `json:"extension_params,omitempty"`
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

// ParseHeaders parses a raw RFC 5322 header block into Headers.
//
// The input may be a bare header block without the terminating blank line, or
// a complete message. Folded header lines are unfolded using the same rules as
// Content.FromRaw.
func ParseHeaders(data []byte) Headers {
	if len(data) == 0 {
		return nil
	}

	if bytes.Contains(data, []byte("\r\n\r\n")) || bytes.Contains(data, []byte("\n\n")) {
		headers, _ := parseRawContent(data)
		return headers
	}

	raw := make([]byte, 0, len(data)+4)
	raw = append(raw, data...)
	raw = append(raw, '\r', '\n', '\r', '\n')
	headers, _ := parseRawContent(raw)
	return headers
}

// ToRaw serializes Headers into a raw RFC 5322 header block.
//
// Header values are folded with FoldHeader and terminated with CRLF. The
// returned bytes include only the header block and do not append the blank line
// that separates headers from the message body.
func (h Headers) ToRaw() []byte {
	if len(h) == 0 {
		return nil
	}

	estimatedSize := 0
	for _, header := range h {
		estimatedSize += len(header.Name) + 2 + len(header.Value) + 10
	}

	raw := make([]byte, 0, estimatedSize)
	for _, header := range h {
		raw = append(raw, FoldHeader(header.Name, header.Value)...)
	}

	return raw
}

// Get returns the first header value with the given name (case-insensitive).
func (h *Headers) Get(name string) string {
	if h == nil {
		return ""
	}
	for _, hdr := range *h {
		if strings.EqualFold(hdr.Name, name) {
			return hdr.Value
		}
	}
	return ""
}

// GetAll returns all header values with the given name (case-insensitive).
func (h *Headers) GetAll(name string) []string {
	var values []string
	if h == nil {
		return values
	}
	for _, hdr := range *h {
		if strings.EqualFold(hdr.Name, name) {
			values = append(values, hdr.Value)
		}
	}
	return values
}

// Count returns the number of headers with the given name (case-insensitive).
func (h *Headers) Count(name string) int {
	if h == nil {
		return 0
	}
	count := 0
	for _, hdr := range *h {
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
	"return-path": true,
	"subject":     true,
}

func isFieldNameChar(b byte) bool {
	return b >= 33 && b <= 126 && b != ':'
}

func isHeaderControlChar(b byte) bool {
	return (b < 32 && b != '\t') || b == 127
}

func isWSP(b byte) bool {
	return b == ' ' || b == '\t'
}

func isAText(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b >= '0' && b <= '9':
		return true
	}

	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~':
		return true
	default:
		return false
	}
}

func validateHeaderName(name string) error {
	if name == "" {
		return ErrInvalidHeaderName
	}
	for i := 0; i < len(name); i++ {
		if !isFieldNameChar(name[i]) {
			return ErrInvalidHeaderName
		}
	}
	return nil
}

func validateHeaderValue(value string) error {
	for i := 0; i < len(value); i++ {
		if value[i] == '\r' || value[i] == '\n' {
			return ErrInvalidLineEnding
		}
		if isHeaderControlChar(value[i]) {
			return ErrInvalidHeaderValue
		}
	}
	return nil
}

func validateHeaderLineLength(name, value string) error {
	lineLen := len(name) + 2 // "Name: "
	if lineLen > MaxLineLength {
		return ErrLineTooLong
	}

	segmentStart := 0
	lastBreak := -1
	for i := 0; i < len(value); i++ {
		lineLen++
		if value[i] == ' ' || value[i] == '\t' {
			lastBreak = i
		}
		if lineLen <= MaxLineLength {
			continue
		}

		if lastBreak < segmentStart {
			return ErrLineTooLong
		}

		nextStart := lastBreak + 1
		for nextStart < len(value) && (value[nextStart] == ' ' || value[nextStart] == '\t') {
			nextStart++
		}
		segmentStart = nextStart
		lineLen = 1 + (i - nextStart + 1) // continuation WSP + remaining content
		lastBreak = -1
	}

	return nil
}

func validateHeaderBlock(headers Headers) error {
	for _, hdr := range headers {
		if err := validateHeaderName(hdr.Name); err != nil {
			return err
		}
		if err := validateHeaderValue(hdr.Value); err != nil {
			return err
		}
		if err := validateHeaderLineLength(hdr.Name, hdr.Value); err != nil {
			return err
		}
	}
	return nil
}

func validateAddressListHeader(name, value string, allowEmpty bool) error {
	if isCFWSOnly(value) {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("%w: %s: empty address list", ErrInvalidHeaderValue, name)
	}

	if _, err := mail.ParseAddressList(value); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrInvalidHeaderValue, name, err)
	}

	return nil
}

func validateSingleMailboxHeader(name, value string) error {
	if err := validateAddressListHeader(name, value, false); err != nil {
		return err
	}

	parsed, err := mail.ParseAddressList(value)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrInvalidHeaderValue, name, err)
	}
	if len(parsed) != 1 {
		return fmt.Errorf("%w: %s: must contain exactly one mailbox", ErrInvalidHeaderValue, name)
	}

	return nil
}

func consumeComment(value string, pos int) (int, error) {
	if pos >= len(value) || value[pos] != '(' {
		return 0, ErrInvalidHeaderValue
	}

	depth := 0
	for pos < len(value) {
		switch value[pos] {
		case '(':
			depth++
			pos++
		case ')':
			depth--
			pos++
			if depth == 0 {
				return pos, nil
			}
		case '\\':
			pos++
			if pos >= len(value) || value[pos] == '\r' || value[pos] == '\n' || value[pos] == 0 {
				return 0, ErrInvalidHeaderValue
			}
			pos++
		default:
			if value[pos] == '\r' || value[pos] == '\n' {
				return 0, ErrInvalidLineEnding
			}
			if isHeaderControlChar(value[pos]) {
				return 0, ErrInvalidHeaderValue
			}
			pos++
		}
	}

	return 0, ErrInvalidHeaderValue
}

func skipCFWS(value string, pos int) (int, error) {
	for {
		start := pos
		for pos < len(value) && isWSP(value[pos]) {
			pos++
		}
		if pos < len(value) && value[pos] == '(' {
			next, err := consumeComment(value, pos)
			if err != nil {
				return 0, err
			}
			pos = next
			continue
		}
		if pos == start {
			return pos, nil
		}
	}
}

func isCFWSOnly(value string) bool {
	pos, err := skipCFWS(value, 0)
	return err == nil && pos == len(value)
}

func consumeAtom(value string, pos int, allowUTF8 bool) (int, error) {
	start := pos
	for pos < len(value) {
		if isAText(value[pos]) || (allowUTF8 && value[pos] >= 128) {
			pos++
			continue
		}
		break
	}
	if pos == start {
		return 0, ErrInvalidHeaderValue
	}
	return pos, nil
}

func consumeDotAtomText(value string, pos int, allowUTF8 bool) (int, error) {
	next, err := consumeAtom(value, pos, allowUTF8)
	if err != nil {
		return 0, err
	}
	pos = next
	for pos < len(value) && value[pos] == '.' {
		pos++
		next, err = consumeAtom(value, pos, allowUTF8)
		if err != nil {
			return 0, ErrInvalidHeaderValue
		}
		pos = next
	}
	return pos, nil
}

func consumeQuotedString(value string, pos int) (int, error) {
	if pos >= len(value) || value[pos] != '"' {
		return 0, ErrInvalidHeaderValue
	}

	pos++
	for pos < len(value) {
		switch value[pos] {
		case '"':
			return pos + 1, nil
		case '\\':
			pos++
			if pos >= len(value) || value[pos] == '\r' || value[pos] == '\n' || value[pos] == 0 {
				return 0, ErrInvalidHeaderValue
			}
			pos++
		default:
			if value[pos] == '\r' || value[pos] == '\n' {
				return 0, ErrInvalidLineEnding
			}
			if value[pos] != '\t' && value[pos] < 32 {
				return 0, ErrInvalidHeaderValue
			}
			pos++
		}
	}

	return 0, ErrInvalidHeaderValue
}

func consumeLocalPart(value string, pos int) (int, error) {
	if pos < len(value) && value[pos] == '"' {
		return consumeQuotedString(value, pos)
	}
	return consumeDotAtomText(value, pos, true)
}

func consumeDomainLiteral(value string, pos int) (int, error) {
	if pos >= len(value) || value[pos] != '[' {
		return 0, ErrInvalidHeaderValue
	}

	pos++
	for pos < len(value) {
		if value[pos] == ']' {
			return pos + 1, nil
		}
		if value[pos] < 33 || value[pos] > 126 || value[pos] == '[' || value[pos] == '\\' {
			return 0, ErrInvalidHeaderValue
		}
		pos++
	}

	return 0, ErrInvalidHeaderValue
}

func consumeDomain(value string, pos int, allowUTF8 bool) (int, error) {
	if pos < len(value) && value[pos] == '[' {
		return consumeDomainLiteral(value, pos)
	}
	return consumeDotAtomText(value, pos, allowUTF8)
}

func consumeAddrSpec(value string, pos int) (int, error) {
	next, err := consumeLocalPart(value, pos)
	if err != nil {
		return 0, err
	}
	if next >= len(value) || value[next] != '@' {
		return 0, ErrInvalidHeaderValue
	}
	return consumeDomain(value, next+1, true)
}

func consumeMsgID(value string, pos int) (int, error) {
	pos, err := skipCFWS(value, pos)
	if err != nil {
		return 0, err
	}
	if pos >= len(value) || value[pos] != '<' {
		return 0, ErrInvalidHeaderValue
	}

	pos++
	pos, err = consumeDotAtomText(value, pos, false)
	if err != nil {
		return 0, err
	}
	if pos >= len(value) || value[pos] != '@' {
		return 0, ErrInvalidHeaderValue
	}

	pos, err = consumeDomain(value, pos+1, false)
	if err != nil {
		return 0, err
	}
	if pos >= len(value) || value[pos] != '>' {
		return 0, ErrInvalidHeaderValue
	}

	return skipCFWS(value, pos+1)
}

func validateMessageIDHeader(name, value string) error {
	pos, err := consumeMsgID(value, 0)
	if err != nil || pos != len(value) {
		return fmt.Errorf("%w: %s: invalid message identifier", ErrInvalidHeaderValue, name)
	}
	return nil
}

func validateMessageIDListHeader(name, value string) error {
	pos, err := skipCFWS(value, 0)
	if err != nil {
		return fmt.Errorf("%w: %s: invalid message identifier list", ErrInvalidHeaderValue, name)
	}
	if pos == len(value) {
		return fmt.Errorf("%w: %s: empty message identifier list", ErrInvalidHeaderValue, name)
	}

	count := 0
	for pos < len(value) {
		next, err := consumeMsgID(value, pos)
		if err != nil {
			return fmt.Errorf("%w: %s: invalid message identifier list", ErrInvalidHeaderValue, name)
		}
		if next == pos {
			return fmt.Errorf("%w: %s: invalid message identifier list", ErrInvalidHeaderValue, name)
		}
		count++
		pos = next
	}
	if count == 0 {
		return fmt.Errorf("%w: %s: empty message identifier list", ErrInvalidHeaderValue, name)
	}

	return nil
}

func consumeWord(value string, pos int) (int, error) {
	if pos < len(value) && value[pos] == '"' {
		return consumeQuotedString(value, pos)
	}
	return consumeAtom(value, pos, true)
}

func consumePhrase(value string, pos int) (int, error) {
	pos, err := skipCFWS(value, pos)
	if err != nil {
		return 0, err
	}

	words := 0
	for pos < len(value) && value[pos] != ',' {
		next, err := consumeWord(value, pos)
		if err != nil {
			return 0, err
		}
		words++
		pos, err = skipCFWS(value, next)
		if err != nil {
			return 0, err
		}
		if pos >= len(value) || value[pos] == ',' {
			break
		}
	}
	if words == 0 {
		return 0, ErrInvalidHeaderValue
	}

	return pos, nil
}

func validateKeywordsHeader(name, value string) error {
	pos, err := skipCFWS(value, 0)
	if err != nil || pos == len(value) {
		return fmt.Errorf("%w: %s: empty keyword list", ErrInvalidHeaderValue, name)
	}

	for {
		pos, err = consumePhrase(value, pos)
		if err != nil {
			return fmt.Errorf("%w: %s: invalid keyword list", ErrInvalidHeaderValue, name)
		}
		pos, err = skipCFWS(value, pos)
		if err != nil {
			return fmt.Errorf("%w: %s: invalid keyword list", ErrInvalidHeaderValue, name)
		}
		if pos == len(value) {
			return nil
		}
		if value[pos] != ',' {
			return fmt.Errorf("%w: %s: invalid keyword list", ErrInvalidHeaderValue, name)
		}
		pos++
		pos, err = skipCFWS(value, pos)
		if err != nil || pos == len(value) {
			return fmt.Errorf("%w: %s: invalid keyword list", ErrInvalidHeaderValue, name)
		}
	}
}

func validateReturnPathHeader(name, value string) error {
	pos, err := skipCFWS(value, 0)
	if err != nil {
		return fmt.Errorf("%w: %s: invalid path", ErrInvalidHeaderValue, name)
	}
	if pos >= len(value) || value[pos] != '<' {
		return fmt.Errorf("%w: %s: invalid path", ErrInvalidHeaderValue, name)
	}

	pos++
	next, err := skipCFWS(value, pos)
	if err != nil {
		return fmt.Errorf("%w: %s: invalid path", ErrInvalidHeaderValue, name)
	}
	if next < len(value) && value[next] == '>' {
		pos, err = skipCFWS(value, next+1)
		if err != nil || pos != len(value) {
			return fmt.Errorf("%w: %s: invalid path", ErrInvalidHeaderValue, name)
		}
		return nil
	}

	pos, err = consumeAddrSpec(value, pos)
	if err != nil || pos >= len(value) || value[pos] != '>' {
		return fmt.Errorf("%w: %s: invalid path", ErrInvalidHeaderValue, name)
	}
	pos, err = skipCFWS(value, pos+1)
	if err != nil || pos != len(value) {
		return fmt.Errorf("%w: %s: invalid path", ErrInvalidHeaderValue, name)
	}

	return nil
}

func findTopLevelSemicolon(value string) (int, error) {
	commentDepth := 0
	inQuote := false

	for i := 0; i < len(value); i++ {
		switch {
		case commentDepth > 0:
			switch value[i] {
			case '(':
				commentDepth++
			case ')':
				commentDepth--
			case '\\':
				i++
				if i >= len(value) || value[i] == '\r' || value[i] == '\n' || value[i] == 0 {
					return -1, ErrInvalidHeaderValue
				}
			case '\r', '\n':
				return -1, ErrInvalidLineEnding
			}
		case inQuote:
			switch value[i] {
			case '\\':
				i++
				if i >= len(value) || value[i] == '\r' || value[i] == '\n' || value[i] == 0 {
					return -1, ErrInvalidHeaderValue
				}
			case '"':
				inQuote = false
			case '\r', '\n':
				return -1, ErrInvalidLineEnding
			}
		default:
			switch value[i] {
			case '(':
				commentDepth = 1
			case '"':
				inQuote = true
			case ';':
				return i, nil
			case '\r', '\n':
				return -1, ErrInvalidLineEnding
			}
		}
	}

	if commentDepth != 0 || inQuote {
		return -1, ErrInvalidHeaderValue
	}

	return -1, ErrInvalidHeaderValue
}

func validateReceivedHeader(name, value string) error {
	semi, err := findTopLevelSemicolon(value)
	if err != nil {
		return fmt.Errorf("%w: %s: invalid received field", ErrInvalidHeaderValue, name)
	}
	datePart := strings.TrimSpace(value[semi+1:])
	if datePart == "" {
		return fmt.Errorf("%w: %s: missing date-time", ErrInvalidHeaderValue, name)
	}
	if _, err := mail.ParseDate(datePart); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrInvalidHeaderValue, name, err)
	}
	return nil
}

func isTraceHeader(name string) bool {
	return name == "return-path" || name == "received"
}

func isResentHeader(name string) bool {
	switch name {
	case "resent-date", "resent-from", "resent-sender", "resent-to", "resent-cc", "resent-bcc", "resent-message-id":
		return true
	default:
		return false
	}
}

func validateResentBlock(block map[string]Header) error {
	if len(block) == 0 {
		return nil
	}
	if _, ok := block["resent-date"]; !ok {
		return fmt.Errorf("%w: resent block missing Resent-Date", ErrInvalidHeaderValue)
	}
	resentFrom, ok := block["resent-from"]
	if !ok {
		return fmt.Errorf("%w: resent block missing Resent-From", ErrInvalidHeaderValue)
	}

	parsed, err := mail.ParseAddressList(resentFrom.Value)
	if err != nil {
		return fmt.Errorf("%w: Resent-From: %w", ErrInvalidHeaderValue, err)
	}
	if len(parsed) > 1 {
		if _, ok := block["resent-sender"]; !ok {
			return fmt.Errorf("%w: multiple Resent-From addresses require Resent-Sender", ErrInvalidHeaderValue)
		}
	}

	return nil
}

// Validate validates headers according to RFC 5322 requirements.
// It checks for required headers, single-occurrence constraints, and line length limits.
func (h *Headers) Validate() error {
	var headers Headers
	if h != nil {
		headers = *h
	}

	if err := validateHeaderBlock(headers); err != nil {
		return err
	}

	counts := make(map[string]int, len(headers))
	resentBlock := make(map[string]Header)
	seenRegular := false
	seenResent := false
	seenReceived := false
	for _, hdr := range headers {
		canonicalName := strings.ToLower(hdr.Name)
		counts[canonicalName]++
		if canonicalName == "resent-reply-to" {
			return fmt.Errorf("%w: Resent-Reply-To is obsolete and must not be generated", ErrInvalidHeaderValue)
		}

		switch {
		case isTraceHeader(canonicalName):
			if len(resentBlock) > 0 {
				if err := validateResentBlock(resentBlock); err != nil {
					return err
				}
				clear(resentBlock)
			}
			if seenRegular || seenResent {
				return fmt.Errorf("%w: %s must be prepended before regular headers", ErrInvalidHeaderValue, hdr.Name)
			}
			if canonicalName == "return-path" && seenReceived {
				return fmt.Errorf("%w: Return-Path must precede Received headers", ErrInvalidHeaderValue)
			}
		case isResentHeader(canonicalName):
			if seenRegular {
				return fmt.Errorf("%w: %s must be prepended before regular headers", ErrInvalidHeaderValue, hdr.Name)
			}
			seenResent = true
			if _, exists := resentBlock[canonicalName]; exists {
				if err := validateResentBlock(resentBlock); err != nil {
					return err
				}
				clear(resentBlock)
			}
			resentBlock[canonicalName] = hdr
		default:
			if len(resentBlock) > 0 {
				if err := validateResentBlock(resentBlock); err != nil {
					return err
				}
				clear(resentBlock)
			}
			seenRegular = true
		}

		switch canonicalName {
		case "date":
			if _, err := mail.ParseDate(hdr.Value); err != nil {
				return fmt.Errorf("%w: Date: %w", ErrInvalidHeaderValue, err)
			}
		case "message-id", "resent-message-id":
			if err := validateMessageIDHeader(hdr.Name, hdr.Value); err != nil {
				return err
			}
		case "in-reply-to", "references":
			if err := validateMessageIDListHeader(hdr.Name, hdr.Value); err != nil {
				return err
			}
		case "from", "reply-to", "to", "cc":
			if err := validateAddressListHeader(hdr.Name, hdr.Value, false); err != nil {
				return err
			}
		case "resent-from", "resent-to", "resent-cc":
			if err := validateAddressListHeader(hdr.Name, hdr.Value, false); err != nil {
				return err
			}
		case "bcc":
			if err := validateAddressListHeader(hdr.Name, hdr.Value, true); err != nil {
				return err
			}
		case "resent-bcc":
			if err := validateAddressListHeader(hdr.Name, hdr.Value, true); err != nil {
				return err
			}
		case "sender":
			if err := validateSingleMailboxHeader(hdr.Name, hdr.Value); err != nil {
				return err
			}
		case "resent-sender":
			if err := validateSingleMailboxHeader(hdr.Name, hdr.Value); err != nil {
				return err
			}
		case "keywords":
			if err := validateKeywordsHeader(hdr.Name, hdr.Value); err != nil {
				return err
			}
		case "return-path":
			if err := validateReturnPathHeader(hdr.Name, hdr.Value); err != nil {
				return err
			}
		case "received":
			if err := validateReceivedHeader(hdr.Name, hdr.Value); err != nil {
				return err
			}
		}

		if canonicalName == "received" {
			seenReceived = true
		}
	}

	if len(resentBlock) > 0 {
		if err := validateResentBlock(resentBlock); err != nil {
			return err
		}
	}

	if counts["date"] == 0 {
		return ErrMissingDateHeader
	}

	if counts["from"] == 0 {
		return ErrMissingFromHeader
	}

	for name := range singleOccurrenceHeaders {
		if counts[name] > 1 {
			return ErrDuplicateSingleHeader
		}
	}

	parsedFrom, err := mail.ParseAddressList(h.Get("From"))
	if err != nil {
		return fmt.Errorf("%w: From: %w", ErrInvalidHeaderValue, err)
	}
	if len(parsedFrom) > 1 && counts["sender"] == 0 {
		return ErrMultipleFromNoSender
	}

	return nil
}

// Content represents the message content (headers + body).
type Content struct {
	Headers  Headers                 `json:"headers"`
	Body     []byte                  `json:"body,omitempty"`
	Encoding ContentTransferEncoding `json:"encoding"`
	Charset  string                  `json:"charset,omitempty"`
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
	// The FOR clause should contain exactly one recipient path
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
func (t *TraceField) String() string {
	if t == nil {
		return ""
	}
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

	// WITH clause (optional) - protocol identifier
	if t.With != "" {
		parts = append(parts, "with "+t.With)
	}

	// ID clause (optional)
	if t.ID != "" {
		parts = append(parts, "id "+t.ID)
	}

	// FOR clause (optional) - should contain exactly one path
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

// A Mail object contains an envelope (transmitted via SMTP commands)
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
}

// RequiresSMTPUTF8 determines if this mail requires the SMTPUTF8 extension.
// Returns true if any envelope address or header contains non-ASCII characters.
func (m *Mail) RequiresSMTPUTF8() bool {
	// Check explicit flag first
	if m.Envelope.SMTPUTF8 {
		return true
	}

	// Check envelope addresses
	if ravenio.ContainsNonASCII(m.Envelope.From.Mailbox.LocalPart) ||
		ravenio.ContainsNonASCII(m.Envelope.From.Mailbox.Domain) {
		return true
	}
	for _, rcpt := range m.Envelope.To {
		if ravenio.ContainsNonASCII(rcpt.Address.Mailbox.LocalPart) ||
			ravenio.ContainsNonASCII(rcpt.Address.Mailbox.Domain) {
			return true
		}
	}

	// Check headers for non-ASCII content
	for _, h := range m.Content.Headers {
		if ravenio.ContainsNonASCII(h.Value) {
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
// The SMTP server making final delivery should insert this header
// at the beginning of the mail data. This preserves the reverse-path
// from MAIL FROM for bounce messages.
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

	// Validate body line lengths and line endings
	if len(c.Body) > 0 {
		for i := 0; i < len(c.Body); i++ {
			switch c.Body[i] {
			case '\r':
				if i+1 >= len(c.Body) || c.Body[i+1] != '\n' {
					return ErrInvalidLineEnding
				}
			case '\n':
				if i == 0 || c.Body[i-1] != '\r' {
					return ErrInvalidLineEnding
				}
			}
		}

		lineStart := 0
		for i := 0; i < len(c.Body); i++ {
			if c.Body[i] == '\n' {
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

// ToMIME parses the content body into a MIMEPart tree using the current headers.
//
// Multipart content is parsed recursively. For single-part content, the returned
// MIMEPart carries the decoded media type metadata and the original wire body.
func (c *Content) ToMIME() (*MIMEPart, error) {
	return parseMIME(&c.Headers, c.Body)
}

// FromMIME replaces the content body with the serialized representation of part.
//
// Multipart trees are serialized with their boundaries preserved. Encoding and
// Charset are updated from the supplied part, defaulting the encoding to 7bit
// when the part does not specify one.
func (c *Content) FromMIME(part *MIMEPart) error {
	if part == nil {
		return errors.New("mime part is required")
	}
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
		c.Encoding = Encoding7Bit
	}
	c.Charset = part.Charset
	return nil
}

// FromRaw parses raw message data and populates Headers and Body fields.
// This also sets the Encoding field based on Content-Transfer-Encoding header,
// defaulting to "7bit" if not specified.
func (c *Content) FromRaw(data []byte) {
	c.Headers, c.Body = parseRawContent(data)

	cte := c.Headers.Get("Content-Transfer-Encoding")
	if cte != "" {
		c.Encoding = ContentTransferEncoding(strings.ToLower(cte))
	} else {
		c.Encoding = Encoding7Bit
	}

	// Set charset from Content-Type header if present
	contentType := c.Headers.Get("Content-Type")
	if contentType != "" {
		// Simple charset extraction - look for charset parameter
		if idx := strings.Index(strings.ToLower(contentType), "charset="); idx != -1 {
			charset := contentType[idx+8:]
			// Handle quoted charset values
			if charset != "" && charset[0] == '"' {
				if endQuote := strings.Index(charset[1:], "\""); endQuote != -1 {
					c.Charset = charset[1 : endQuote+1]
				}
			} else {
				// Unquoted - extract until semicolon or end
				if before, _, ok := strings.Cut(charset, ";"); ok {
					c.Charset = strings.TrimSpace(before)
				} else {
					c.Charset = strings.TrimSpace(charset)
				}
			}
		}
	}
}

// ToRaw serializes the Content back to raw RFC 5322 format.
// It reconstructs the message from Headers and Body.
// Header lines are folded to comply with line length limits.
func (c *Content) ToRaw() []byte {
	// Estimate size: headers + blank line + body (with some extra for folding)
	estimatedSize := len(c.Body) + 2 // +2 for CRLF before body
	for _, h := range c.Headers {
		estimatedSize += len(h.Name) + 2 + len(h.Value) + 10 // Extra for potential folding
	}

	buf := make([]byte, 0, estimatedSize)

	// Write headers with folding
	for _, h := range c.Headers {
		headerLine := FoldHeader(h.Name, h.Value)
		buf = append(buf, headerLine...)
	}

	// Write blank line separating headers from body
	buf = append(buf, '\r', '\n')

	// Write body
	buf = append(buf, c.Body...)

	return buf
}

// FoldHeader folds a header line.
// Lines MUST be no more than 998 characters, SHOULD be no more than 78.
// Folding is done by inserting CRLF before whitespace.
func FoldHeader(name, value string) []byte {
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

// parseRawContent parses raw message data into headers and body.
// The header section is separated from the body by an empty line.
// Both CRLF (RFC 5322) and bare-LF (lenient fallback) separators are accepted.
func parseRawContent(data []byte) (Headers, []byte) {
	dataLen := len(data)

	// Find the header/body separator: CRLF CRLF (RFC 5322) or bare LF LF (lenient).
	// headerEnd points to the first byte of the terminating line-ending sequence.
	var headerEnd int
	var lfOnly bool // true when a bare-LF separator was used

	for i := 0; i < dataLen-3; i++ {
		if data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n' {
			headerEnd = i + 2 // points to the '\r' of the second CRLF
			break
		}
	}

	// Fallback: accept bare-LF separator (common in messages piped through Unix tools).
	if headerEnd == 0 && dataLen >= 2 {
		for i := 0; i < dataLen-1; i++ {
			if data[i] == '\n' && data[i+1] == '\n' {
				headerEnd = i + 1 // points to the second bare LF
				lfOnly = true
				break
			}
		}
	}

	// No separator found: treat entire input as body (malformed message).
	if headerEnd == 0 {
		return nil, data
	}

	// Parse headers from bytes [0, headerEnd).
	// Triggered on '\n'; an optional preceding '\r' is stripped, so both
	// CRLF and bare-LF line endings are handled uniformly.
	estimatedHeaders := max(headerEnd/50, 8)
	headers := make(Headers, 0, estimatedHeaders)

	var currentName, currentValue string
	lineStart := 0

	for i := 0; i < headerEnd; i++ {
		if data[i] != '\n' {
			continue
		}
		// Determine printable end of line (strip trailing CR if present).
		lineEnd := i
		if lineEnd > lineStart && data[lineEnd-1] == '\r' {
			lineEnd--
		}
		line := string(data[lineStart:lineEnd])
		lineStart = i + 1

		if line == "" {
			continue
		}

		// Continuation line (folded header)?
		if line[0] == ' ' || line[0] == '\t' {
			if currentName != "" {
				currentValue += " " + strings.TrimSpace(line)
			}
			continue
		}

		// Flush the previous header field.
		if currentName != "" {
			headers = append(headers, Header{Name: currentName, Value: currentValue})
		}

		// Parse "Field-Name: field-value".
		if name, value, found := strings.Cut(line, ":"); found {
			currentName = strings.TrimSpace(name)
			currentValue = strings.TrimSpace(value)
		} else {
			// Malformed line (no colon) — drop it.
			currentName = ""
			currentValue = ""
		}
	}

	// Flush the last header field.
	if currentName != "" {
		headers = append(headers, Header{Name: currentName, Value: currentValue})
	}

	// Body immediately follows the separator.
	// CRLF separator: skip 2 bytes (\r\n); bare-LF separator: skip 1 byte (\n).
	bodyStart := headerEnd + 2
	if lfOnly {
		bodyStart = headerEnd + 1
	}
	var body []byte
	if bodyStart < dataLen {
		body = data[bodyStart:]
	}

	return headers, body
}

// Extension represents an SMTP extension advertised via EHLO response.
type Extension string

const (
	Ext8BitMIME            Extension = "8BITMIME"
	ExtPipelining          Extension = "PIPELINING"
	ExtSMTPUTF8            Extension = "SMTPUTF8"
	ExtSTARTTLS            Extension = "STARTTLS"
	ExtSize                Extension = "SIZE"
	ExtDSN                 Extension = "DSN"
	ExtAuth                Extension = "AUTH"
	ExtChunking            Extension = "CHUNKING"
	ExtBinaryMIME          Extension = "BINARYMIME"
	ExtEnhancedStatusCodes Extension = "ENHANCEDSTATUSCODES"
	ExtRequireTLS          Extension = "REQUIRETLS"
	ExtDeliverBy           Extension = "DELIVERBY"
)
