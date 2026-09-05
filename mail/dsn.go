package mail

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// RFC 3461 implementation limits, including each keyword and equals sign.
const (
	MaxDSNEnvelopeIDLength           = 100
	MaxDSNOriginalRecipientLength    = 500
	dsnEnvelopeIDPrefixLength        = len("ENVID=")
	dsnOriginalRecipientPrefixLength = len("ORCPT=")
)

// NormalizeDSNReturn validates RET and returns its canonical uppercase form.
func NormalizeDSNReturn(value string) (string, error) {
	if strings.ContainsAny(value, "\r\n") {
		return "", errors.New("RET contains a line break")
	}
	value = strings.ToUpper(value)
	if value != "FULL" && value != "HDRS" {
		return "", errors.New("RET must be FULL or HDRS")
	}
	return value, nil
}

// NormalizeDSNNotify validates NOTIFY values and returns canonical uppercase
// forms. NEVER is valid only when it is the sole value.
func NormalizeDSNNotify(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, errors.New("NOTIFY value is empty")
	}
	normalized := make([]string, 0, len(values))
	never := false
	for _, value := range values {
		if value == "" || strings.ContainsAny(value, "\r\n") {
			return nil, errors.New("invalid NOTIFY value")
		}
		value = strings.ToUpper(value)
		switch value {
		case "NEVER", "SUCCESS", "FAILURE", "DELAY":
		default:
			return nil, fmt.Errorf("invalid NOTIFY value %q", value)
		}
		never = never || value == "NEVER"
		normalized = append(normalized, value)
	}
	if never && len(normalized) != 1 {
		return nil, errors.New("NOTIFY NEVER must appear alone")
	}
	return normalized, nil
}

// ParseDSNXText validates and decodes RFC 3461 xtext. Hexadecimal digits in
// escape sequences must be uppercase as required by the RFC grammar.
func ParseDSNXText(wire string) (DSNXText, error) {
	decoded := make([]byte, 0, len(wire))
	for i := 0; i < len(wire); {
		b := wire[i]
		if b == '+' {
			if i+2 >= len(wire) || !isUpperHex(wire[i+1]) || !isUpperHex(wire[i+2]) {
				return DSNXText{}, errors.New("invalid xtext escape")
			}
			decoded = append(decoded, fromHex(wire[i+1])<<4|fromHex(wire[i+2]))
			i += 3
			continue
		}
		if b < '!' || b > '~' || b == '=' {
			return DSNXText{}, errors.New("invalid xtext character")
		}
		decoded = append(decoded, b)
		i++
	}
	return DSNXText{Wire: wire, Decoded: string(decoded)}, nil
}

// EncodeDSNXText encodes bytes that cannot appear literally in RFC 3461 xtext.
func EncodeDSNXText(decoded string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(decoded))
	for i := 0; i < len(decoded); i++ {
		c := decoded[i]
		if c >= '!' && c <= '~' && c != '+' && c != '=' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('+')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return b.String()
}

// ParseDSNEnvelopeID parses and validates an ENVID parameter value.
func ParseDSNEnvelopeID(wire string) (DSNXText, error) {
	if wire == "" {
		return DSNXText{}, errors.New("ENVID value is empty")
	}
	if len(wire)+dsnEnvelopeIDPrefixLength > MaxDSNEnvelopeIDLength {
		return DSNXText{}, fmt.Errorf("ENVID exceeds %d characters", MaxDSNEnvelopeIDLength)
	}
	value, err := ParseDSNXText(wire)
	if err != nil {
		return DSNXText{}, fmt.Errorf("invalid ENVID: %w", err)
	}
	if !isPrintableASCII(value.Decoded) {
		return DSNXText{}, errors.New("invalid ENVID decoded value")
	}
	return value, nil
}

// FormatDSNEnvelopeID validates a structured ENVID and returns its wire form.
// If Wire is supplied it is preserved exactly; otherwise Decoded is encoded.
func FormatDSNEnvelopeID(value DSNXText) (string, error) {
	if value.Wire != "" {
		parsed, err := ParseDSNEnvelopeID(value.Wire)
		if err != nil {
			return "", err
		}
		if value.Decoded != "" && value.Decoded != parsed.Decoded {
			return "", errors.New("ENVID wire and decoded values differ")
		}
		return value.Wire, nil
	}
	if value.Decoded == "" || !isPrintableASCII(value.Decoded) {
		return "", errors.New("invalid ENVID decoded value")
	}
	wire := EncodeDSNXText(value.Decoded)
	if len(wire)+dsnEnvelopeIDPrefixLength > MaxDSNEnvelopeIDLength {
		return "", fmt.Errorf("ENVID exceeds %d characters after xtext encoding", MaxDSNEnvelopeIDLength)
	}
	return wire, nil
}

// ParseDSNOriginalRecipient parses and validates an ORCPT parameter value.
// Native UTF-8 in the utf-8 address type is accepted only for SMTPUTF8 mail.
func ParseDSNOriginalRecipient(wire string, smtpUTF8 bool) (DSNOriginalRecipient, error) {
	if wire == "" {
		return DSNOriginalRecipient{}, errors.New("ORCPT value is empty")
	}
	if len(wire)+dsnOriginalRecipientPrefixLength > MaxDSNOriginalRecipientLength {
		return DSNOriginalRecipient{}, fmt.Errorf("ORCPT exceeds %d characters", MaxDSNOriginalRecipientLength)
	}
	addressType, encodedAddress, ok := strings.Cut(wire, ";")
	if !ok || !isAtom(addressType) {
		return DSNOriginalRecipient{}, errors.New("ORCPT must contain address-type;encoded-address")
	}

	var address DSNXText
	var err error
	if strings.EqualFold(addressType, "utf-8") {
		address, err = parseUTF8ORCPTAddress(encodedAddress, smtpUTF8)
	} else {
		address, err = ParseDSNXText(encodedAddress)
		if err == nil && !isPrintableASCII(address.Decoded) {
			err = errors.New("ORCPT decoded address is not printable US-ASCII")
		}
	}
	if err != nil {
		return DSNOriginalRecipient{}, fmt.Errorf("invalid ORCPT address: %w", err)
	}

	return DSNOriginalRecipient{
		Wire:        wire,
		AddressType: addressType,
		Address:     address,
	}, nil
}

// FormatDSNOriginalRecipient validates a structured ORCPT and returns its wire
// form. If Wire is supplied it is preserved exactly.
func FormatDSNOriginalRecipient(value DSNOriginalRecipient, smtpUTF8 bool) (string, error) {
	if value.Wire != "" {
		parsed, err := ParseDSNOriginalRecipient(value.Wire, smtpUTF8)
		if err != nil {
			return "", err
		}
		if value.AddressType != "" && value.AddressType != parsed.AddressType {
			return "", errors.New("ORCPT wire and address type differ")
		}
		if value.Address.Decoded != "" && value.Address.Decoded != parsed.Address.Decoded {
			return "", errors.New("ORCPT wire and decoded address differ")
		}
		return value.Wire, nil
	}
	if !isAtom(value.AddressType) {
		return "", errors.New("invalid ORCPT address type")
	}

	var encoded string
	var err error
	if strings.EqualFold(value.AddressType, "utf-8") {
		encoded, err = encodeUTF8ORCPTAddress(value.Address.Decoded, smtpUTF8)
	} else {
		if value.Address.Decoded == "" || !isPrintableASCII(value.Address.Decoded) {
			return "", errors.New("invalid ORCPT decoded address")
		}
		encoded = EncodeDSNXText(value.Address.Decoded)
	}
	if err != nil {
		return "", err
	}
	wire := value.AddressType + ";" + encoded
	if len(wire)+dsnOriginalRecipientPrefixLength > MaxDSNOriginalRecipientLength {
		return "", fmt.Errorf("ORCPT exceeds %d characters after encoding", MaxDSNOriginalRecipientLength)
	}
	return wire, nil
}

func parseUTF8ORCPTAddress(wire string, smtpUTF8 bool) (DSNXText, error) {
	if wire == "" {
		return DSNXText{}, errors.New("UTF-8 address is empty")
	}
	decoded := make([]byte, 0, len(wire))
	for i := 0; i < len(wire); {
		if wire[i] >= utf8.RuneSelf {
			if !smtpUTF8 {
				return DSNXText{}, errors.New("native UTF-8 requires SMTPUTF8")
			}
			r, size := utf8.DecodeRuneInString(wire[i:])
			if r == utf8.RuneError && size == 1 {
				return DSNXText{}, errors.New("invalid UTF-8")
			}
			decoded = append(decoded, wire[i:i+size]...)
			i += size
			continue
		}
		if wire[i] == '+' {
			if i+2 >= len(wire) || !isUpperHex(wire[i+1]) || !isUpperHex(wire[i+2]) {
				return DSNXText{}, errors.New("invalid xtext escape")
			}
			decoded = append(decoded, fromHex(wire[i+1])<<4|fromHex(wire[i+2]))
			i += 3
			continue
		}
		if strings.HasPrefix(wire[i:], `\x{`) {
			end := strings.IndexByte(wire[i+3:], '}')
			if end < 0 {
				return DSNXText{}, errors.New("invalid unitext escape")
			}
			end += i + 3
			hexPoint := wire[i+3 : end]
			if len(hexPoint) < 2 || len(hexPoint) > 6 || !isUpperHexString(hexPoint) {
				return DSNXText{}, errors.New("invalid unitext code point")
			}
			point, parseErr := strconv.ParseUint(hexPoint, 16, 32)
			if parseErr != nil || !utf8.ValidRune(rune(point)) {
				return DSNXText{}, errors.New("invalid unitext code point")
			}
			decoded = utf8.AppendRune(decoded, rune(point))
			i = end + 1
			continue
		}
		if !isQChar(wire[i]) {
			return DSNXText{}, errors.New("invalid UTF-8 ORCPT character")
		}
		decoded = append(decoded, wire[i])
		i++
	}
	if !utf8.Valid(decoded) {
		return DSNXText{}, errors.New("invalid UTF-8 address")
	}
	return DSNXText{Wire: wire, Decoded: string(decoded)}, nil
}

func encodeUTF8ORCPTAddress(address string, smtpUTF8 bool) (string, error) {
	if address == "" || !utf8.ValidString(address) || strings.ContainsAny(address, "\r\n") {
		return "", errors.New("invalid UTF-8 ORCPT address")
	}
	mailbox, err := ParseAddress(address)
	if err != nil || mailbox.DisplayName != "" || mailbox.LocalPart == "" || mailbox.Domain == "" {
		return "", errors.New("invalid UTF-8 mailbox")
	}
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for _, r := range address {
		if r < utf8.RuneSelf && isQChar(byte(r)) {
			b.WriteRune(r)
			continue
		}
		if r >= utf8.RuneSelf && smtpUTF8 {
			b.WriteRune(r)
			continue
		}
		b.WriteString(`\x{`)
		if r <= 0xff {
			b.WriteByte(hex[byte(r)>>4])
			b.WriteByte(hex[byte(r)&0x0f])
		} else {
			b.WriteString(strings.ToUpper(strconv.FormatInt(int64(r), 16)))
		}
		b.WriteByte('}')
	}
	return b.String(), nil
}

func isPrintableASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '\t' && (s[i] < ' ' || s[i] > '~') {
			return false
		}
	}
	return true
}

func isAtom(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		if !strings.ContainsRune("!#$%&'*+-/?^_`{|}~", rune(c)) {
			return false
		}
	}
	return true
}

func isQChar(b byte) bool {
	return b >= '!' && b <= '~' && b != '\\' && b != '+' && b != '='
}

func isUpperHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isUpperHex(s[i]) {
			return false
		}
	}
	return true
}

func isUpperHex(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'F'
}

func fromHex(b byte) byte {
	if b <= '9' {
		return b - '0'
	}
	return b - 'A' + 10
}
