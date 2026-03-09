package server

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// Address validation errors.
var (
	ErrAddressEmpty        = errors.New("address is empty")
	ErrAddressMissingAt    = errors.New("address must contain @")
	ErrAddressMultipleAt   = errors.New("address contains multiple @")
	ErrLocalPartEmpty      = errors.New("local-part is empty")
	ErrLocalPartTooLong    = errors.New("local-part exceeds 64 characters")
	ErrDomainEmpty         = errors.New("domain is empty")
	ErrDomainTooLong       = errors.New("domain exceeds 255 characters")
	ErrAddressTooLong      = errors.New("address exceeds 254 characters")
	ErrInvalidUTF8         = errors.New("address contains invalid UTF-8")
	ErrNonASCIIWithoutUTF8 = errors.New("non-ASCII characters require SMTPUTF8")
	ErrInvalidLocalPart    = errors.New("invalid local-part syntax")
	ErrInvalidDomain       = errors.New("invalid domain syntax")
	ErrInvalidIPLiteral    = errors.New("invalid IP address literal")
	ErrPathMissingBrackets = errors.New("path must be enclosed in angle brackets")
)

// RFC 5321 limits.
const (
	maxLocalPartLength = 64
	maxDomainLength    = 255
	maxAddressLength   = 254 // RFC 5321 section 4.5.3.1.3
)

// ParsedAddress represents a parsed and validated email address.
type ParsedAddress struct {
	LocalPart string // The local-part (before @)
	Domain    string // The domain (after @), ASCII-encoded (punycode if needed)
	Raw       string // The original address as provided
}

// String returns the normalized address (local-part@ascii-domain).
func (a *ParsedAddress) String() string {
	if a.LocalPart == "" && a.Domain == "" {
		return ""
	}
	return a.LocalPart + "@" + a.Domain
}

// parsePath parses and validates an SMTP path (e.g., "<user@domain> PARAMS").
// Returns the parsed address, remaining parameters, and any error.
// If allowUTF8 is false, non-ASCII characters are rejected.
func parsePath(s string, allowUTF8 bool) (*ParsedAddress, string, error) {
	s = strings.TrimSpace(s)

	if s == "" {
		return nil, "", ErrAddressEmpty
	}

	// Handle null path <>
	if s == "<>" {
		return &ParsedAddress{}, "", nil
	}

	// Must start with <
	if s[0] != '<' {
		return nil, "", ErrPathMissingBrackets
	}

	// Find closing >
	idx := strings.Index(s, ">")
	if idx == -1 {
		return nil, "", ErrPathMissingBrackets
	}

	address := s[1:idx]
	params := strings.TrimSpace(s[idx+1:])

	// Parse and validate the address
	parsed, err := parseAddress(address, allowUTF8)
	if err != nil {
		return nil, "", fmt.Errorf("parsing SMTP path address %q: %w", address, err)
	}

	return parsed, params, nil
}

// parseAddress parses and validates an email address.
// If allowUTF8 is false, non-ASCII characters are rejected.
func parseAddress(addr string, allowUTF8 bool) (*ParsedAddress, error) {
	if addr == "" {
		return nil, ErrAddressEmpty
	}

	// Validate UTF-8 encoding
	if !utf8.ValidString(addr) {
		return nil, ErrInvalidUTF8
	}

	// Check for non-ASCII when SMTPUTF8 not enabled
	if !allowUTF8 && !isASCII(addr) {
		return nil, ErrNonASCIIWithoutUTF8
	}

	// RFC 5321: address length limit
	if len(addr) > maxAddressLength {
		return nil, ErrAddressTooLong
	}

	// Split into local-part and domain
	atIdx := strings.LastIndex(addr, "@")
	if atIdx == -1 {
		return nil, ErrAddressMissingAt
	}

	// Check for multiple @ (only valid inside quoted local-part)
	localPart := addr[:atIdx]
	domain := addr[atIdx+1:]

	// Validate local-part
	if err := validateLocalPart(localPart, allowUTF8); err != nil {
		return nil, fmt.Errorf("validating local-part %q: %w", localPart, err)
	}

	// Validate and normalize domain
	normalizedDomain, err := validateAndNormalizeDomain(domain, allowUTF8)
	if err != nil {
		return nil, fmt.Errorf("validating domain %q: %w", domain, err)
	}

	return &ParsedAddress{
		LocalPart: localPart,
		Domain:    normalizedDomain,
		Raw:       addr,
	}, nil
}

// validateLocalPart validates the local-part of an email address per RFC 5321.
func validateLocalPart(local string, allowUTF8 bool) error {
	if local == "" {
		return ErrLocalPartEmpty
	}

	if len(local) > maxLocalPartLength {
		return ErrLocalPartTooLong
	}

	// Check if quoted
	if len(local) >= 2 && local[0] == '"' && local[len(local)-1] == '"' {
		return validateQuotedLocalPart(local[1:len(local)-1], allowUTF8)
	}

	return validateDotAtom(local, allowUTF8)
}

// validateQuotedLocalPart validates a quoted-string local-part.
// Inside quotes, most printable ASCII is allowed, with escaping via backslash.
func validateQuotedLocalPart(content string, allowUTF8 bool) error {
	i := 0
	for i < len(content) {
		r, size := utf8.DecodeRuneInString(content[i:])
		if r == utf8.RuneError && size == 1 {
			return ErrInvalidUTF8
		}

		if r == '\\' {
			// Escape sequence - next char must exist and be printable
			i += size
			if i >= len(content) {
				return ErrInvalidLocalPart
			}
			next, nextSize := utf8.DecodeRuneInString(content[i:])
			if next == utf8.RuneError && nextSize == 1 {
				return ErrInvalidUTF8
			}
			if !allowUTF8 && next > 127 {
				return ErrNonASCIIWithoutUTF8
			}
			i += nextSize
			continue
		}

		// Check if character is allowed
		if !allowUTF8 && r > 127 {
			return ErrNonASCIIWithoutUTF8
		}

		// In quoted string, most printable chars allowed except unescaped " and \
		if r < 32 || r == 127 {
			// Control characters not allowed
			return ErrInvalidLocalPart
		}

		i += size
	}

	return nil
}

// validateDotAtom validates a dot-atom local-part (unquoted).
// RFC 5321 atext: alphanumeric + !#$%&'*+-/=?^_`{|}~
func validateDotAtom(local string, allowUTF8 bool) error {
	if local == "" {
		return ErrLocalPartEmpty
	}

	// Cannot start or end with dot
	if local[0] == '.' || local[len(local)-1] == '.' {
		return ErrInvalidLocalPart
	}

	// Cannot have consecutive dots
	if strings.Contains(local, "..") {
		return ErrInvalidLocalPart
	}

	for i := 0; i < len(local); {
		r, size := utf8.DecodeRuneInString(local[i:])
		if r == utf8.RuneError && size == 1 {
			return ErrInvalidUTF8
		}

		if r > 127 {
			// Non-ASCII: only allowed with SMTPUTF8
			if !allowUTF8 {
				return ErrNonASCIIWithoutUTF8
			}
			// RFC 6531: UTF8-non-ascii
			i += size
			continue
		}

		// ASCII: must be atext or dot
		if !isAtext(byte(r)) && r != '.' {
			return ErrInvalidLocalPart
		}

		i += size
	}

	return nil
}

// isAtext checks if a byte is a valid atext character per RFC 5321.
// atext = ALPHA / DIGIT / "!" / "#" / "$" / "%" / "&" / "'" / "*" /
//
//	"+" / "-" / "/" / "=" / "?" / "^" / "_" / "`" / "{" / "|" / "}" / "~"
func isAtext(c byte) bool {
	if c >= 'a' && c <= 'z' {
		return true
	}
	if c >= 'A' && c <= 'Z' {
		return true
	}
	if c >= '0' && c <= '9' {
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~':
		return true
	}
	return false
}

// validateAndNormalizeDomain validates the domain and converts IDN to ASCII (punycode).
func validateAndNormalizeDomain(domain string, allowUTF8 bool) (string, error) {
	if domain == "" {
		return "", ErrDomainEmpty
	}

	// Handle IP address literals [IPv4] or [IPv6:...]
	if len(domain) >= 2 && domain[0] == '[' && domain[len(domain)-1] == ']' {
		return validateIPLiteral(domain)
	}

	// Check for non-ASCII
	hasNonASCII := !isASCII(domain)

	if hasNonASCII {
		if !allowUTF8 {
			return "", ErrNonASCIIWithoutUTF8
		}

		// Convert internationalized domain to ASCII (punycode)
		// Use IDNA2008 with transitional processing disabled for email
		profile := idna.New(
			idna.MapForLookup(),
			idna.ValidateLabels(true),
			idna.CheckHyphens(true),
			idna.CheckJoiners(true),
			idna.StrictDomainName(true),
		)
		ascii, err := profile.ToASCII(domain)
		if err != nil {
			return "", fmt.Errorf("converting IDN domain %q to ASCII: %w", domain, errors.Join(ErrInvalidDomain, err))
		}
		domain = ascii
	}

	// Validate ASCII domain
	if err := validateASCIIDomain(domain); err != nil {
		return "", fmt.Errorf("validating ASCII domain %q: %w", domain, err)
	}

	return strings.ToLower(domain), nil
}

// validateASCIIDomain validates an ASCII domain name.
func validateASCIIDomain(domain string) error {
	if len(domain) > maxDomainLength {
		return ErrDomainTooLong
	}

	if domain == "" {
		return ErrDomainEmpty
	}

	// Cannot start or end with dot or hyphen
	if domain[0] == '.' || domain[0] == '-' {
		return ErrInvalidDomain
	}
	if domain[len(domain)-1] == '.' || domain[len(domain)-1] == '-' {
		return ErrInvalidDomain
	}

	// Cannot have consecutive dots
	if strings.Contains(domain, "..") {
		return ErrInvalidDomain
	}

	// Validate each label
	labels := strings.Split(domain, ".")
	if len(labels) < 1 {
		return ErrInvalidDomain
	}

	for _, label := range labels {
		if err := validateDomainLabel(label); err != nil {
			return fmt.Errorf("validating domain label %q: %w", label, err)
		}
	}

	return nil
}

// validateDomainLabel validates a single domain label.
func validateDomainLabel(label string) error {
	if label == "" {
		return ErrInvalidDomain
	}

	// RFC 5321: each label max 63 octets
	if len(label) > 63 {
		return ErrInvalidDomain
	}

	// Cannot start or end with hyphen
	if label[0] == '-' || label[len(label)-1] == '-' {
		return ErrInvalidDomain
	}

	// Must be alphanumeric or hyphen
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return ErrInvalidDomain
		}
	}

	return nil
}

// validateIPLiteral validates an IP address literal like [192.168.1.1] or [IPv6:2001:db8::1].
func validateIPLiteral(lit string) (string, error) {
	// Remove brackets
	inner := lit[1 : len(lit)-1]

	// Check for IPv6 prefix
	if strings.HasPrefix(strings.ToUpper(inner), "IPV6:") {
		ipv6 := inner[5:]
		if !isValidIPv6(ipv6) {
			return "", ErrInvalidIPLiteral
		}
		return lit, nil
	}

	// Must be IPv4
	if !isValidIPv4(inner) {
		return "", ErrInvalidIPLiteral
	}

	return lit, nil
}

// isValidIPv4 checks if a string is a valid IPv4 address.
func isValidIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		if part == "" || len(part) > 3 {
			return false
		}
		// No leading zeros except for "0" itself
		if len(part) > 1 && part[0] == '0' {
			return false
		}
		n := 0
		for i := 0; i < len(part); i++ {
			c := part[i]
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}

	return true
}

// isValidIPv6 checks if a string is a valid IPv6 address.
// This is a simplified check - accepts standard and compressed formats.
func isValidIPv6(s string) bool {
	if s == "" {
		return false
	}

	// Count colons and check for ::
	colons := strings.Count(s, ":")
	doubleColon := strings.Contains(s, "::")

	if doubleColon {
		// Can only have one ::
		if strings.Count(s, "::") > 1 {
			return false
		}
		// With ::, we can have fewer than 7 colons
		if colons > 7 {
			return false
		}
	} else {
		// Without ::, must have exactly 7 colons
		if colons != 7 {
			return false
		}
	}

	// Handle :: at start or end
	s = strings.TrimPrefix(s, "::")
	s = strings.TrimSuffix(s, "::")
	if s == "" {
		return true // Just "::" is valid
	}

	// Split and validate each group
	parts := strings.Split(s, ":")
	for _, part := range parts {
		if part == "" {
			continue // Empty from ::
		}
		if len(part) > 4 {
			return false
		}
		for i := 0; i < len(part); i++ {
			c := part[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}

	return true
}

// isASCII checks if a string contains only ASCII characters (0-127).
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}
