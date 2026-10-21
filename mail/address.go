package mail

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// Address parsing and validation errors.
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
	ErrInvalidAddress      = errors.New("invalid email address")
)

// RFC 5321 limits.
const (
	maxLocalPartLength = 64
	maxDomainLength    = 255
	maxAddressLength   = 254 // RFC 5321 section 4.5.3.1.3
)

// ParseAddress parses a single RFC 5322 mailbox into a MailboxAddress.
//
// It accepts both a bare addr-spec ("user@example.com") and a name-addr with a
// display name ("Jane Doe <jane@example.com>", or a quoted/observed phrase).
// Comments and folding white space are permitted, and RFC 2047 encoded-words
// in the display name are decoded. Encoded-words that decode to control
// characters, including CR and LF, are rejected. RFC 6532 UTF-8 addresses are
// permitted.
//
// The domain is normalized: an internationalized domain is converted to its
// ASCII (punycode) form and the result is lowercased. The local-part is stored
// in unquoted semantic form, with obs-local-part words joined by dots; call
// String to serialize it with RFC 5321 quoting when necessary. Groups are not
// accepted; use ParseAddressList for headers that may carry an address-list.
func ParseAddress(addr string) (MailboxAddress, error) {
	mailbox, next, err := parseMailbox(addr, 0)
	if err != nil {
		return MailboxAddress{}, err
	}
	end, err := skipCFWS(addr, next)
	if err != nil || end != len(addr) {
		return MailboxAddress{}, ErrInvalidAddress
	}
	return mailbox, nil
}

// ParseAddressList parses an RFC 5322 address-list (as found in From, To, Cc,
// and similar headers) into a flat list of mailboxes.
//
// Name-addr mailboxes, quoted display names, comments, obsolete phrase syntax,
// and groups are supported. A group contributes its member mailboxes; an empty
// group such as "Undisclosed recipients:;" contributes none. RFC 6532 UTF-8
// addresses are permitted.
func ParseAddressList(value string) ([]MailboxAddress, error) {
	pos, err := skipCFWS(value, 0)
	if err != nil {
		return nil, err
	}
	if pos == len(value) {
		return nil, nil
	}

	// obs-addr-list permits leading commas before the first address. Interior
	// and trailing empty elements are rejected deliberately so a malformed list
	// cannot silently drop or invent recipients.
	for pos < len(value) && value[pos] == ',' {
		pos, err = skipCFWS(value, pos+1)
		if err != nil {
			return nil, err
		}
	}
	if pos == len(value) {
		return nil, ErrInvalidAddress
	}

	var out []MailboxAddress
	for {
		mailboxes, next, err := parseAddress(value, pos)
		if err != nil {
			return nil, err
		}
		out = append(out, mailboxes...)

		next, err = skipCFWS(value, next)
		if err != nil {
			return nil, err
		}
		if next == len(value) {
			return out, nil
		}
		if value[next] != ',' {
			return nil, ErrInvalidAddress
		}

		pos, err = skipCFWS(value, next+1)
		if err != nil {
			return nil, err
		}
		if pos == len(value) || value[pos] == ',' {
			return nil, ErrInvalidAddress
		}
	}
}

// ParsePath parses and validates an SMTP path (RFC 5321 forward-path or
// reverse-path), e.g. "<user@domain> PARAMS" or "<@relay1,@relay2:user@domain>
// PARAMS". It returns the parsed mailbox, any trailing ESMTP parameters, and an
// error.
//
// The null reverse-path "<>" yields a zero MailboxAddress. When allowUTF8 is
// false, non-ASCII characters are rejected.
func ParsePath(s string, allowUTF8 bool) (MailboxAddress, string, error) {
	s = strings.TrimSpace(s)

	if s == "" {
		return MailboxAddress{}, "", ErrAddressEmpty
	}

	// Handle null path <>.
	if s == "<>" {
		return MailboxAddress{}, "", nil
	}

	if s[0] != '<' {
		return MailboxAddress{}, "", ErrPathMissingBrackets
	}

	idx := strings.Index(s, ">")
	if idx == -1 {
		return MailboxAddress{}, "", ErrPathMissingBrackets
	}

	inner := s[1:idx]
	params := strings.TrimSpace(s[idx+1:])

	// Optional source route: A-d-l = At-domain *( "," At-domain ).
	if strings.HasPrefix(inner, "@") {
		colon := findSourceRouteEnd(inner)
		if colon == -1 {
			return MailboxAddress{}, "", fmt.Errorf("parsing SMTP path %q: %w", s, ErrAddressMissingAt)
		}
		if err := validateSourceRoute(inner[:colon], allowUTF8); err != nil {
			return MailboxAddress{}, "", fmt.Errorf("parsing SMTP path %q: %w", s, err)
		}
		inner = inner[colon+1:]
	}

	parsed, err := ParseAddrSpec(inner, allowUTF8)
	if err != nil {
		return MailboxAddress{}, "", fmt.Errorf("parsing SMTP path address %q: %w", inner, err)
	}

	return parsed, params, nil
}

// ParseAddrSpec parses and validates a bare RFC 5321 address (addr-spec), i.e.
// "local-part@domain" without a display name or angle brackets.
//
// This is the strict SMTP form: the local-part is a dot-string or quoted-string,
// the domain is a DNS domain or an address-literal, and the RFC 5321 length
// limits are enforced. Internationalized domains are converted to their ASCII
// (punycode) form and the result is lowercased. The returned local-part is in
// unquoted semantic form; String re-quotes it when required. When allowUTF8 is
// false, non-ASCII characters are rejected (SMTPUTF8 is required to carry
// them).
func ParseAddrSpec(addr string, allowUTF8 bool) (MailboxAddress, error) {
	if addr == "" {
		return MailboxAddress{}, ErrAddressEmpty
	}
	if !utf8.ValidString(addr) {
		return MailboxAddress{}, ErrInvalidUTF8
	}
	if !allowUTF8 && !isASCII(addr) {
		return MailboxAddress{}, ErrNonASCIIWithoutUTF8
	}
	if len(addr) > maxAddressLength {
		return MailboxAddress{}, ErrAddressTooLong
	}

	if addr[0] == '@' {
		return MailboxAddress{}, ErrLocalPartEmpty
	}

	localEnd, err := consumeEnvelopeLocalPart(addr, 0, allowUTF8)
	if err != nil {
		return MailboxAddress{}, err
	}
	if localEnd > maxLocalPartLength {
		return MailboxAddress{}, ErrLocalPartTooLong
	}
	if localEnd >= len(addr) || addr[localEnd] != '@' {
		// If an @ appears later, the local-part itself is malformed rather
		// than the address simply missing its separator.
		if strings.ContainsRune(addr[localEnd:], '@') {
			return MailboxAddress{}, ErrInvalidLocalPart
		}
		return MailboxAddress{}, ErrAddressMissingAt
	}

	localPart := addr[:localEnd]
	if localPart[0] == '"' {
		localPart = unquoteQuotedString(localPart[1 : len(localPart)-1])
	}
	if !validMailboxPart(localPart) {
		return MailboxAddress{}, ErrInvalidLocalPart
	}
	domain := addr[localEnd+1:]

	normalizedDomain, err := validateAndNormalizeDomain(domain, allowUTF8)
	if err != nil {
		return MailboxAddress{}, err
	}

	return MailboxAddress{LocalPart: localPart, Domain: normalizedDomain}, nil
}

// ---------------------------------------------------------------------------
// RFC 5322 address grammar (headers)
// ---------------------------------------------------------------------------

// parseAddress parses a single RFC 5322 address (mailbox or group) at pos and
// returns the mailboxes it contributes and the position after it.
func parseAddress(value string, pos int) ([]MailboxAddress, int, error) {
	start, err := skipCFWS(value, pos)
	if err != nil {
		return nil, 0, err
	}

	if start < len(value) && value[start] == '<' {
		mailbox, next, err := parseAngleAddr(value, start, "")
		if err != nil {
			return nil, 0, err
		}
		return []MailboxAddress{mailbox}, next, nil
	}

	if phraseEnd, ok := consumeAddressPhrase(value, start); ok {
		after, err := skipCFWS(value, phraseEnd)
		if err != nil {
			return nil, 0, err
		}
		if after < len(value) {
			switch value[after] {
			case '<':
				display, err := parseDisplayName(value[start:phraseEnd])
				if err != nil {
					return nil, 0, err
				}
				mailbox, next, err := parseAngleAddr(value, after, display)
				if err != nil {
					return nil, 0, err
				}
				return []MailboxAddress{mailbox}, next, nil
			case ':':
				return parseGroup(value, after)
			}
		}
	}

	mailbox, next, err := parseBareAddrSpec(value, start)
	if err != nil {
		return nil, 0, err
	}
	return []MailboxAddress{mailbox}, next, nil
}

// parseMailbox parses a single RFC 5322 mailbox (name-addr or addr-spec) at pos.
func parseMailbox(value string, pos int) (MailboxAddress, int, error) {
	start, err := skipCFWS(value, pos)
	if err != nil {
		return MailboxAddress{}, 0, err
	}

	if start < len(value) && value[start] == '<' {
		return parseAngleAddr(value, start, "")
	}

	if phraseEnd, ok := consumeAddressPhrase(value, start); ok {
		after, err := skipCFWS(value, phraseEnd)
		if err != nil {
			return MailboxAddress{}, 0, err
		}
		if after < len(value) && value[after] == '<' {
			display, err := parseDisplayName(value[start:phraseEnd])
			if err != nil {
				return MailboxAddress{}, 0, err
			}
			return parseAngleAddr(value, after, display)
		}
	}

	return parseBareAddrSpec(value, start)
}

// parseBareAddrSpec parses an addr-spec in header (RFC 5322) context.
func parseBareAddrSpec(value string, pos int) (MailboxAddress, int, error) {
	local, domain, next, err := consumeHeaderAddrSpec(value, pos)
	if err != nil {
		return MailboxAddress{}, 0, err
	}

	normalized, err := normalizeHeaderDomain(domain)
	if err != nil {
		return MailboxAddress{}, 0, err
	}
	mailbox, err := newHeaderMailbox(local, normalized, "")
	if err != nil {
		return MailboxAddress{}, 0, err
	}
	return mailbox, next, nil
}

// parseAngleAddr parses "[display-name] <addr-spec>" beginning at the '<'.
func parseAngleAddr(value string, pos int, display string) (MailboxAddress, int, error) {
	if pos >= len(value) || value[pos] != '<' {
		return MailboxAddress{}, 0, ErrInvalidAddress
	}

	inner, err := skipCFWS(value, pos+1)
	if err != nil {
		return MailboxAddress{}, 0, err
	}
	local, domain, next, err := consumeHeaderAddrSpec(value, inner)
	if err != nil {
		return MailboxAddress{}, 0, err
	}
	if next >= len(value) || value[next] != '>' {
		return MailboxAddress{}, 0, ErrInvalidAddress
	}

	normalized, err := normalizeHeaderDomain(domain)
	if err != nil {
		return MailboxAddress{}, 0, err
	}

	after, err := skipCFWS(value, next+1)
	if err != nil {
		return MailboxAddress{}, 0, err
	}
	mailbox, err := newHeaderMailbox(local, normalized, display)
	if err != nil {
		return MailboxAddress{}, 0, err
	}
	return mailbox, after, nil
}

// newHeaderMailbox applies the RFC 5321 path length limits to a mailbox parsed
// from an RFC 5322 header. Header parsing still produces an SMTP-like address,
// so an address that cannot be put on the wire is rejected here rather than
// being discovered when the envelope is sent.
func newHeaderMailbox(local, domain, display string) (MailboxAddress, error) {
	if !validMailboxPart(local) || !validMailboxPart(domain) {
		return MailboxAddress{}, ErrInvalidAddress
	}
	if len(encodeLocalPart(local)) > maxLocalPartLength {
		return MailboxAddress{}, ErrLocalPartTooLong
	}
	if len(domain) > maxDomainLength {
		return MailboxAddress{}, ErrDomainTooLong
	}
	if len(encodeLocalPart(local))+1+len(domain) > maxAddressLength {
		return MailboxAddress{}, ErrAddressTooLong
	}
	return MailboxAddress{
		LocalPart:   local,
		Domain:      domain,
		DisplayName: display,
	}, nil
}

// localPartNeedsQuoting reports whether a semantic local-part can be emitted as
// an RFC 5321 dot-string. Empty local-parts and anything outside atext (or
// non-ASCII SMTPUTF8 text) require a quoted-string.
func localPartNeedsQuoting(local string) bool {
	if local == "" {
		return true
	}
	atomStart := 0
	for i := 0; i <= len(local); i++ {
		if i < len(local) && local[i] != '.' {
			if !isAText(local[i]) && local[i] < 128 {
				return true
			}
			continue
		}
		if i == atomStart {
			return true
		}
		atomStart = i + 1
	}
	return false
}

// encodeLocalPart serializes a semantic local-part, quoting and escaping it
// when it is not a valid dot-string.
func encodeLocalPart(local string) string {
	if !localPartNeedsQuoting(local) {
		return local
	}

	var b strings.Builder
	b.Grow(len(local) + 2)
	b.WriteByte('"')
	for i := 0; i < len(local); i++ {
		if local[i] == '\\' || local[i] == '"' {
			b.WriteByte('\\')
		}
		b.WriteByte(local[i])
	}
	b.WriteByte('"')
	return b.String()
}

// parseGroup parses a group whose display-name ends at colonIdx.
func parseGroup(value string, colonIdx int) ([]MailboxAddress, int, error) {
	pos, err := skipCFWS(value, colonIdx+1)
	if err != nil {
		return nil, 0, err
	}

	// group-list may be empty (CFWS).
	if pos < len(value) && value[pos] == ';' {
		next, err := skipCFWS(value, pos+1)
		if err != nil {
			return nil, 0, err
		}
		return nil, next, nil
	}

	var out []MailboxAddress
	for {
		mailbox, next, err := parseMailbox(value, pos)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, mailbox)

		next, err = skipCFWS(value, next)
		if err != nil {
			return nil, 0, err
		}
		if next == len(value) {
			return nil, 0, ErrInvalidAddress
		}

		switch value[next] {
		case ',':
			pos, err = skipCFWS(value, next+1)
			if err != nil {
				return nil, 0, err
			}
			if pos == len(value) {
				return nil, 0, ErrInvalidAddress
			}
		case ';':
			after, err := skipCFWS(value, next+1)
			if err != nil {
				return nil, 0, err
			}
			return out, after, nil
		default:
			return nil, 0, ErrInvalidAddress
		}
	}
}

// consumeAddressPhrase consumes an RFC 5322 phrase (1*word, plus the obsolete
// form that permits "." between words). It reports whether a phrase was present.
func consumeAddressPhrase(value string, pos int) (int, bool) {
	pos, err := skipCFWS(value, pos)
	if err != nil {
		return 0, false
	}

	words := 0
	for pos < len(value) {
		c := value[pos]
		if c != '"' && !isAText(c) && c < 128 {
			// Obsolescent phrase permits a "." between words.
			if c == '.' && words > 0 {
				pos++
				next, err := skipCFWS(value, pos)
				if err != nil {
					return 0, false
				}
				pos = next
				continue
			}
			break
		}

		next, err := consumeWord(value, pos)
		if err != nil {
			return 0, false
		}
		words++
		pos, err = skipCFWS(value, next)
		if err != nil {
			return 0, false
		}
	}

	if words == 0 {
		return 0, false
	}
	return pos, true
}

// parseDisplayName converts a raw RFC 5322 phrase into a display name. Quoted
// words are unquoted, obs-phrase dots are preserved, CFWS runs collapse to a
// single space, and RFC 2047 encoded-words are decoded.
func parseDisplayName(raw string) (string, error) {
	var b strings.Builder
	pos := 0
	pendingSpace := false
	for {
		next, err := skipCFWS(raw, pos)
		if err != nil {
			return "", err
		}
		if next != pos {
			pendingSpace = true
		}
		pos = next
		if pos >= len(raw) {
			break
		}
		if pendingSpace && b.Len() > 0 {
			b.WriteByte(' ')
		}
		pendingSpace = false

		switch c := raw[pos]; {
		case c == '.':
			// Obsolescent phrase separator; it is part of the display name.
			b.WriteByte('.')
			pos++
		case c == '"':
			end, err := consumeQuotedString(raw, pos)
			if err != nil {
				return "", err
			}
			b.WriteString(unquoteQuotedString(raw[pos+1 : end-1]))
			pos = end
		case isAText(c) || c >= 128:
			end, err := consumeAtom(raw, pos, true)
			if err != nil {
				return "", err
			}
			b.WriteString(raw[pos:end])
			pos = end
		default:
			return "", ErrInvalidAddress
		}
	}

	if b.Len() == 0 {
		return "", nil
	}

	decoded, err := decodeHeaderValue(b.String())
	if err != nil || !validDisplayName(decoded) {
		return "", ErrInvalidAddress
	}
	return decoded, nil
}

// validDisplayName reports whether a decoded display name is safe to emit in a
// header field. In particular, an RFC 2047 encoded-word can decode to CR or LF,
// which must never reach the wire because it would terminate the header line.
func validDisplayName(name string) bool {
	if !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}

// validMailboxPart reports whether a local-part or domain can be placed in an
// SMTP path without terminating the command. Unlike a display name, it cannot
// contain tab or any other control character.
func validMailboxPart(part string) bool {
	if !utf8.ValidString(part) {
		return false
	}
	for _, r := range part {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}

// unquoteQuotedString removes the backslash escaping from a quoted-string body
// and unfolds any folding white space it contains.
func unquoteQuotedString(content string) string {
	var b strings.Builder
	b.Grow(len(content))
	for i := 0; i < len(content); i++ {
		switch {
		case content[i] == '\\' && i+1 < len(content):
			i++
			b.WriteByte(content[i])
		case content[i] == '\r' && i+1 < len(content) && content[i+1] == '\n':
			i++
			for i+1 < len(content) && isWSP(content[i+1]) {
				i++
			}
			b.WriteByte(' ')
		default:
			b.WriteByte(content[i])
		}
	}
	return b.String()
}

// consumeHeaderAddrSpec parses local-part "@" domain in RFC 5322 context and
// returns the canonical local-part and domain substrings plus the position
// after the domain (past any trailing CFWS). Comments and other CFWS inside an
// obs-local-part or obs-domain are removed from the canonical form so the
// result can also be used as an SMTP path.
func consumeHeaderAddrSpec(value string, pos int) (local, domain string, next int, err error) {
	localStart, err := skipCFWS(value, pos)
	if err != nil {
		return "", "", 0, err
	}

	localTextEnd, local, err := consumeHeaderLocalPart(value, localStart)
	if err != nil {
		return "", "", 0, err
	}
	at, err := skipCFWS(value, localTextEnd)
	if err != nil {
		return "", "", 0, err
	}
	if at >= len(value) || value[at] != '@' {
		return "", "", 0, ErrAddressMissingAt
	}

	domainStart, err := skipCFWS(value, at+1)
	if err != nil {
		return "", "", 0, err
	}
	domainTextEnd, domain, err := consumeHeaderDomain(value, domainStart)
	if err != nil {
		return "", "", 0, err
	}

	next, err = skipCFWS(value, domainTextEnd)
	if err != nil {
		return "", "", 0, err
	}
	return local, domain, next, nil
}

// consumeHeaderLocalPart parses local-part = (dot-atom / quoted-string /
// obs-local-part). obs-local-part permits CFWS and quoted words between dots.
// It returns the end of the local-part text, before any trailing CFWS, and the
// semantic local-part: quoted words are unquoted, words are joined with dots,
// and comments/folding whitespace are removed.
func consumeHeaderLocalPart(value string, pos int) (int, string, error) {
	pos, err := skipCFWS(value, pos)
	if err != nil {
		return 0, "", err
	}

	end, word, err := consumeHeaderWordText(value, pos)
	if err != nil {
		return 0, "", err
	}
	var semantic strings.Builder
	semantic.WriteString(word)
	pos = end

	for {
		after, err := skipCFWS(value, pos)
		if err != nil {
			return 0, "", err
		}
		if after >= len(value) || value[after] != '.' {
			return pos, semantic.String(), nil
		}
		next, err := skipCFWS(value, after+1)
		if err != nil {
			return 0, "", err
		}
		end, word, err := consumeHeaderWordText(value, next)
		if err != nil {
			return 0, "", ErrInvalidLocalPart
		}
		semantic.WriteByte('.')
		semantic.WriteString(word)
		pos = end
	}
}

// consumeHeaderWordText parses a single word (atom or quoted-string) at pos and
// returns its semantic text. Quoted words are unquoted and any FWS inside them
// is unfolded.
func consumeHeaderWordText(value string, pos int) (int, string, error) {
	end, err := consumeHeaderWord(value, pos)
	if err != nil {
		return 0, "", err
	}
	if value[pos] == '"' {
		return end, unquoteQuotedString(value[pos+1 : end-1]), nil
	}
	return end, value[pos:end], nil
}

// consumeHeaderWord parses a single word (atom or quoted-string) at pos. pos
// must be the start of the word; no leading or trailing CFWS is consumed.
func consumeHeaderWord(value string, pos int) (int, error) {
	if pos >= len(value) {
		return 0, ErrInvalidLocalPart
	}
	if value[pos] == '"' {
		return consumeQuotedString(value, pos)
	}
	return consumeAtom(value, pos, true)
}

// consumeHeaderDomain parses domain = (dot-atom / domain-literal / obs-domain).
// obs-domain is atom *("." atom) with optional CFWS. It returns the end of the
// domain text, before any trailing CFWS, and a canonical domain in which
// comments and folding whitespace are removed. A domain-literal is reduced to
// its address-literal form (FWS inside the brackets is dropped).
func consumeHeaderDomain(value string, pos int) (int, string, error) {
	pos, err := skipCFWS(value, pos)
	if err != nil {
		return 0, "", err
	}
	if pos >= len(value) {
		return 0, "", ErrDomainEmpty
	}

	if value[pos] == '[' {
		end, err := consumeDomainLiteralFWS(value, pos)
		if err != nil {
			return 0, "", err
		}
		return end, stripFWS(value[pos:end]), nil
	}

	next, err := consumeAtom(value, pos, true)
	if err != nil {
		return 0, "", ErrInvalidDomain
	}
	var canonical strings.Builder
	canonical.WriteString(value[pos:next])
	pos = next

	for {
		after, err := skipCFWS(value, pos)
		if err != nil {
			return 0, "", err
		}
		if after >= len(value) || value[after] != '.' {
			return pos, canonical.String(), nil
		}
		wordStart, err := skipCFWS(value, after+1)
		if err != nil {
			return 0, "", err
		}
		next, err := consumeAtom(value, wordStart, true)
		if err != nil {
			return 0, "", ErrInvalidDomain
		}
		canonical.WriteByte('.')
		canonical.WriteString(value[wordStart:next])
		pos = next
	}
}

// stripFWS removes folding white space from a domain-literal.
func stripFWS(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		default:
			return r
		}
	}, s)
}

// normalizeHeaderDomain normalizes an RFC 5322 domain. Domain literals are
// validated as RFC 5321 address-literals; internationalized domains are
// punycoded and the result is lowercased. The resulting domain is also checked
// against the DNS rules used for envelope addresses, so a syntactically odd
// header domain cannot be emitted on the wire as an invalid RCPT TO domain.
func normalizeHeaderDomain(domain string) (string, error) {
	if domain == "" {
		return "", ErrDomainEmpty
	}
	if strings.HasPrefix(domain, "[") {
		if !strings.HasSuffix(domain, "]") {
			return "", ErrInvalidDomain
		}
		return validateIPLiteral(domain)
	}

	return validateAndNormalizeDomain(domain, true)
}

// consumeDomainLiteralFWS parses a domain-literal (RFC 5322), allowing folding
// white space between dtext characters. pos must be at '['.
func consumeDomainLiteralFWS(value string, pos int) (int, error) {
	pos++
	for pos < len(value) {
		c := value[pos]
		switch {
		case c == ']':
			return pos + 1, nil
		case c == '\r' || c == '\n' || isWSP(c):
			next, err := consumeFWS(value, pos)
			if err != nil {
				return 0, err
			}
			pos = next
		case (c >= 33 && c <= 90) || (c >= 94 && c <= 126):
			pos++
		default:
			return 0, ErrInvalidDomain
		}
	}
	return 0, ErrInvalidDomain
}

// ---------------------------------------------------------------------------
// RFC 5321 envelope grammar
// ---------------------------------------------------------------------------

// consumeEnvelopeLocalPart parses local-part = dot-string / quoted-string and
// returns the position just after it.
func consumeEnvelopeLocalPart(value string, pos int, allowUTF8 bool) (int, error) {
	if pos < len(value) && value[pos] == '"' {
		return consumeSMTPQuotedString(value, pos, allowUTF8)
	}

	next, err := consumeSMTPAtom(value, pos, allowUTF8)
	if err != nil {
		return 0, ErrInvalidLocalPart
	}
	pos = next

	for pos < len(value) && value[pos] == '.' {
		next, err := consumeSMTPAtom(value, pos+1, allowUTF8)
		if err != nil {
			return 0, ErrInvalidLocalPart
		}
		pos = next
	}
	return pos, nil
}

// consumeSMTPAtom parses Atom = 1*atext (RFC 6531 extends atext with UTF-8
// non-ASCII when SMTPUTF8 is enabled).
func consumeSMTPAtom(value string, pos int, allowUTF8 bool) (int, error) {
	start := pos
	for pos < len(value) {
		c := value[pos]
		if isAText(c) || (allowUTF8 && c >= 128) {
			pos++
			continue
		}
		break
	}
	if pos == start {
		return 0, ErrInvalidLocalPart
	}
	return pos, nil
}

// consumeSMTPQuotedString parses Quoted-string = DQUOTE *QcontentSMTP DQUOTE.
func consumeSMTPQuotedString(value string, pos int, allowUTF8 bool) (int, error) {
	pos++ // opening quote
	for pos < len(value) {
		c := value[pos]
		switch {
		case c == '"':
			return pos + 1, nil
		case c == '\\':
			// quoted-pairSMTP = "\" %d32-126
			pos++
			if pos >= len(value) {
				return 0, ErrInvalidLocalPart
			}
			c = value[pos]
			if c < 32 || c == 127 {
				return 0, ErrInvalidLocalPart
			}
			if !allowUTF8 && c > 127 {
				return 0, ErrNonASCIIWithoutUTF8
			}
			pos++
		case c == 32 || c == 33 || (c >= 35 && c <= 91) || (c >= 93 && c <= 126):
			pos++
		case allowUTF8 && c >= 128:
			pos++
		default:
			return 0, ErrInvalidLocalPart
		}
	}
	return 0, ErrInvalidLocalPart
}

// findSourceRouteEnd returns the index of the top-level ":" that terminates an
// A-d-l source route, or -1 if there is none. Colons inside address literals
// (e.g. [IPv6:...]) are ignored.
func findSourceRouteEnd(value string) int {
	depth := 0
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case ':':
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// validateSourceRoute validates A-d-l = At-domain *( "," At-domain ).
func validateSourceRoute(route string, allowUTF8 bool) error {
	for domain := range strings.SplitSeq(route, ",") {
		domain = strings.TrimSpace(domain)
		if !strings.HasPrefix(domain, "@") {
			return ErrInvalidDomain
		}
		if _, err := validateAndNormalizeDomain(domain[1:], allowUTF8); err != nil {
			return err
		}
	}
	return nil
}

// validateAndNormalizeDomain validates an RFC 5321 domain (DNS domain or
// address-literal) and converts IDN to ASCII (punycode).
func validateAndNormalizeDomain(domain string, allowUTF8 bool) (string, error) {
	if domain == "" {
		return "", ErrDomainEmpty
	}

	// Handle address literals [IPv4] or [IPv6:...].
	if len(domain) >= 2 && domain[0] == '[' && domain[len(domain)-1] == ']' {
		return validateIPLiteral(domain)
	}

	if !isASCII(domain) {
		if !allowUTF8 {
			return "", ErrNonASCIIWithoutUTF8
		}

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

	if err := validateASCIIDomain(domain); err != nil {
		return "", err
	}

	return strings.ToLower(domain), nil
}

// validateASCIIDomain validates an ASCII DNS domain name.
func validateASCIIDomain(domain string) error {
	if len(domain) > maxDomainLength {
		return ErrDomainTooLong
	}
	if domain == "" {
		return ErrDomainEmpty
	}

	if domain[0] == '.' || domain[0] == '-' {
		return ErrInvalidDomain
	}
	if domain[len(domain)-1] == '.' || domain[len(domain)-1] == '-' {
		return ErrInvalidDomain
	}
	if strings.Contains(domain, "..") {
		return ErrInvalidDomain
	}

	for label := range strings.SplitSeq(domain, ".") {
		if err := validateDomainLabel(label); err != nil {
			return err
		}
	}
	return nil
}

// validateDomainLabel validates a single RFC 5321 sub-domain (LDH label).
func validateDomainLabel(label string) error {
	if label == "" || len(label) > 63 {
		return ErrInvalidDomain
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return ErrInvalidDomain
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
			return ErrInvalidDomain
		}
	}
	return nil
}

// validateIPLiteral validates an address-literal: an IPv4 literal, an
// IPv6 literal, or a general-address-literal (Standardized-tag ":" dcontent).
func validateIPLiteral(lit string) (string, error) {
	inner := lit[1 : len(lit)-1]

	if strings.HasPrefix(strings.ToUpper(inner), "IPV6:") {
		if !isValidIPv6(inner[5:]) {
			return "", ErrInvalidIPLiteral
		}
		return lit, nil
	}

	if isValidIPv4(inner) {
		return lit, nil
	}

	// General-address-literal (RFC 5321 section 4.1.3).
	if colon := strings.IndexByte(inner, ':'); colon > 0 {
		if validateStandardizedTag(inner[:colon]) == nil && isValidDContent(inner[colon+1:]) {
			return lit, nil
		}
	}

	return "", ErrInvalidIPLiteral
}

// validateStandardizedTag validates Standardized-tag = Ldh-str.
func validateStandardizedTag(tag string) error {
	if tag == "" {
		return ErrInvalidIPLiteral
	}
	if tag[0] == '-' || tag[len(tag)-1] == '-' {
		return ErrInvalidIPLiteral
	}
	for i := 0; i < len(tag); i++ {
		c := tag[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
			return ErrInvalidIPLiteral
		}
	}
	return nil
}

// isValidDContent validates dcontent = %d33-90 / %d94-126.
func isValidDContent(content string) bool {
	if content == "" {
		return false
	}
	for i := 0; i < len(content); i++ {
		c := content[i]
		if !((c >= 33 && c <= 90) || (c >= 94 && c <= 126)) {
			return false
		}
	}
	return true
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

// isValidIPv6 checks if a string is a valid IPv6 address. It accepts standard
// and compressed formats, and IPv4-embedded forms.
func isValidIPv6(s string) bool {
	if s == "" {
		return false
	}

	// Allow a trailing IPv4 part (e.g. ::ffff:192.0.2.1).
	if dot := strings.LastIndex(s, "."); dot != -1 {
		colon := strings.LastIndex(s, ":")
		if colon > dot || !isValidIPv4(s[colon+1:]) {
			return false
		}
		s = s[:colon+1]
	}

	colons := strings.Count(s, ":")
	doubleColon := strings.Contains(s, "::")

	if doubleColon {
		if strings.Count(s, "::") > 1 {
			return false
		}
		if colons > 7 {
			return false
		}
	} else if colons != 7 {
		return false
	}

	s = strings.TrimPrefix(s, "::")
	s = strings.TrimSuffix(s, "::")
	if s == "" {
		return true // Just "::" is valid.
	}

	for part := range strings.SplitSeq(s, ":") {
		if part == "" {
			continue
		}
		if len(part) > 4 {
			return false
		}
		for i := 0; i < len(part); i++ {
			c := part[i]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return false
			}
		}
	}
	return true
}

// isASCII reports whether s contains only ASCII characters (0-127).
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}
