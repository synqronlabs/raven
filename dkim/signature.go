package dkim

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// Signature represents a parsed DKIM-Signature header (RFC 6376 Section 3.5).
type Signature struct {
	// Required fields
	Version       int      // v= Version, must be 1
	Algorithm     string   // a= Algorithm (e.g., "rsa-sha256")
	Signature     []byte   // b= Signature data
	BodyHash      []byte   // bh= Body hash
	Domain        string   // d= Signing domain
	SignedHeaders []string // h= Signed header fields
	Selector      string   // s= Selector

	// Optional fields
	Canonicalization string   // c= Canonicalization (e.g., "relaxed/simple")
	Identity         string   // i= Agent or User Identifier (AUID)
	Length           int64    // l= Body length limit (-1 if not set)
	QueryMethods     []string // q= Query methods
	SignTime         int64    // t= Signature timestamp (-1 if not set)
	ExpireTime       int64    // x= Signature expiration (-1 if not set)
	CopiedHeaders    []string // z= Copied header fields
}

// NewSignature creates a new Signature with default values.
func NewSignature() *Signature {
	return &Signature{
		Version:          1,
		Canonicalization: "simple/simple",
		Length:           -1,
		SignTime:         -1,
		ExpireTime:       -1,
	}
}

// AlgorithmSign returns the signing algorithm part (e.g., "rsa" from "rsa-sha256").
func (s *Signature) AlgorithmSign() string {
	parts := strings.SplitN(s.Algorithm, "-", 2)
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// AlgorithmHash returns the hash algorithm part (e.g., "sha256" from "rsa-sha256").
func (s *Signature) AlgorithmHash() string {
	parts := strings.SplitN(s.Algorithm, "-", 2)
	if len(parts) > 1 {
		return parts[1]
	}
	return ""
}

// HeaderCanon returns the header canonicalization algorithm.
func (s *Signature) HeaderCanon() Canonicalization {
	parts := strings.SplitN(s.Canonicalization, "/", 2)
	if len(parts) > 0 {
		return Canonicalization(strings.ToLower(parts[0]))
	}
	return CanonSimple
}

// BodyCanon returns the body canonicalization algorithm.
func (s *Signature) BodyCanon() Canonicalization {
	parts := strings.SplitN(s.Canonicalization, "/", 2)
	if len(parts) > 1 {
		return Canonicalization(strings.ToLower(parts[1]))
	}
	// Default body canonicalization is "simple"
	return CanonSimple
}

// IsExpired returns true if the signature has expired.
func (s *Signature) IsExpired() bool {
	if s.ExpireTime < 0 {
		return false
	}
	return timeNow().Unix() > s.ExpireTime
}

// headerWriter helps create DKIM-Signature headers with proper folding.
// It tracks line length and folds to the next line when needed (RFC 5322).
type headerWriter struct {
	b        strings.Builder
	lineLen  int
	nonfirst bool
}

// add adds text, potentially folding to a new line if it exceeds maxLen.
func (w *headerWriter) add(sep, text string) {
	const maxLen = 76

	n := len(text)
	if w.nonfirst && w.lineLen > 1 && w.lineLen+len(sep)+n > maxLen {
		w.b.WriteString("\r\n\t")
		w.lineLen = 1
	} else if w.nonfirst && sep != "" {
		w.b.WriteString(sep)
		w.lineLen += len(sep)
	}
	w.b.WriteString(text)
	w.lineLen += len(text)
	w.nonfirst = true
}

// addf formats and adds text.
func (w *headerWriter) addf(sep, format string, args ...any) {
	w.add(sep, fmt.Sprintf(format, args...))
}

// addWrap adds data that can be wrapped at any position (like base64).
func (w *headerWriter) addWrap(data []byte) {
	const maxLen = 76

	for len(data) > 0 {
		n := maxLen - w.lineLen
		if n <= 0 {
			w.b.WriteString("\r\n\t")
			w.lineLen = 1
			n = maxLen - 1
		}
		if n > len(data) {
			n = len(data)
		}
		w.b.Write(data[:n])
		w.lineLen += n
		data = data[n:]
	}
}

// String returns the header content (without trailing CRLF).
func (w *headerWriter) String() string {
	return w.b.String()
}

// Header generates the DKIM-Signature header string.
// If includeSignature is false, the b= value is left empty for signing.
func (s *Signature) Header(includeSignature bool) (string, error) {
	w := &headerWriter{}

	// Header name and version (required, must be first)
	w.addf("", "DKIM-Signature: v=%d;", s.Version)

	// Domain (required, must always be ASCII per RFC 6376)
	w.addf(" ", "d=%s;", s.Domain)

	// Selector (required)
	w.addf(" ", "s=%s;", s.Selector)

	// Algorithm (required)
	w.addf(" ", "a=%s;", s.Algorithm)

	// Canonicalization (only if not default simple/simple)
	if s.Canonicalization != "" &&
		!strings.EqualFold(s.Canonicalization, "simple") &&
		!strings.EqualFold(s.Canonicalization, "simple/simple") {
		w.addf(" ", "c=%s;", s.Canonicalization)
	}

	// Identity (optional)
	if s.Identity != "" {
		w.addf(" ", "i=%s;", s.Identity)
	}

	// Query methods (only if not default dns/txt)
	if len(s.QueryMethods) > 0 && !(len(s.QueryMethods) == 1 && strings.EqualFold(s.QueryMethods[0], "dns/txt")) {
		w.addf(" ", "q=%s;", strings.Join(s.QueryMethods, ":"))
	}

	// Timestamp
	if s.SignTime >= 0 {
		w.addf(" ", "t=%d;", s.SignTime)
	}

	// Expiration
	if s.ExpireTime >= 0 {
		w.addf(" ", "x=%d;", s.ExpireTime)
	}

	// Body length (optional, but discouraged for security)
	if s.Length >= 0 {
		w.addf(" ", "l=%d;", s.Length)
	}

	// Signed headers (required)
	if len(s.SignedHeaders) > 0 {
		// Add h= prefix to first header, colon separators, and semicolon at end
		for i, h := range s.SignedHeaders {
			sep := ""
			if i == 0 {
				h = "h=" + h
				sep = " "
			}
			if i < len(s.SignedHeaders)-1 {
				h += ":"
			} else {
				h += ";"
			}
			w.add(sep, h)
		}
	}

	// Copied headers (optional)
	if len(s.CopiedHeaders) > 0 {
		for i, h := range s.CopiedHeaders {
			// Encode the header
			parts := strings.SplitN(h, ":", 2)
			var encoded string
			if len(parts) == 2 {
				encoded = parts[0] + ":" + encodeCopiedHeader(parts[1])
			} else {
				encoded = encodeCopiedHeader(h)
			}

			sep := ""
			if i == 0 {
				encoded = "z=" + encoded
				sep = " "
			}
			if i < len(s.CopiedHeaders)-1 {
				encoded += "|"
			} else {
				encoded += ";"
			}
			w.add(sep, encoded)
		}
	}

	// Body hash (required)
	w.addf(" ", "bh=%s;", base64.StdEncoding.EncodeToString(s.BodyHash))

	// Signature
	w.add(" ", "b=")
	if includeSignature && len(s.Signature) > 0 {
		w.addWrap([]byte(base64.StdEncoding.EncodeToString(s.Signature)))
	}

	return w.String(), nil
}

// encodeCopiedHeader encodes a header value for the z= tag using DKIM quoted-printable.
func encodeCopiedHeader(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for _, c := range []byte(s) {
		// DKIM-safe-char: printable ASCII except ; = | :
		if c > ' ' && c < 0x7f && c != ';' && c != '=' && c != '|' && c != ':' {
			b.WriteByte(c)
		} else {
			b.WriteByte('=')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		}
	}
	return b.String()
}

// signatureParser parses DKIM-Signature headers while tracking content.
// The tracked field accumulates all parsed content except when drop is true,
// which is used to strip the b= value for signature verification.
type signatureParser struct {
	s       string // input string
	offset  int    // current position
	tracked string // accumulated content (excluding dropped portions)
	drop    bool   // when true, content is not added to tracked
}

func (p *signatureParser) track(s string) {
	if !p.drop {
		p.tracked += s
	}
}

func (p *signatureParser) remaining() string {
	return p.s[p.offset:]
}

func (p *signatureParser) empty() bool {
	return p.offset >= len(p.s)
}

func (p *signatureParser) peek() byte {
	if p.offset >= len(p.s) {
		return 0
	}
	return p.s[p.offset]
}

func (p *signatureParser) take(n int) string {
	if p.offset+n > len(p.s) {
		n = len(p.s) - p.offset
	}
	r := p.s[p.offset : p.offset+n]
	p.offset += n
	p.track(r)
	return r
}

func (p *signatureParser) skipFWS() {
	for p.offset < len(p.s) {
		c := p.s[p.offset]
		if c == ' ' || c == '\t' {
			p.take(1)
		} else if c == '\r' && p.offset+2 < len(p.s) && p.s[p.offset+1] == '\n' && (p.s[p.offset+2] == ' ' || p.s[p.offset+2] == '\t') {
			p.take(3)
		} else if c == '\n' && p.offset+1 < len(p.s) && (p.s[p.offset+1] == ' ' || p.s[p.offset+1] == '\t') {
			p.take(2)
		} else {
			break
		}
	}
}

func (p *signatureParser) takeUntil(delim byte) string {
	start := p.offset
	for p.offset < len(p.s) && p.s[p.offset] != delim {
		p.offset++
	}
	r := p.s[start:p.offset]
	p.track(r)
	return r
}

func (p *signatureParser) expect(s string) bool {
	if strings.HasPrefix(p.remaining(), s) {
		p.take(len(s))
		return true
	}
	return false
}

// ParseSignature parses a DKIM-Signature header value.
// The input should include the header name (DKIM-Signature:).
// Returns the parsed signature and the original header with b= value removed
// (for signature verification).
func ParseSignature(header string) (*Signature, []byte, error) {
	// Remove trailing CRLF for parsing
	input := strings.TrimSuffix(header, "\r\n")

	// Unfold headers (remove CRLF followed by whitespace) for tag parsing
	unfolded := unfoldHeader(input)

	// Check for DKIM-Signature header
	if !strings.HasPrefix(strings.ToLower(unfolded), "dkim-signature:") {
		return nil, nil, fmt.Errorf("%w: not a DKIM-Signature header", ErrHeaderMalformed)
	}

	// Extract value portion for parsing
	value := strings.TrimSpace(unfolded[len("DKIM-Signature:"):])

	// Create parser for tracking (uses original input to preserve FWS)
	p := &signatureParser{s: input}

	// Track everything up to and including the colon
	colonIdx := strings.Index(input, ":")
	if colonIdx < 0 {
		return nil, nil, fmt.Errorf("%w: missing colon", ErrHeaderMalformed)
	}
	p.take(colonIdx + 1)

	sig := NewSignature()
	seen := make(map[string]bool)

	// Parse tag=value pairs from unfolded value
	parts := strings.Split(value, ";")
	for partIdx, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			// Track the semicolon and surrounding whitespace
			if partIdx < len(parts)-1 {
				p.skipFWS()
				if p.peek() == ';' {
					p.take(1)
				}
			}
			continue
		}

		idx := strings.Index(part, "=")
		if idx == -1 {
			continue
		}

		tag := strings.TrimSpace(part[:idx])
		tagValue := strings.TrimSpace(part[idx+1:])

		// Check for duplicate tags
		if seen[tag] {
			return nil, nil, fmt.Errorf("%w: %s", ErrDuplicateTag, tag)
		}
		seen[tag] = true

		// Track up to this tag in original input
		p.skipFWS()

		// Find and track the tag name and equals sign
		tagStart := strings.Index(strings.ToLower(p.remaining()), strings.ToLower(tag)+"=")
		if tagStart >= 0 {
			p.take(tagStart)
			p.take(len(tag) + 1) // tag + "="
		}

		// For b= tag, enable drop mode to exclude value from tracked string
		if tag == "b" {
			p.drop = true
			p.skipFWS()
		} else {
			p.skipFWS()
		}

		// Parse the tag value
		switch tag {
		case "v":
			v, err := strconv.Atoi(tagValue)
			if err != nil || v != 1 {
				return nil, nil, fmt.Errorf("%w: %s", ErrInvalidVersion, tagValue)
			}
			sig.Version = v

		case "a":
			sig.Algorithm = strings.ToLower(tagValue)

		case "b":
			// Decode signature, ignoring whitespace
			cleaned := strings.Map(func(r rune) rune {
				if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
					return -1
				}
				return r
			}, tagValue)
			decoded, err := base64.StdEncoding.DecodeString(cleaned)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid signature encoding: %w", err)
			}
			sig.Signature = decoded

		case "bh":
			// Decode body hash, ignoring whitespace
			cleaned := strings.Map(func(r rune) rune {
				if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
					return -1
				}
				return r
			}, tagValue)
			decoded, err := base64.StdEncoding.DecodeString(cleaned)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid body hash encoding: %w", err)
			}
			sig.BodyHash = decoded

		case "c":
			sig.Canonicalization = strings.ToLower(tagValue)

		case "d":
			sig.Domain = strings.ToLower(tagValue)

		case "h":
			headers := strings.Split(tagValue, ":")
			for _, h := range headers {
				h = strings.TrimSpace(h)
				if h != "" {
					sig.SignedHeaders = append(sig.SignedHeaders, h)
				}
			}

		case "i":
			sig.Identity = tagValue

		case "l":
			l, err := strconv.ParseInt(tagValue, 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid length: %w", err)
			}
			sig.Length = l

		case "q":
			methods := strings.Split(tagValue, ":")
			for _, m := range methods {
				m = strings.TrimSpace(m)
				if m != "" {
					sig.QueryMethods = append(sig.QueryMethods, m)
				}
			}

		case "s":
			sig.Selector = strings.ToLower(tagValue)

		case "t":
			t, err := strconv.ParseInt(tagValue, 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid timestamp: %w", err)
			}
			sig.SignTime = t

		case "x":
			x, err := strconv.ParseInt(tagValue, 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid expiration: %w", err)
			}
			sig.ExpireTime = x

		case "z":
			// Parse copied headers
			headers := strings.Split(tagValue, "|")
			for _, h := range headers {
				sig.CopiedHeaders = append(sig.CopiedHeaders, decodeCopiedHeader(h))
			}
		}

		// Track value in original (skipped for b=)
		if tag != "b" {
			// Find value end in original
			valueEnd := strings.Index(p.remaining(), ";")
			if valueEnd < 0 {
				p.take(len(p.remaining()))
			} else {
				p.take(valueEnd)
			}
		} else {
			// For b=, skip value without tracking, then turn off drop
			valueEnd := strings.Index(p.remaining(), ";")
			if valueEnd < 0 {
				p.offset += len(p.remaining())
			} else {
				p.offset += valueEnd
			}
			p.skipFWS()
			p.drop = false
		}

		// Track semicolon if present
		if p.peek() == ';' {
			p.take(1)
		}
	}

	// Validate required tags
	required := []string{"v", "a", "b", "bh", "d", "h", "s"}
	for _, tag := range required {
		if !seen[tag] {
			return nil, nil, fmt.Errorf("%w: %s", ErrMissingTag, tag)
		}
	}

	// Validate body hash length matches algorithm (RFC 6376)
	hashAlg := sig.AlgorithmHash()
	switch strings.ToLower(hashAlg) {
	case "sha1":
		if len(sig.BodyHash) != 20 {
			return nil, nil, fmt.Errorf("invalid body hash length: got %d bytes, expected 20 for sha1", len(sig.BodyHash))
		}
	case "sha256":
		if len(sig.BodyHash) != 32 {
			return nil, nil, fmt.Errorf("invalid body hash length: got %d bytes, expected 32 for sha256", len(sig.BodyHash))
		}
	}

	// Validate signature timestamp vs expiration
	if sig.SignTime >= 0 && sig.ExpireTime >= 0 && sig.SignTime >= sig.ExpireTime {
		return nil, nil, fmt.Errorf("%w: sign time >= expire time", ErrSigExpired)
	}

	// Validate identity domain matches signing domain
	if sig.Identity != "" {
		atIdx := strings.LastIndex(sig.Identity, "@")
		if atIdx >= 0 {
			identityDomain := strings.ToLower(sig.Identity[atIdx+1:])
			if identityDomain != sig.Domain && !strings.HasSuffix(identityDomain, "."+sig.Domain) {
				return nil, nil, fmt.Errorf("%w: identity domain %s not under signing domain %s",
					ErrDomainIdentityMismatch, identityDomain, sig.Domain)
			}
		}
	}

	return sig, []byte(p.tracked), nil
}

// unfoldHeader unfolds a folded header (removes CRLF followed by whitespace)
func unfoldHeader(s string) string {
	// Remove CRLF+WSP
	s = strings.ReplaceAll(s, "\r\n\t", " ")
	s = strings.ReplaceAll(s, "\r\n ", " ")
	// Also handle just LF+WSP
	s = strings.ReplaceAll(s, "\n\t", " ")
	s = strings.ReplaceAll(s, "\n ", " ")
	return s
}

// decodeCopiedHeader decodes a DKIM quoted-printable encoded header.
func decodeCopiedHeader(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '=' && i+2 < len(s) {
			hi := hexVal(s[i+1])
			lo := hexVal(s[i+2])
			if hi >= 0 && lo >= 0 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	}
	return -1
}
