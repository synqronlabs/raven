package arc

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// Set represents a complete ARC set for a single instance.
// Each set contains exactly one of each header type with matching instance numbers.
type Set struct {
	// Instance is the ARC set instance number (i= tag).
	// Must be between 1 and MaxInstance (50).
	Instance int

	// AuthenticationResults is the parsed ARC-Authentication-Results header.
	AuthenticationResults *AuthenticationResults

	// MessageSignature is the parsed ARC-Message-Signature header.
	MessageSignature *MessageSignature

	// Seal is the parsed ARC-Seal header.
	Seal *Seal
}

// AuthenticationResults represents a parsed ARC-Authentication-Results header.
// Per RFC 8617, this header preserves the authentication results observed
// by an intermediary.
type AuthenticationResults struct {
	// Instance is the ARC set instance number (i= tag).
	Instance int

	// AuthServID is the authentication service identifier (required).
	AuthServID string

	// Results contains the authentication results string.
	// This is the raw results string as it appears in the header.
	Results string

	// Raw is the complete raw header value.
	Raw string
}

// MessageSignature represents a parsed ARC-Message-Signature header.
// This is similar to a DKIM-Signature but with an instance number.
type MessageSignature struct {
	// Instance is the ARC set instance number (i= tag). Required.
	Instance int

	// Version is the signature version (v= tag). Must be 1.
	Version int

	// Algorithm is the signing algorithm (a= tag). Required.
	Algorithm string

	// Signature is the message signature (b= tag). Required.
	Signature []byte

	// BodyHash is the body hash (bh= tag). Required.
	BodyHash []byte

	// Domain is the signing domain (d= tag). Required.
	Domain string

	// SignedHeaders is the list of signed headers (h= tag). Required.
	SignedHeaders []string

	// Selector is the selector (s= tag). Required.
	Selector string

	// Canonicalization is the canonicalization (c= tag).
	// Format: "header/body" (e.g., "relaxed/relaxed").
	Canonicalization string

	// Length is the body length limit (l= tag). -1 if not set.
	Length int64

	// Timestamp is the signature timestamp (t= tag). -1 if not set.
	Timestamp int64

	// Expiration is the signature expiration (x= tag). -1 if not set.
	Expiration int64

	// Raw is the complete raw header value.
	Raw string
}

// Seal represents a parsed ARC-Seal header.
// The seal signs the ARC chain to prevent tampering.
type Seal struct {
	// Instance is the ARC set instance number (i= tag). Required.
	Instance int

	// Version is the seal version (v= tag). Must be 1.
	Version int

	// Algorithm is the signing algorithm (a= tag). Required.
	Algorithm string

	// Signature is the seal signature (b= tag). Required.
	Signature []byte

	// Domain is the signing domain (d= tag). Required.
	Domain string

	// Selector is the selector (s= tag). Required.
	Selector string

	// ChainValidation is the chain validation status (cv= tag). Required.
	ChainValidation ChainValidationStatus

	// Timestamp is the signature timestamp (t= tag). -1 if not set.
	Timestamp int64

	// Raw is the complete raw header value.
	Raw string
}

// HeaderCanon returns the header canonicalization algorithm.
func (ms *MessageSignature) HeaderCanon() Canonicalization {
	parts := strings.SplitN(ms.Canonicalization, "/", 2)
	if len(parts) > 0 {
		c := strings.ToLower(strings.TrimSpace(parts[0]))
		if c == "relaxed" {
			return CanonRelaxed
		}
	}
	return CanonSimple
}

// BodyCanon returns the body canonicalization algorithm.
func (ms *MessageSignature) BodyCanon() Canonicalization {
	parts := strings.SplitN(ms.Canonicalization, "/", 2)
	if len(parts) > 1 {
		c := strings.ToLower(strings.TrimSpace(parts[1]))
		if c == "relaxed" {
			return CanonRelaxed
		}
	}
	return CanonSimple
}

// AlgorithmHash returns the hash algorithm part (e.g., "sha256" from "rsa-sha256").
func (ms *MessageSignature) AlgorithmHash() string {
	parts := strings.SplitN(ms.Algorithm, "-", 2)
	if len(parts) > 1 {
		return strings.ToLower(parts[1])
	}
	return ""
}

// AlgorithmSign returns the signing algorithm part (e.g., "rsa" from "rsa-sha256").
func (ms *MessageSignature) AlgorithmSign() string {
	parts := strings.SplitN(ms.Algorithm, "-", 2)
	if len(parts) > 0 {
		return strings.ToLower(parts[0])
	}
	return ""
}

// AlgorithmHash returns the hash algorithm part for the seal.
func (s *Seal) AlgorithmHash() string {
	parts := strings.SplitN(s.Algorithm, "-", 2)
	if len(parts) > 1 {
		return strings.ToLower(parts[1])
	}
	return ""
}

// AlgorithmSign returns the signing algorithm part for the seal.
func (s *Seal) AlgorithmSign() string {
	parts := strings.SplitN(s.Algorithm, "-", 2)
	if len(parts) > 0 {
		return strings.ToLower(parts[0])
	}
	return ""
}

// ParseAuthenticationResults parses an ARC-Authentication-Results header value.
func ParseAuthenticationResults(value string) (*AuthenticationResults, error) {
	aar := &AuthenticationResults{
		Raw:      value,
		Instance: -1,
	}

	// Find the instance number (i=N)
	// Format: i=N; authserv-id; results...
	value = strings.TrimSpace(value)

	// Parse instance tag (must come first)
	if !strings.HasPrefix(strings.ToLower(value), "i=") {
		return nil, fmt.Errorf("%w: missing i= tag in ARC-Authentication-Results", ErrSyntax)
	}

	// Find the first semicolon
	idx := strings.Index(value, ";")
	if idx == -1 {
		return nil, fmt.Errorf("%w: missing semicolon in ARC-Authentication-Results", ErrSyntax)
	}

	// Parse instance
	instanceStr := strings.TrimSpace(value[2:idx])
	instance, err := strconv.Atoi(instanceStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid instance number: %v", ErrSyntax, err)
	}
	if instance < 1 || instance > MaxInstance {
		return nil, fmt.Errorf("%w: instance %d out of range", ErrInvalidInstance, instance)
	}
	aar.Instance = instance

	// The rest is the Authentication-Results content
	rest := strings.TrimSpace(value[idx+1:])

	// Parse authserv-id (the part before the first semicolon or space)
	// Format: authserv-id [optional-version]; results...
	authIdx := strings.IndexAny(rest, "; ")
	if authIdx == -1 {
		// No results, just authserv-id
		aar.AuthServID = strings.TrimSpace(rest)
		aar.Results = ""
	} else {
		aar.AuthServID = strings.TrimSpace(rest[:authIdx])
		remaining := strings.TrimSpace(rest[authIdx:])
		if strings.HasPrefix(remaining, ";") {
			remaining = strings.TrimSpace(remaining[1:])
		}
		aar.Results = remaining
	}

	if aar.AuthServID == "" {
		return nil, fmt.Errorf("%w: missing authserv-id", ErrSyntax)
	}

	return aar, nil
}

// ParseMessageSignature parses an ARC-Message-Signature header value.
func ParseMessageSignature(value string) (*MessageSignature, []byte, error) {
	ms := &MessageSignature{
		Raw:        value,
		Instance:   -1,
		Version:    -1,
		Length:     -1,
		Timestamp:  -1,
		Expiration: -1,
	}

	// Parse tags similar to DKIM
	tags, err := parseTags(value)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSyntax, err)
	}

	// Required tags: i, a, b, bh, d, h, s
	requiredTags := map[string]bool{
		"i": false, "a": false, "b": false, "bh": false,
		"d": false, "h": false, "s": false,
	}

	var signatureForVerify []byte

	for name, val := range tags {
		switch name {
		case "i":
			instance, err := strconv.Atoi(val)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: invalid i= tag: %v", ErrSyntax, err)
			}
			if instance < 1 || instance > MaxInstance {
				return nil, nil, fmt.Errorf("%w: instance %d out of range", ErrInvalidInstance, instance)
			}
			ms.Instance = instance
			requiredTags["i"] = true

		case "v":
			version, err := strconv.Atoi(val)
			if err != nil || version != 1 {
				return nil, nil, fmt.Errorf("%w: v= must be 1", ErrInvalidVersion)
			}
			ms.Version = version

		case "a":
			ms.Algorithm = strings.ToLower(val)
			requiredTags["a"] = true

		case "b":
			// Store for verification computation
			signatureForVerify = []byte(val)
			decoded, err := base64.StdEncoding.DecodeString(stripWhitespace(val))
			if err != nil {
				return nil, nil, fmt.Errorf("%w: invalid b= tag: %v", ErrSyntax, err)
			}
			ms.Signature = decoded
			requiredTags["b"] = true

		case "bh":
			decoded, err := base64.StdEncoding.DecodeString(stripWhitespace(val))
			if err != nil {
				return nil, nil, fmt.Errorf("%w: invalid bh= tag: %v", ErrSyntax, err)
			}
			ms.BodyHash = decoded
			requiredTags["bh"] = true

		case "d":
			ms.Domain = strings.ToLower(val)
			requiredTags["d"] = true

		case "h":
			headers := strings.Split(val, ":")
			for _, h := range headers {
				h = strings.TrimSpace(h)
				if h != "" {
					ms.SignedHeaders = append(ms.SignedHeaders, h)
				}
			}
			requiredTags["h"] = true

		case "s":
			ms.Selector = val
			requiredTags["s"] = true

		case "c":
			ms.Canonicalization = strings.ToLower(val)

		case "l":
			length, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: invalid l= tag: %v", ErrSyntax, err)
			}
			ms.Length = length

		case "t":
			timestamp, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: invalid t= tag: %v", ErrSyntax, err)
			}
			ms.Timestamp = timestamp

		case "x":
			expiration, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: invalid x= tag: %v", ErrSyntax, err)
			}
			ms.Expiration = expiration
		}
	}

	// Check required tags
	for tag, found := range requiredTags {
		if !found {
			return nil, nil, fmt.Errorf("%w: %s= tag", ErrMissingTag, tag)
		}
	}

	// Default version is 1
	if ms.Version == -1 {
		ms.Version = 1
	}

	// Default canonicalization
	if ms.Canonicalization == "" {
		ms.Canonicalization = "relaxed/relaxed"
	}

	return ms, signatureForVerify, nil
}

// ParseSeal parses an ARC-Seal header value.
func ParseSeal(value string) (*Seal, []byte, error) {
	seal := &Seal{
		Raw:       value,
		Instance:  -1,
		Version:   -1,
		Timestamp: -1,
	}

	tags, err := parseTags(value)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSyntax, err)
	}

	// Required tags: i, a, b, cv, d, s
	requiredTags := map[string]bool{
		"i": false, "a": false, "b": false,
		"cv": false, "d": false, "s": false,
	}

	var signatureForVerify []byte

	for name, val := range tags {
		switch name {
		case "i":
			instance, err := strconv.Atoi(val)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: invalid i= tag: %v", ErrSyntax, err)
			}
			if instance < 1 || instance > MaxInstance {
				return nil, nil, fmt.Errorf("%w: instance %d out of range", ErrInvalidInstance, instance)
			}
			seal.Instance = instance
			requiredTags["i"] = true

		case "v":
			version, err := strconv.Atoi(val)
			if err != nil || version != 1 {
				return nil, nil, fmt.Errorf("%w: v= must be 1", ErrInvalidVersion)
			}
			seal.Version = version

		case "a":
			seal.Algorithm = strings.ToLower(val)
			requiredTags["a"] = true

		case "b":
			signatureForVerify = []byte(val)
			decoded, err := base64.StdEncoding.DecodeString(stripWhitespace(val))
			if err != nil {
				return nil, nil, fmt.Errorf("%w: invalid b= tag: %v", ErrSyntax, err)
			}
			seal.Signature = decoded
			requiredTags["b"] = true

		case "cv":
			cv := strings.ToLower(val)
			switch cv {
			case "none":
				seal.ChainValidation = ChainValidationNone
			case "pass":
				seal.ChainValidation = ChainValidationPass
			case "fail":
				seal.ChainValidation = ChainValidationFail
			default:
				return nil, nil, fmt.Errorf("%w: invalid cv= value: %s", ErrSyntax, val)
			}
			requiredTags["cv"] = true

		case "d":
			seal.Domain = strings.ToLower(val)
			requiredTags["d"] = true

		case "s":
			seal.Selector = val
			requiredTags["s"] = true

		case "t":
			timestamp, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: invalid t= tag: %v", ErrSyntax, err)
			}
			seal.Timestamp = timestamp
		}
	}

	// Check required tags
	for tag, found := range requiredTags {
		if !found {
			return nil, nil, fmt.Errorf("%w: %s= tag", ErrMissingTag, tag)
		}
	}

	// Default version is 1
	if seal.Version == -1 {
		seal.Version = 1
	}

	return seal, signatureForVerify, nil
}

// parseTags parses tag=value pairs from a header value.
func parseTags(value string) (map[string]string, error) {
	tags := make(map[string]string)

	// Split by semicolons
	parts := strings.Split(value, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Find equals sign
		idx := strings.Index(part, "=")
		if idx == -1 {
			// Tag without value - skip
			continue
		}

		name := strings.TrimSpace(part[:idx])
		val := strings.TrimSpace(part[idx+1:])

		if name == "" {
			continue
		}

		// Check for duplicate tags
		if _, exists := tags[name]; exists {
			return nil, fmt.Errorf("duplicate tag: %s", name)
		}

		tags[name] = val
	}

	return tags, nil
}

// stripWhitespace removes all whitespace from a string.
func stripWhitespace(s string) string {
	var result strings.Builder
	result.Grow(len(s))
	for _, c := range s {
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			result.WriteRune(c)
		}
	}
	return result.String()
}

// Header generates the ARC-Authentication-Results header string.
func (aar *AuthenticationResults) Header() string {
	var b strings.Builder
	b.WriteString("ARC-Authentication-Results: i=")
	b.WriteString(strconv.Itoa(aar.Instance))
	b.WriteString("; ")
	b.WriteString(aar.AuthServID)
	if aar.Results != "" {
		b.WriteString(";\r\n\t")
		b.WriteString(aar.Results)
	}
	return b.String()
}

// Header generates the ARC-Message-Signature header string.
// If includeSignature is false, the b= value is left empty for signing.
func (ms *MessageSignature) Header(includeSignature bool) string {
	w := &headerWriter{}

	w.add("", "ARC-Message-Signature: i="+strconv.Itoa(ms.Instance)+";")
	w.add(" ", "a="+ms.Algorithm+";")

	if ms.Canonicalization != "" {
		w.add(" ", "c="+ms.Canonicalization+";")
	}

	w.add(" ", "d="+ms.Domain+";")
	w.add(" ", "s="+ms.Selector+";")

	if ms.Timestamp >= 0 {
		w.add(" ", "t="+strconv.FormatInt(ms.Timestamp, 10)+";")
	}

	if ms.Expiration >= 0 {
		w.add(" ", "x="+strconv.FormatInt(ms.Expiration, 10)+";")
	}

	if ms.Length >= 0 {
		w.add(" ", "l="+strconv.FormatInt(ms.Length, 10)+";")
	}

	// Signed headers
	if len(ms.SignedHeaders) > 0 {
		for i, h := range ms.SignedHeaders {
			sep := ""
			if i == 0 {
				h = "h=" + h
				sep = " "
			}
			if i < len(ms.SignedHeaders)-1 {
				h += ":"
			} else {
				h += ";"
			}
			w.add(sep, h)
		}
	}

	// Body hash
	w.add(" ", "bh=")
	w.addWrap([]byte(base64.StdEncoding.EncodeToString(ms.BodyHash)))
	w.add("", ";")

	// Signature
	w.add(" ", "b=")
	if includeSignature && len(ms.Signature) > 0 {
		w.addWrap([]byte(base64.StdEncoding.EncodeToString(ms.Signature)))
	}

	return w.String()
}

// Header generates the ARC-Seal header string.
// If includeSignature is false, the b= value is left empty for signing.
func (s *Seal) Header(includeSignature bool) string {
	w := &headerWriter{}

	w.add("", "ARC-Seal: i="+strconv.Itoa(s.Instance)+";")
	w.add(" ", "a="+s.Algorithm+";")
	w.add(" ", "cv="+string(s.ChainValidation)+";")
	w.add(" ", "d="+s.Domain+";")
	w.add(" ", "s="+s.Selector+";")

	if s.Timestamp >= 0 {
		w.add(" ", "t="+strconv.FormatInt(s.Timestamp, 10)+";")
	}

	// Signature
	w.add(" ", "b=")
	if includeSignature && len(s.Signature) > 0 {
		w.addWrap([]byte(base64.StdEncoding.EncodeToString(s.Signature)))
	}

	return w.String()
}

// headerWriter helps create ARC headers with proper folding.
type headerWriter struct {
	b        strings.Builder
	lineLen  int
	nonfirst bool
}

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

func (w *headerWriter) String() string {
	return w.b.String()
}
