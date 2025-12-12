package raven

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	ErrDKIMNoSignature             = errors.New("dkim: no DKIM-Signature header found")
	ErrDKIMInvalidSignature        = errors.New("dkim: invalid signature format")
	ErrDKIMSignatureExpired        = errors.New("dkim: signature expired")
	ErrDKIMBodyHashMismatch        = errors.New("dkim: body hash did not verify")
	ErrDKIMSignatureMismatch       = errors.New("dkim: signature did not verify")
	ErrDKIMKeyNotFound             = errors.New("dkim: no key for signature")
	ErrDKIMKeyRevoked              = errors.New("dkim: key revoked")
	ErrDKIMInvalidKey              = errors.New("dkim: invalid public key")
	ErrDKIMUnsupportedAlgorithm    = errors.New("dkim: unsupported algorithm")
	ErrDKIMDomainMismatch          = errors.New("dkim: domain mismatch between d= and i=")
	ErrDKIMFromNotSigned           = errors.New("dkim: From header field not signed")
	ErrDKIMInvalidVersion          = errors.New("dkim: incompatible version")
	ErrDKIMMissingRequiredTag      = errors.New("dkim: signature missing required tag")
	ErrDKIMInvalidCanonicalization = errors.New("dkim: invalid canonicalization algorithm")
	ErrDKIMKeyUnavailable          = errors.New("dkim: key unavailable (temporary failure)")
)

// DKIMAlgorithm represents a DKIM signing algorithm (RFC 6376).
type DKIMAlgorithm string

const (
	DKIMAlgorithmRSASHA256 DKIMAlgorithm = "rsa-sha256" // Recommended
	DKIMAlgorithmRSASHA1   DKIMAlgorithm = "rsa-sha1"   // Deprecated
)

// DKIMCanonicalization represents the canonicalization algorithm (RFC 6376).
type DKIMCanonicalization string

const (
	DKIMCanonicalizationSimple  DKIMCanonicalization = "simple"
	DKIMCanonicalizationRelaxed DKIMCanonicalization = "relaxed"
)

// DKIMSignature represents a parsed DKIM-Signature header (RFC 6376).
type DKIMSignature struct {
	Version                string
	Algorithm              DKIMAlgorithm
	Signature              []byte
	BodyHash               []byte
	HeaderCanonicalization DKIMCanonicalization
	BodyCanonicalization   DKIMCanonicalization
	Domain                 string
	SignedHeaders          []string
	AUID                   string
	BodyLength             int64
	BodyLengthSet          bool
	QueryMethods           []string
	Selector               string
	Timestamp              time.Time
	TimestampSet           bool
	Expiration             time.Time
	ExpirationSet          bool
	CopiedHeaders          map[string]string
	Raw                    string
}

// DKIMPublicKey represents a DKIM public key record per RFC 6376 Section 3.6.1.
type DKIMPublicKey struct {
	// Version (v=) - RECOMMENDED. Should be "DKIM1" if present.
	Version string

	// HashAlgorithms (h=) - OPTIONAL. Acceptable hash algorithms.
	// Defaults to allowing all algorithms.
	HashAlgorithms []string

	// KeyType (k=) - OPTIONAL. Default is "rsa".
	KeyType string

	// Notes (n=) - OPTIONAL. Notes for administrators.
	Notes string

	// PublicKey (p=) - REQUIRED. The public key data in base64.
	// Empty value means the key has been revoked.
	PublicKey *rsa.PublicKey

	// ServiceTypes (s=) - OPTIONAL. Default is "*" (all services).
	ServiceTypes []string

	// Flags (t=) - OPTIONAL.
	// "y" = testing mode
	// "s" = strict domain matching (i= domain must equal d= domain)
	Flags []string

	Raw string
}

// DKIMSignOptions contains options for DKIM signing.
type DKIMSignOptions struct {
	// Domain is the signing domain (d= tag). REQUIRED.
	Domain string

	// Selector is the selector for key lookup (s= tag). REQUIRED.
	Selector string

	// PrivateKey is the RSA private key for signing. REQUIRED.
	PrivateKey *rsa.PrivateKey

	// Algorithm specifies the signing algorithm.
	// Default is DKIMAlgorithmRSASHA256 (strongly recommended).
	Algorithm DKIMAlgorithm

	// HeaderCanonicalization specifies the header canonicalization algorithm.
	// Default is DKIMCanonicalizationRelaxed.
	HeaderCanonicalization DKIMCanonicalization

	// BodyCanonicalization specifies the body canonicalization algorithm.
	// Default is DKIMCanonicalizationRelaxed.
	BodyCanonicalization DKIMCanonicalization

	// Headers specifies which headers to sign.
	// If empty, a default secure set will be used.
	// The From header is ALWAYS included per RFC 6376.
	Headers []string

	// AUID is the Agent or User Identifier (i= tag).
	// Optional. If empty, defaults to "@" + Domain.
	AUID string

	// BodyLength limits the body length to sign.
	// If 0 or negative, the entire body is signed (RECOMMENDED for security).
	// WARNING: Using body length limits can enable certain attacks (see RFC 6376 Section 8.2).
	BodyLength int64

	// AddTimestamp adds the t= timestamp tag.
	// Default is true (recommended).
	AddTimestamp bool

	// Expiration sets the signature expiration time.
	// If zero, no expiration is set.
	Expiration time.Time

	// QueryMethods specifies the key query methods.
	// Default is ["dns/txt"].
	QueryMethods []string
}

// DKIMVerifyOptions contains options for DKIM verification.
type DKIMVerifyOptions struct {
	// DNSResolver is a custom DNS resolver function.
	// If nil, the default net.LookupTXT is used.
	DNSResolver func(domain string) ([]string, error)

	// IgnoreExpiration skips signature expiration check.
	// Default is false (check expiration).
	// WARNING: Setting this to true reduces security.
	IgnoreExpiration bool

	// AllowSHA1 allows verification of rsa-sha1 signatures.
	// Default is false per RFC 8301 which deprecates SHA-1.
	// WARNING: SHA-1 is cryptographically weak and should not be trusted.
	AllowSHA1 bool

	// MinKeyBits is the minimum RSA key size to accept.
	// Default is 1024 bits per RFC 6376 Section 3.3.3.
	// Recommended: 2048 bits for better security.
	MinKeyBits int

	// MaxSignaturesToVerify limits the number of signatures to verify.
	// Default is 5. This prevents denial-of-service attacks.
	MaxSignaturesToVerify int
}

// DKIMResult represents the result of DKIM verification.
type DKIMResult struct {
	// Status is the verification status.
	Status DKIMStatus

	// Domain is the signing domain (d= tag value).
	Domain string

	// Selector is the selector used.
	Selector string

	// AUID is the Agent or User Identifier if present.
	AUID string

	// Error contains the error if verification failed.
	Error error

	// Signature is the parsed DKIM-Signature.
	Signature *DKIMSignature
}

// DKIMStatus represents the status of DKIM verification per RFC 6376.
type DKIMStatus string

const (
	// DKIMStatusPass indicates successful verification.
	DKIMStatusPass DKIMStatus = "pass"

	// DKIMStatusFail indicates permanent verification failure (PERMFAIL).
	DKIMStatusFail DKIMStatus = "fail"

	// DKIMStatusTempError indicates temporary failure (TEMPFAIL).
	// The signature could not be verified at this time but may succeed later.
	DKIMStatusTempError DKIMStatus = "temperror"

	// DKIMStatusNone indicates no DKIM signature was found.
	DKIMStatusNone DKIMStatus = "none"
)

// DefaultDKIMSignOptions returns DKIMSignOptions with secure defaults per RFC 6376.
func DefaultDKIMSignOptions() *DKIMSignOptions {
	return &DKIMSignOptions{
		Algorithm:              DKIMAlgorithmRSASHA256,
		HeaderCanonicalization: DKIMCanonicalizationRelaxed,
		BodyCanonicalization:   DKIMCanonicalizationRelaxed,
		AddTimestamp:           true,
		QueryMethods:           []string{"dns/txt"},
		// Default headers to sign per RFC 6376 Section 5.4.1
		Headers: []string{
			"From", // REQUIRED per RFC 6376
			"To",
			"Cc",
			"Subject",
			"Date",
			"Message-ID",
			"Reply-To",
			"In-Reply-To",
			"References",
			"MIME-Version",
			"Content-Type",
			"Content-Transfer-Encoding",
		},
	}
}

// DefaultDKIMVerifyOptions returns DKIMVerifyOptions with secure defaults.
func DefaultDKIMVerifyOptions() *DKIMVerifyOptions {
	return &DKIMVerifyOptions{
		DNSResolver:           net.LookupTXT,
		IgnoreExpiration:      false,
		AllowSHA1:             false,
		MinKeyBits:            2048,
		MaxSignaturesToVerify: 5,
	}
}

// SignDKIM signs the mail with DKIM and adds a DKIM-Signature header.
// This method should be called by servers before sending the message.
//
// Per RFC 6376 Section 5, the signature is computed over the message headers
// (specified in opts.Headers) and body, using the specified canonicalization
// algorithms.
//
// The DKIM-Signature header is prepended to the message headers per RFC 6376 Section 5.6.
func (m *Mail) SignDKIM(opts *DKIMSignOptions) error {
	if opts == nil {
		return errors.New("dkim: sign options required")
	}
	if opts.Domain == "" {
		return errors.New("dkim: domain required")
	}
	if opts.Selector == "" {
		return errors.New("dkim: selector required")
	}
	if opts.PrivateKey == nil {
		return errors.New("dkim: private key required")
	}

	if opts.Algorithm == "" {
		opts.Algorithm = DKIMAlgorithmRSASHA256
	}
	if opts.HeaderCanonicalization == "" {
		opts.HeaderCanonicalization = DKIMCanonicalizationRelaxed
	}
	if opts.BodyCanonicalization == "" {
		opts.BodyCanonicalization = DKIMCanonicalizationRelaxed
	}
	if len(opts.Headers) == 0 {
		opts.Headers = DefaultDKIMSignOptions().Headers
	}
	if len(opts.QueryMethods) == 0 {
		opts.QueryMethods = []string{"dns/txt"}
	}

	// Only rsa-sha256 is allowed for signing per RFC 8301
	if opts.Algorithm != DKIMAlgorithmRSASHA256 {
		return fmt.Errorf("dkim: only rsa-sha256 is allowed for signing (got %s)", opts.Algorithm)
	}

	// Ensure "From" is always signed per RFC 6376 Section 5.4
	hasFrom := false
	for _, h := range opts.Headers {
		if strings.EqualFold(h, "From") {
			hasFrom = true
			break
		}
	}
	if !hasFrom {
		opts.Headers = append([]string{"From"}, opts.Headers...)
	}

	bodyHash, err := m.computeDKIMBodyHash(opts.Algorithm, opts.BodyCanonicalization, opts.BodyLength)
	if err != nil {
		return fmt.Errorf("dkim: failed to compute body hash: %w", err)
	}

	sig := &DKIMSignature{
		Version:                "1",
		Algorithm:              opts.Algorithm,
		BodyHash:               bodyHash,
		HeaderCanonicalization: opts.HeaderCanonicalization,
		BodyCanonicalization:   opts.BodyCanonicalization,
		Domain:                 opts.Domain,
		SignedHeaders:          opts.Headers,
		Selector:               opts.Selector,
		QueryMethods:           opts.QueryMethods,
	}

	if opts.AUID != "" {
		sig.AUID = opts.AUID
	}

	if opts.BodyLength > 0 {
		sig.BodyLength = opts.BodyLength
		sig.BodyLengthSet = true
	}

	if opts.AddTimestamp {
		sig.Timestamp = time.Now().UTC()
		sig.TimestampSet = true
	}

	if !opts.Expiration.IsZero() {
		sig.Expiration = opts.Expiration.UTC()
		sig.ExpirationSet = true
	}

	headerValue := sig.buildHeaderValue("")

	headerHash, err := m.computeDKIMHeaderHash(opts.Algorithm, opts.HeaderCanonicalization, opts.Headers, headerValue)
	if err != nil {
		return fmt.Errorf("dkim: failed to compute header hash: %w", err)
	}

	signature, err := signRSA(opts.PrivateKey, opts.Algorithm, headerHash)
	if err != nil {
		return fmt.Errorf("dkim: failed to sign: %w", err)
	}

	finalHeaderValue := sig.buildHeaderValue(base64.StdEncoding.EncodeToString(signature))

	// Per RFC 6376 Section 5.6: MUST be inserted before any other DKIM-Signature fields
	m.Content.Headers = append(Headers{{
		Name:  "DKIM-Signature",
		Value: finalHeaderValue,
	}}, m.Content.Headers...)

	return nil
}

// VerifyDKIM verifies DKIM signatures on the mail.
// This method should be called by clients after receiving a message.
//
// Per RFC 6376 Section 6, verification involves:
// 1. Extracting and parsing DKIM-Signature headers
// 2. Retrieving the public key from DNS
// 3. Computing and comparing the body hash
// 4. Verifying the header signature
//
// Returns a slice of DKIMResult, one for each DKIM-Signature header found.
// A message may have multiple signatures from different domains.
func (m *Mail) VerifyDKIM(opts *DKIMVerifyOptions) []DKIMResult {
	if opts == nil {
		opts = DefaultDKIMVerifyOptions()
	}

	if opts.DNSResolver == nil {
		opts.DNSResolver = net.LookupTXT
	}
	if opts.MinKeyBits == 0 {
		opts.MinKeyBits = 1024
	}
	if opts.MaxSignaturesToVerify == 0 {
		opts.MaxSignaturesToVerify = 5
	}

	var signatures []string
	for _, h := range m.Content.Headers {
		if strings.EqualFold(h.Name, "DKIM-Signature") {
			signatures = append(signatures, h.Value)
		}
	}

	if len(signatures) == 0 {
		return []DKIMResult{{
			Status: DKIMStatusNone,
			Error:  ErrDKIMNoSignature,
		}}
	}

	// Limit signatures to prevent DoS
	if len(signatures) > opts.MaxSignaturesToVerify {
		signatures = signatures[:opts.MaxSignaturesToVerify]
	}

	results := make([]DKIMResult, 0, len(signatures))

	for _, sigValue := range signatures {
		result := m.verifySingleDKIMSignature(sigValue, opts)
		results = append(results, result)

		// Per RFC 6376 Section 6.1: Verifiers SHOULD continue to check signatures
		// until a signature successfully verifies
		if result.Status == DKIMStatusPass {
			break
		}
	}

	return results
}

// verifySingleDKIMSignature verifies a single DKIM signature.
func (m *Mail) verifySingleDKIMSignature(sigValue string, opts *DKIMVerifyOptions) DKIMResult {
	result := DKIMResult{
		Status: DKIMStatusFail,
	}

	sig, err := parseDKIMSignature(sigValue)
	if err != nil {
		result.Error = fmt.Errorf("%w: %v", ErrDKIMInvalidSignature, err)
		return result
	}
	result.Signature = sig
	result.Domain = sig.Domain
	result.Selector = sig.Selector
	result.AUID = sig.AUID

	if err := m.validateDKIMSignature(sig, opts); err != nil {
		result.Error = err
		return result
	}

	pubKey, err := lookupDKIMPublicKey(sig.Domain, sig.Selector, opts)
	if err != nil {
		if errors.Is(err, ErrDKIMKeyUnavailable) {
			result.Status = DKIMStatusTempError
		}
		result.Error = err
		return result
	}

	if pubKey.PublicKey.Size()*8 < opts.MinKeyBits {
		result.Error = fmt.Errorf("dkim: key size %d bits is below minimum %d bits", pubKey.PublicKey.Size()*8, opts.MinKeyBits)
		return result
	}

	if err := m.verifyDKIMSignatureData(sig, pubKey, opts); err != nil {
		result.Error = err
		return result
	}

	result.Status = DKIMStatusPass
	return result
}

// validateDKIMSignature validates the DKIM signature structure
func (m *Mail) validateDKIMSignature(sig *DKIMSignature, opts *DKIMVerifyOptions) error {
	// Check version - MUST be "1"
	if sig.Version != "1" {
		return ErrDKIMInvalidVersion
	}

	if sig.Algorithm != DKIMAlgorithmRSASHA256 && sig.Algorithm != DKIMAlgorithmRSASHA1 {
		return ErrDKIMUnsupportedAlgorithm
	}

	if sig.Algorithm == DKIMAlgorithmRSASHA1 && !opts.AllowSHA1 {
		return fmt.Errorf("%w: rsa-sha1 is deprecated", ErrDKIMUnsupportedAlgorithm)
	}

	// Check required tags
	if sig.Domain == "" {
		return fmt.Errorf("%w: d= (domain)", ErrDKIMMissingRequiredTag)
	}
	if sig.Selector == "" {
		return fmt.Errorf("%w: s= (selector)", ErrDKIMMissingRequiredTag)
	}
	if len(sig.SignedHeaders) == 0 {
		return fmt.Errorf("%w: h= (signed headers)", ErrDKIMMissingRequiredTag)
	}
	if len(sig.Signature) == 0 {
		return fmt.Errorf("%w: b= (signature)", ErrDKIMMissingRequiredTag)
	}
	if len(sig.BodyHash) == 0 {
		return fmt.Errorf("%w: bh= (body hash)", ErrDKIMMissingRequiredTag)
	}

	// Check that From is signed
	fromSigned := false
	for _, h := range sig.SignedHeaders {
		if strings.EqualFold(h, "From") {
			fromSigned = true
			break
		}
	}
	if !fromSigned {
		return ErrDKIMFromNotSigned
	}

	// Check AUID domain matches
	if sig.AUID != "" {
		auidDomain := sig.AUID
		if idx := strings.LastIndex(sig.AUID, "@"); idx != -1 {
			auidDomain = sig.AUID[idx+1:]
		}
		if !strings.EqualFold(auidDomain, sig.Domain) && !strings.HasSuffix(strings.ToLower(auidDomain), "."+strings.ToLower(sig.Domain)) {
			return ErrDKIMDomainMismatch
		}
	}

	if sig.ExpirationSet && !opts.IgnoreExpiration {
		if time.Now().After(sig.Expiration) {
			return ErrDKIMSignatureExpired
		}
	}

	return nil
}

// verifyDKIMSignatureData verifies the signature data.
func (m *Mail) verifyDKIMSignatureData(sig *DKIMSignature, pubKey *DKIMPublicKey, _ *DKIMVerifyOptions) error {
	bodyHash, err := m.computeDKIMBodyHash(sig.Algorithm, sig.BodyCanonicalization, sig.BodyLength)
	if err != nil {
		return fmt.Errorf("dkim: failed to compute body hash: %w", err)
	}

	if !bytes.Equal(bodyHash, sig.BodyHash) {
		return ErrDKIMBodyHashMismatch
	}

	// Per RFC 6376: The value of the "b=" tag (including all surrounding whitespace)
	// must be deleted (i.e., treated as the empty string).
	headerValueWithoutSig := stripDKIMSignatureValue(sig.Raw)
	headerHash, err := m.computeDKIMHeaderHash(sig.Algorithm, sig.HeaderCanonicalization, sig.SignedHeaders, headerValueWithoutSig)
	if err != nil {
		return fmt.Errorf("dkim: failed to compute header hash: %w", err)
	}

	if err := verifyRSA(pubKey.PublicKey, sig.Algorithm, headerHash, sig.Signature); err != nil {
		return ErrDKIMSignatureMismatch
	}

	return nil
}

// stripDKIMSignatureValue removes the b= tag value from a DKIM-Signature header value.
// Per RFC 6376, the signature value (including surrounding whitespace) must be
// treated as empty when computing the header hash for verification.
func stripDKIMSignatureValue(headerValue string) string {
	// Find the b= tag and remove its value (but keep "b=")
	// The b= tag value is base64 and may contain whitespace for folding

	// Use a regex to find b= followed by base64 characters and whitespace
	bTagPattern := regexp.MustCompile(`(\bb=)([A-Za-z0-9+/=\s]*)`)
	return bTagPattern.ReplaceAllString(headerValue, "${1}")
}

// computeDKIMBodyHash computes the body hash
func (m *Mail) computeDKIMBodyHash(alg DKIMAlgorithm, canon DKIMCanonicalization, bodyLength int64) ([]byte, error) {
	body := canonicalizeBody(m.Content.Body, canon)

	if bodyLength > 0 && int64(len(body)) > bodyLength {
		body = body[:bodyLength]
	}

	switch alg {
	case DKIMAlgorithmRSASHA256:
		h := sha256.Sum256(body)
		return h[:], nil
	case DKIMAlgorithmRSASHA1:
		h := crypto.SHA1.New()
		h.Write(body)
		return h.Sum(nil), nil
	default:
		return nil, ErrDKIMUnsupportedAlgorithm
	}
}

// computeDKIMHeaderHash computes the header hash
func (m *Mail) computeDKIMHeaderHash(alg DKIMAlgorithm, canon DKIMCanonicalization, signedHeaders []string, dkimSigValue string) ([]byte, error) {
	var buf bytes.Buffer

	// Process headers in order specified in h= tag
	// Per RFC 6376: headers are processed from bottom to top
	headerCounts := make(map[string]int)
	for _, hdrName := range signedHeaders {
		headerCounts[strings.ToLower(hdrName)]++
	}

	// Build a map of header occurrences (bottom to top)
	headerOccurrences := make(map[string][]Header)
	for i := len(m.Content.Headers) - 1; i >= 0; i-- {
		h := m.Content.Headers[i]
		name := strings.ToLower(h.Name)
		headerOccurrences[name] = append(headerOccurrences[name], h)
	}

	// Process headers in h= tag order
	usedCounts := make(map[string]int)
	for _, hdrName := range signedHeaders {
		name := strings.ToLower(hdrName)
		idx := usedCounts[name]
		usedCounts[name]++

		if idx < len(headerOccurrences[name]) {
			hdr := headerOccurrences[name][idx]
			canonHeader := canonicalizeHeader(hdr.Name, hdr.Value, canon)
			buf.WriteString(canonHeader)
			buf.WriteString("\r\n")
		}
	}

	// Add DKIM-Signature header without trailing CRLF
	canonDKIMSig := canonicalizeHeader("DKIM-Signature", dkimSigValue, canon)
	buf.WriteString(canonDKIMSig)

	switch alg {
	case DKIMAlgorithmRSASHA256:
		h := sha256.Sum256(buf.Bytes())
		return h[:], nil
	case DKIMAlgorithmRSASHA1:
		h := crypto.SHA1.New()
		h.Write(buf.Bytes())
		return h.Sum(nil), nil
	default:
		return nil, ErrDKIMUnsupportedAlgorithm
	}
}

// canonicalizeBody canonicalizes the message body
func canonicalizeBody(body []byte, canon DKIMCanonicalization) []byte {
	switch canon {
	case DKIMCanonicalizationSimple:
		return canonicalizeBodySimple(body)
	case DKIMCanonicalizationRelaxed:
		return canonicalizeBodyRelaxed(body)
	default:
		return canonicalizeBodySimple(body)
	}
}

// canonicalizeBodySimple implements simple body canonicalization per RFC 6376
// Ignores all empty lines at the end of the message body.
// If there is no body or no trailing CRLF, a CRLF is added.
func canonicalizeBodySimple(body []byte) []byte {
	if len(body) == 0 {
		return []byte("\r\n")
	}

	// Remove trailing empty lines
	result := body
	for len(result) >= 2 && result[len(result)-2] == '\r' && result[len(result)-1] == '\n' {
		// Check if the line before is also empty
		if len(result) == 2 {
			// This is the last CRLF, keep it
			break
		}
		if len(result) >= 4 && result[len(result)-4] == '\r' && result[len(result)-3] == '\n' {
			result = result[:len(result)-2]
		} else {
			break
		}
	}

	// Ensure body ends with CRLF
	if len(result) < 2 || result[len(result)-2] != '\r' || result[len(result)-1] != '\n' {
		result = append(result, '\r', '\n')
	}

	return result
}

// canonicalizeBodyRelaxed implements relaxed body canonicalization per RFC 6376 Section 3.4.4.
// Reduces whitespace and ignores empty lines at the end.
func canonicalizeBodyRelaxed(body []byte) []byte {
	if len(body) == 0 {
		return []byte{}
	}

	var result bytes.Buffer
	lines := bytes.Split(body, []byte("\r\n"))

	var processedLines [][]byte
	for _, line := range lines {
		// Reduce whitespace within line
		processed := reduceWhitespace(line)
		// Ignore trailing whitespace
		processed = bytes.TrimRight(processed, " \t")
		processedLines = append(processedLines, processed)
	}

	// Remove trailing empty lines
	for len(processedLines) > 0 && len(processedLines[len(processedLines)-1]) == 0 {
		processedLines = processedLines[:len(processedLines)-1]
	}

	if len(processedLines) == 0 {
		return []byte{}
	}

	// Reconstruct body with CRLF
	for i, line := range processedLines {
		result.Write(line)
		if i < len(processedLines)-1 {
			result.WriteString("\r\n")
		}
	}
	result.WriteString("\r\n")

	return result.Bytes()
}

// reduceWhitespace reduces sequences of WSP to a single space.
func reduceWhitespace(data []byte) []byte {
	var result bytes.Buffer
	inWhitespace := false

	for _, b := range data {
		if b == ' ' || b == '\t' {
			if !inWhitespace {
				result.WriteByte(' ')
				inWhitespace = true
			}
		} else {
			result.WriteByte(b)
			inWhitespace = false
		}
	}

	return result.Bytes()
}

// canonicalizeHeader canonicalizes a header field
func canonicalizeHeader(name, value string, canon DKIMCanonicalization) string {
	switch canon {
	case DKIMCanonicalizationSimple:
		return canonicalizeHeaderSimple(name, value)
	case DKIMCanonicalizationRelaxed:
		return canonicalizeHeaderRelaxed(name, value)
	default:
		return canonicalizeHeaderSimple(name, value)
	}
}

// canonicalizeHeaderSimple implements simple header canonicalization.
// Does not change header fields in any way.
func canonicalizeHeaderSimple(name, value string) string {
	return name + ": " + value
}

// canonicalizeHeaderRelaxed implements relaxed header canonicalization.
func canonicalizeHeaderRelaxed(name, value string) string {
	name = strings.ToLower(name)

	// Unfold continuation lines and reduce whitespace
	value = unfoldHeader(value)
	value = string(reduceWhitespace([]byte(value)))

	value = strings.TrimSpace(value)

	return name + ":" + value
}

// unfoldHeader unfolds a folded header value.
func unfoldHeader(value string) string {
	// Replace CRLF followed by WSP with a single space
	result := strings.ReplaceAll(value, "\r\n ", " ")
	result = strings.ReplaceAll(result, "\r\n\t", " ")
	return result
}

// buildHeaderValue builds the DKIM-Signature header value.
func (sig *DKIMSignature) buildHeaderValue(signature string) string {
	var parts []string

	// Required tags
	parts = append(parts, "v="+sig.Version)
	parts = append(parts, "a="+string(sig.Algorithm))

	// Canonicalization
	canonStr := string(sig.HeaderCanonicalization) + "/" + string(sig.BodyCanonicalization)
	parts = append(parts, "c="+canonStr)

	parts = append(parts, "d="+sig.Domain)
	parts = append(parts, "s="+sig.Selector)

	// Signed headers
	parts = append(parts, "h="+strings.Join(sig.SignedHeaders, ":"))

	// Body hash
	parts = append(parts, "bh="+base64.StdEncoding.EncodeToString(sig.BodyHash))

	// Optional tags
	if sig.AUID != "" {
		parts = append(parts, "i="+sig.AUID)
	}

	if sig.BodyLengthSet {
		parts = append(parts, "l="+strconv.FormatInt(sig.BodyLength, 10))
	}

	if len(sig.QueryMethods) > 0 {
		parts = append(parts, "q="+strings.Join(sig.QueryMethods, ":"))
	}

	if sig.TimestampSet {
		parts = append(parts, "t="+strconv.FormatInt(sig.Timestamp.Unix(), 10))
	}

	if sig.ExpirationSet {
		parts = append(parts, "x="+strconv.FormatInt(sig.Expiration.Unix(), 10))
	}

	// Signature (b=) - must be last
	parts = append(parts, "b="+signature)

	// Join with "; " and fold for readability
	return strings.Join(parts, "; ")
}

// parseDKIMSignature parses a DKIM-Signature header value
func parseDKIMSignature(value string) (*DKIMSignature, error) {
	sig := &DKIMSignature{
		Raw:                    value,
		HeaderCanonicalization: DKIMCanonicalizationSimple, // Default
		BodyCanonicalization:   DKIMCanonicalizationSimple, // Default
		QueryMethods:           []string{"dns/txt"},        // Default
	}

	// Parse tag=value pairs
	tags := parseDKIMTagList(value)

	// Version (v=) - REQUIRED
	if v, ok := tags["v"]; ok {
		sig.Version = v
	} else {
		return nil, fmt.Errorf("missing required tag: v")
	}

	// Algorithm (a=) - REQUIRED
	if a, ok := tags["a"]; ok {
		sig.Algorithm = DKIMAlgorithm(a)
	} else {
		return nil, fmt.Errorf("missing required tag: a")
	}

	// Signature (b=) - REQUIRED
	if b, ok := tags["b"]; ok {
		// Remove whitespace
		b = strings.Join(strings.Fields(b), "")
		decoded, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			return nil, fmt.Errorf("invalid b= tag: %w", err)
		}
		sig.Signature = decoded
	} else {
		return nil, fmt.Errorf("missing required tag: b")
	}

	// Body hash (bh=) - REQUIRED
	if bh, ok := tags["bh"]; ok {
		bh = strings.Join(strings.Fields(bh), "")
		decoded, err := base64.StdEncoding.DecodeString(bh)
		if err != nil {
			return nil, fmt.Errorf("invalid bh= tag: %w", err)
		}
		sig.BodyHash = decoded
	} else {
		return nil, fmt.Errorf("missing required tag: bh")
	}

	// Canonicalization (c=) - OPTIONAL
	if c, ok := tags["c"]; ok {
		parts := strings.SplitN(c, "/", 2)
		sig.HeaderCanonicalization = DKIMCanonicalization(parts[0])
		if len(parts) > 1 {
			sig.BodyCanonicalization = DKIMCanonicalization(parts[1])
		} else {
			sig.BodyCanonicalization = DKIMCanonicalizationSimple
		}
	}

	// Domain (d=) - REQUIRED
	if d, ok := tags["d"]; ok {
		sig.Domain = d
	} else {
		return nil, fmt.Errorf("missing required tag: d")
	}

	// Signed headers (h=) - REQUIRED
	if h, ok := tags["h"]; ok {
		sig.SignedHeaders = strings.Split(h, ":")
		for i, hdr := range sig.SignedHeaders {
			sig.SignedHeaders[i] = strings.TrimSpace(hdr)
		}
	} else {
		return nil, fmt.Errorf("missing required tag: h")
	}

	// AUID (i=) - OPTIONAL
	if i, ok := tags["i"]; ok {
		sig.AUID = i
	} else {
		sig.AUID = "@" + sig.Domain
	}

	// Body length (l=) - OPTIONAL
	if l, ok := tags["l"]; ok {
		length, err := strconv.ParseInt(l, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid l= tag: %w", err)
		}
		sig.BodyLength = length
		sig.BodyLengthSet = true
	}

	// Query methods (q=) - OPTIONAL
	if q, ok := tags["q"]; ok {
		sig.QueryMethods = strings.Split(q, ":")
	}

	// Selector (s=) - REQUIRED
	if s, ok := tags["s"]; ok {
		sig.Selector = s
	} else {
		return nil, fmt.Errorf("missing required tag: s")
	}

	// Timestamp (t=) - OPTIONAL
	if t, ok := tags["t"]; ok {
		ts, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid t= tag: %w", err)
		}
		sig.Timestamp = time.Unix(ts, 0).UTC()
		sig.TimestampSet = true
	}

	// Expiration (x=) - OPTIONAL
	if x, ok := tags["x"]; ok {
		exp, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid x= tag: %w", err)
		}
		sig.Expiration = time.Unix(exp, 0).UTC()
		sig.ExpirationSet = true
	}

	// Copied headers (z=) - OPTIONAL
	if z, ok := tags["z"]; ok {
		sig.CopiedHeaders = make(map[string]string)
		pairs := strings.SplitSeq(z, "|")
		for pair := range pairs {
			if idx := strings.Index(pair, ":"); idx != -1 {
				sig.CopiedHeaders[pair[:idx]] = pair[idx+1:]
			}
		}
	}

	return sig, nil
}

// parseDKIMTagList parses a DKIM tag=value list
func parseDKIMTagList(value string) map[string]string {
	tags := make(map[string]string)

	// Split by semicolon
	pairs := strings.SplitSeq(value, ";")
	for pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		// Split by first equals sign
		idx := strings.Index(pair, "=")
		if idx == -1 {
			continue
		}

		tagName := strings.TrimSpace(pair[:idx])
		tagValue := strings.TrimSpace(pair[idx+1:])
		tags[tagName] = tagValue
	}

	return tags
}

// lookupDKIMPublicKey retrieves the DKIM public key from DNS.
func lookupDKIMPublicKey(domain, selector string, opts *DKIMVerifyOptions) (*DKIMPublicKey, error) {
	// Construct DNS query: selector._domainkey.domain
	dnsName := selector + "._domainkey." + domain

	records, err := opts.DNSResolver(dnsName)
	if err != nil {
		// Check if it's a DNS error (NXDOMAIN, etc.)
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			if dnsErr.IsNotFound {
				return nil, ErrDKIMKeyNotFound
			}
			if dnsErr.IsTemporary || dnsErr.IsTimeout {
				return nil, ErrDKIMKeyUnavailable
			}
		}
		return nil, fmt.Errorf("%w: %v", ErrDKIMKeyUnavailable, err)
	}

	if len(records) == 0 {
		return nil, ErrDKIMKeyNotFound
	}

	// Concatenate TXT RR strings
	record := strings.Join(records, "")

	return parseDKIMPublicKey(record)
}

// parseDKIMPublicKey parses a DKIM public key record.
func parseDKIMPublicKey(record string) (*DKIMPublicKey, error) {
	key := &DKIMPublicKey{
		Raw:          record,
		KeyType:      "rsa",         // Default
		ServiceTypes: []string{"*"}, // Default
	}

	tags := parseDKIMTagList(record)

	// Version (v=) - RECOMMENDED
	if v, ok := tags["v"]; ok {
		if v != "DKIM1" {
			return nil, fmt.Errorf("dkim: unsupported key version: %s", v)
		}
		key.Version = v
	}

	// Hash algorithms (h=) - OPTIONAL
	if h, ok := tags["h"]; ok {
		key.HashAlgorithms = strings.Split(h, ":")
	}

	// Key type (k=) - OPTIONAL
	if k, ok := tags["k"]; ok {
		key.KeyType = k
	}

	// Notes (n=) - OPTIONAL
	if n, ok := tags["n"]; ok {
		key.Notes = n
	}

	// Public key (p=) - REQUIRED
	if p, ok := tags["p"]; ok {
		if p == "" {
			return nil, ErrDKIMKeyRevoked
		}

		// Remove whitespace
		p = strings.Join(strings.Fields(p), "")

		// Decode base64
		keyData, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid base64: %v", ErrDKIMInvalidKey, err)
		}

		// Parse RSA public key (ASN.1 DER encoded)
		pubKey, err := x509.ParsePKIXPublicKey(keyData)
		if err != nil {
			// Try parsing as PKCS1
			rsaPubKey, err2 := x509.ParsePKCS1PublicKey(keyData)
			if err2 != nil {
				return nil, fmt.Errorf("%w: %v", ErrDKIMInvalidKey, err)
			}
			key.PublicKey = rsaPubKey
		} else {
			rsaPubKey, ok := pubKey.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("%w: not an RSA key", ErrDKIMInvalidKey)
			}
			key.PublicKey = rsaPubKey
		}
	} else {
		return nil, fmt.Errorf("%w: missing p= tag", ErrDKIMInvalidKey)
	}

	// Service types (s=) - OPTIONAL
	if s, ok := tags["s"]; ok {
		key.ServiceTypes = strings.Split(s, ":")
	}

	// Flags (t=) - OPTIONAL
	if t, ok := tags["t"]; ok {
		key.Flags = strings.Split(t, ":")
	}

	return key, nil
}

// signRSA signs data using RSA with the specified algorithm.
func signRSA(privateKey *rsa.PrivateKey, alg DKIMAlgorithm, data []byte) ([]byte, error) {
	var hash crypto.Hash
	switch alg {
	case DKIMAlgorithmRSASHA256:
		hash = crypto.SHA256
	case DKIMAlgorithmRSASHA1:
		hash = crypto.SHA1
	default:
		return nil, ErrDKIMUnsupportedAlgorithm
	}

	return rsa.SignPKCS1v15(rand.Reader, privateKey, hash, data)
}

// verifyRSA verifies an RSA signature.
func verifyRSA(publicKey *rsa.PublicKey, alg DKIMAlgorithm, data, signature []byte) error {
	var hash crypto.Hash
	switch alg {
	case DKIMAlgorithmRSASHA256:
		hash = crypto.SHA256
	case DKIMAlgorithmRSASHA1:
		hash = crypto.SHA1
	default:
		return ErrDKIMUnsupportedAlgorithm
	}

	return rsa.VerifyPKCS1v15(publicKey, hash, data, signature)
}

// ParseDKIMPrivateKey parses a PEM-encoded RSA private key for DKIM signing.
func ParseDKIMPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("dkim: failed to parse PEM block")
	}

	// Try PKCS#8 first
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("dkim: not an RSA private key")
		}
		return rsaKey, nil
	}

	// Fall back to PKCS#1
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// GenerateDKIMKeyPair generates a new RSA key pair for DKIM signing.
// The keyBits parameter specifies the key size. Per RFC 6376 Section 3.3.3,
// Signers MUST use RSA keys of at least 1024 bits for long-lived keys.
// A minimum of 2048 bits is RECOMMENDED for security.
func GenerateDKIMKeyPair(keyBits int) (*rsa.PrivateKey, error) {
	if keyBits < 1024 {
		return nil, errors.New("dkim: key size must be at least 1024 bits")
	}
	return rsa.GenerateKey(rand.Reader, keyBits)
}

// FormatDKIMPublicKeyRecord formats an RSA public key as a DKIM DNS TXT record.
// The domain and selector are used for informational purposes.
func FormatDKIMPublicKeyRecord(publicKey *rsa.PublicKey) (string, error) {
	// Encode public key as ASN.1 DER
	pubKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("dkim: failed to marshal public key: %w", err)
	}

	// Encode as base64
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyDER)

	// Build TXT record
	return fmt.Sprintf("v=DKIM1; k=rsa; p=%s", pubKeyB64), nil
}

// HasDKIMSignature returns true if the mail has a DKIM-Signature header.
func (m *Mail) HasDKIMSignature() bool {
	for _, h := range m.Content.Headers {
		if strings.EqualFold(h.Name, "DKIM-Signature") {
			return true
		}
	}
	return false
}

// GetDKIMSignatures returns all DKIM-Signature header values.
func (m *Mail) GetDKIMSignatures() []string {
	var sigs []string
	for _, h := range m.Content.Headers {
		if strings.EqualFold(h.Name, "DKIM-Signature") {
			sigs = append(sigs, h.Value)
		}
	}
	return sigs
}

// dkimSafeDNSRegex validates DNS names per RFC 6376.
var dkimSafeDNSRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`)

// ValidateDKIMDomain validates that a domain is safe for DKIM operations.
func ValidateDKIMDomain(domain string) error {
	if domain == "" {
		return errors.New("dkim: empty domain")
	}
	if len(domain) > 253 {
		return errors.New("dkim: domain too long")
	}
	if !dkimSafeDNSRegex.MatchString(domain) {
		return errors.New("dkim: invalid domain format")
	}
	return nil
}

// ValidateDKIMSelector validates that a selector is safe for DKIM operations.
func ValidateDKIMSelector(selector string) error {
	if selector == "" {
		return errors.New("dkim: empty selector")
	}
	if len(selector) > 63 {
		return errors.New("dkim: selector too long")
	}
	if !dkimSafeDNSRegex.MatchString(selector) {
		return errors.New("dkim: invalid selector format")
	}
	return nil
}
