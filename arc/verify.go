package arc

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	ravendns "github.com/synqronlabs/raven/dns"
	"golang.org/x/net/publicsuffix"
)

// Verifier provides ARC chain verification.
type Verifier struct {
	// Resolver is the DNS resolver for key lookups.
	Resolver ravendns.Resolver

	// MinRSAKeyBits is the minimum RSA key size to accept.
	// Default is 1024.
	MinRSAKeyBits int

	// IgnoreExpired allows verification of expired signatures.
	// Default is false.
	IgnoreExpired bool

	// Clock is used for timestamp verification.
	// If nil, time.Now is used.
	Clock func() time.Time
}

// Verify verifies the ARC chain in a message.
func (v *Verifier) Verify(ctx context.Context, message []byte) (*Result, error) {
	return v.VerifyReader(ctx, bytes.NewReader(message))
}

// VerifyReader verifies the ARC chain from a reader.
func (v *Verifier) VerifyReader(ctx context.Context, message io.ReaderAt) (*Result, error) {
	// Parse headers
	br := bufio.NewReader(&atReader{r: message, offset: 0})
	headers, bodyOffset, err := parseHeaders(br)
	if err != nil {
		return &Result{
			Status: StatusFail,
			Err:    fmt.Errorf("parsing headers: %w", err),
		}, nil
	}

	// Extract ARC sets
	sets, err := extractARCSets(headers)
	if err != nil {
		if errors.Is(err, ErrNoARCHeaders) {
			return &Result{Status: StatusNone}, nil
		}
		return &Result{
			Status: StatusFail,
			Err:    err,
		}, nil
	}

	// Verify the chain
	return v.verifyChain(ctx, sets, headers, message, bodyOffset)
}

// extractARCSets extracts and validates ARC sets from headers.
func extractARCSets(headers []headerData) ([]*Set, error) {
	// Collect headers by type
	var aarHeaders []headerData
	var amsHeaders []headerData
	var asHeaders []headerData

	for _, h := range headers {
		switch h.lkey {
		case "arc-authentication-results":
			aarHeaders = append(aarHeaders, h)
		case "arc-message-signature":
			amsHeaders = append(amsHeaders, h)
		case "arc-seal":
			asHeaders = append(asHeaders, h)
		}
	}

	// Check if any ARC headers exist
	if len(aarHeaders) == 0 && len(amsHeaders) == 0 && len(asHeaders) == 0 {
		return nil, ErrNoARCHeaders
	}

	// Parse all headers and group by instance
	sets := make(map[int]*Set)

	// Parse ARC-Authentication-Results
	for _, h := range aarHeaders {
		aar, err := ParseAuthenticationResults(extractHeaderValue(h.raw))
		if err != nil {
			return nil, fmt.Errorf("parsing ARC-Authentication-Results: %w", err)
		}
		if sets[aar.Instance] == nil {
			sets[aar.Instance] = &Set{Instance: aar.Instance}
		}
		if sets[aar.Instance].AuthenticationResults != nil {
			return nil, fmt.Errorf("%w: duplicate ARC-Authentication-Results for instance %d", ErrDuplicateSet, aar.Instance)
		}
		sets[aar.Instance].AuthenticationResults = aar
	}

	// Parse ARC-Message-Signature
	for _, h := range amsHeaders {
		ms, _, err := ParseMessageSignature(extractHeaderValue(h.raw))
		if err != nil {
			return nil, fmt.Errorf("parsing ARC-Message-Signature: %w", err)
		}
		if sets[ms.Instance] == nil {
			sets[ms.Instance] = &Set{Instance: ms.Instance}
		}
		if sets[ms.Instance].MessageSignature != nil {
			return nil, fmt.Errorf("%w: duplicate ARC-Message-Signature for instance %d", ErrDuplicateSet, ms.Instance)
		}
		sets[ms.Instance].MessageSignature = ms
	}

	// Parse ARC-Seal
	for _, h := range asHeaders {
		seal, _, err := ParseSeal(extractHeaderValue(h.raw))
		if err != nil {
			return nil, fmt.Errorf("parsing ARC-Seal: %w", err)
		}
		if sets[seal.Instance] == nil {
			sets[seal.Instance] = &Set{Instance: seal.Instance}
		}
		if sets[seal.Instance].Seal != nil {
			return nil, fmt.Errorf("%w: duplicate ARC-Seal for instance %d", ErrDuplicateSet, seal.Instance)
		}
		sets[seal.Instance].Seal = seal
	}

	// Validate chain structure: instances must be 1, 2, 3, ... n with no gaps
	n := len(sets)
	if n == 0 {
		return nil, ErrNoARCHeaders
	}

	result := make([]*Set, n)
	for i := 1; i <= n; i++ {
		set := sets[i]
		if set == nil {
			return nil, fmt.Errorf("%w: instance %d", ErrGapInChain, i)
		}
		if set.AuthenticationResults == nil {
			return nil, fmt.Errorf("%w: missing ARC-Authentication-Results for instance %d", ErrMissingSet, i)
		}
		if set.MessageSignature == nil {
			return nil, fmt.Errorf("%w: missing ARC-Message-Signature for instance %d", ErrMissingSet, i)
		}
		if set.Seal == nil {
			return nil, fmt.Errorf("%w: missing ARC-Seal for instance %d", ErrMissingSet, i)
		}
		result[i-1] = set
	}

	// Check for extra sets beyond n
	for instance := range sets {
		if instance < 1 || instance > n {
			return nil, fmt.Errorf("%w: extra instance %d", ErrInvalidChain, instance)
		}
	}

	return result, nil
}

// verifyChain verifies the complete ARC chain.
func (v *Verifier) verifyChain(
	ctx context.Context,
	sets []*Set,
	headers []headerData,
	message io.ReaderAt,
	bodyOffset int,
) (*Result, error) {
	result := &Result{
		Sets:   sets,
		Status: StatusPass,
	}

	// Verify chain validation status consistency
	// The first set (i=1) must have cv=none
	if len(sets) > 0 && sets[0].Seal.ChainValidation != ChainValidationNone {
		result.Status = StatusFail
		result.FailedInstance = 1
		result.FailedReason = "first ARC set must have cv=none"
		result.Err = ErrChainValidationMismatch
		return result, nil
	}

	// All subsequent sets must have cv=pass (unless the chain failed earlier)
	for i := 1; i < len(sets); i++ {
		cv := sets[i].Seal.ChainValidation
		if cv == ChainValidationFail {
			// Chain was marked as failed - we accept this but propagate the failure
			result.Status = StatusFail
			result.FailedInstance = i + 1
			result.FailedReason = "chain validation marked as fail"
			return result, nil
		}
		if cv != ChainValidationPass {
			result.Status = StatusFail
			result.FailedInstance = i + 1
			result.FailedReason = fmt.Sprintf("expected cv=pass for instance %d, got %s", i+1, cv)
			result.Err = ErrChainValidationMismatch
			return result, nil
		}
	}

	// Verify each ARC set from oldest to newest
	for i := 0; i < len(sets); i++ {
		set := sets[i]

		// Verify ARC-Message-Signature
		if err := v.verifyMessageSignature(ctx, set.MessageSignature, headers, message, bodyOffset); err != nil {
			result.Status = StatusFail
			result.FailedInstance = i + 1
			result.FailedReason = fmt.Sprintf("ARC-Message-Signature verification failed: %v", err)
			result.Err = err
			return result, nil
		}

		// Verify ARC-Seal
		if err := v.verifySeal(ctx, sets[:i+1], headers); err != nil {
			result.Status = StatusFail
			result.FailedInstance = i + 1
			result.FailedReason = fmt.Sprintf("ARC-Seal verification failed: %v", err)
			result.Err = err
			return result, nil
		}

		// Track oldest passing set
		if result.OldestPass == 0 {
			result.OldestPass = i + 1
		}
	}

	return result, nil
}

// verifyMessageSignature verifies an ARC-Message-Signature.
func (v *Verifier) verifyMessageSignature(
	ctx context.Context,
	ms *MessageSignature,
	headers []headerData,
	message io.ReaderAt,
	bodyOffset int,
) error {
	// Validate algorithm
	hashAlg := ms.AlgorithmHash()
	hashFunc, ok := getHash(hashAlg)
	if !ok {
		return fmt.Errorf("%w: %s", ErrHashUnknown, hashAlg)
	}

	// Check expiration
	if !v.IgnoreExpired && ms.Expiration >= 0 {
		now := v.now().Unix()
		if ms.Expiration < now {
			return fmt.Errorf("%w: expired at %d", ErrExpired, ms.Expiration)
		}
	}

	// Check From header is signed
	hasFrom := false
	for _, h := range ms.SignedHeaders {
		if strings.EqualFold(h, "from") {
			hasFrom = true
			break
		}
	}
	if !hasFrom {
		return ErrFromRequired
	}

	// Lookup the DKIM key
	record, err := v.lookupKey(ctx, ms.Selector, ms.Domain)
	if err != nil {
		return err
	}

	// Verify body hash
	bodyReader := &atReader{r: message, offset: int64(bodyOffset)}
	bodyHash, err := computeBodyHash(hashFunc.New(), ms.BodyCanon(), bodyReader, ms.Length)
	if err != nil {
		return fmt.Errorf("computing body hash: %w", err)
	}

	if !bytes.Equal(bodyHash, ms.BodyHash) {
		return ErrBodyHashMismatch
	}

	// Compute data hash (headers + signature header)
	headerCanon := ms.HeaderCanon()

	// Find the original ARC-Message-Signature header for this instance
	var amsHeader headerData
	for _, h := range headers {
		if h.lkey == "arc-message-signature" {
			parsed, _, _ := ParseMessageSignature(extractHeaderValue(h.raw))
			if parsed != nil && parsed.Instance == ms.Instance {
				amsHeader = h
				break
			}
		}
	}

	// Build the header hash input
	dataHash, err := computeAMSDataHash(hashFunc.New(), headerCanon, headers, ms.SignedHeaders, amsHeader.raw)
	if err != nil {
		return fmt.Errorf("computing data hash: %w", err)
	}

	// Verify signature
	if err := verifyWithKey(record.PublicKey, hashFunc, dataHash, ms.Signature); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureFailed, err)
	}

	return nil
}

// verifySeal verifies an ARC-Seal.
// This verifies the seal for the most recent set, considering all previous sets.
func (v *Verifier) verifySeal(
	ctx context.Context,
	sets []*Set,
	headers []headerData,
) error {
	if len(sets) == 0 {
		return ErrInvalidChain
	}

	currentSet := sets[len(sets)-1]
	seal := currentSet.Seal

	// Validate algorithm
	hashAlg := seal.AlgorithmHash()
	hashFunc, ok := getHash(hashAlg)
	if !ok {
		return fmt.Errorf("%w: %s", ErrHashUnknown, hashAlg)
	}

	// Lookup the DKIM key
	record, err := v.lookupKey(ctx, seal.Selector, seal.Domain)
	if err != nil {
		return err
	}

	// Build seal hash input per RFC 8617 Section 5.1.2
	// The ARC-Seal covers:
	// - All ARC-Seal headers from i=1 to i=n (with b= emptied for current set)
	// - All ARC-Message-Signature headers from i=1 to i=n
	// - All ARC-Authentication-Results headers from i=1 to i=n
	dataHash, err := computeSealDataHash(hashFunc.New(), sets, headers)
	if err != nil {
		return fmt.Errorf("computing seal data hash: %w", err)
	}

	// Verify signature
	if err := verifyWithKey(record.PublicKey, hashFunc, dataHash, seal.Signature); err != nil {
		return fmt.Errorf("%w: %v", ErrSealFailed, err)
	}

	return nil
}

// lookupKey retrieves a DKIM public key from DNS.
func (v *Verifier) lookupKey(ctx context.Context, selector, domain string) (*DKIMRecord, error) {
	// Check domain is not a TLD
	if isTLD(domain) {
		return nil, fmt.Errorf("%w: %s", ErrTLD, domain)
	}

	// Build query name: selector._domainkey.domain
	queryName := selector + "._domainkey." + domain

	result, err := v.Resolver.LookupTXT(ctx, queryName)
	if err != nil {
		if ravendns.IsNotFound(err) {
			return nil, fmt.Errorf("%w: %s", ErrNoRecord, queryName)
		}
		return nil, fmt.Errorf("%w: %v", ErrDNS, err)
	}

	if len(result.Records) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoRecord, queryName)
	}

	// Find a valid DKIM record
	for _, txt := range result.Records {
		record, err := parseDKIMRecord(txt)
		if err != nil {
			continue // Try next record
		}

		// Check key is not revoked
		if len(record.Pubkey) == 0 {
			return nil, ErrKeyRevoked
		}

		// Check RSA key size
		if record.Key == "rsa" || record.Key == "" {
			if rsaKey, ok := record.PublicKey.(*rsa.PublicKey); ok {
				minBits := v.MinRSAKeyBits
				if minBits == 0 {
					minBits = 1024
				}
				if rsaKey.N.BitLen() < minBits {
					return nil, fmt.Errorf("%w: %d bits", ErrWeakKey, rsaKey.N.BitLen())
				}
			}
		}

		return record, nil
	}

	return nil, fmt.Errorf("%w: no valid record in %s", ErrNoRecord, queryName)
}

// now returns the current time.
func (v *Verifier) now() time.Time {
	if v.Clock != nil {
		return v.Clock()
	}
	return time.Now()
}

// DKIMRecord represents a DKIM public key record.
type DKIMRecord struct {
	Version   string
	Key       string
	Pubkey    []byte
	PublicKey any
}

// parseDKIMRecord parses a DKIM TXT record.
func parseDKIMRecord(txt string) (*DKIMRecord, error) {
	record := &DKIMRecord{}

	tags, err := parseTags(txt)
	if err != nil {
		return nil, err
	}

	// Version (optional, defaults to DKIM1)
	if v, ok := tags["v"]; ok {
		if v != "DKIM1" {
			return nil, fmt.Errorf("invalid version: %s", v)
		}
		record.Version = v
	}

	// Key type (optional, defaults to rsa)
	if k, ok := tags["k"]; ok {
		record.Key = strings.ToLower(k)
	} else {
		record.Key = "rsa"
	}

	// Public key (required)
	p, ok := tags["p"]
	if !ok {
		return nil, fmt.Errorf("missing p= tag")
	}

	// Empty p= means key is revoked
	if p == "" {
		record.Pubkey = nil
		return record, nil
	}

	// Decode public key
	pubkeyData, err := base64.StdEncoding.DecodeString(stripWhitespace(p))
	if err != nil {
		return nil, fmt.Errorf("invalid p= tag: %v", err)
	}
	record.Pubkey = pubkeyData

	// Parse public key based on type
	switch record.Key {
	case "rsa", "":
		pub, err := x509.ParsePKIXPublicKey(pubkeyData)
		if err != nil {
			// Try parsing as PKCS#1 RSA public key
			rsaPub, err := x509.ParsePKCS1PublicKey(pubkeyData)
			if err != nil {
				return nil, fmt.Errorf("invalid RSA public key: %v", err)
			}
			record.PublicKey = rsaPub
		} else {
			rsaPub, ok := pub.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("expected RSA public key")
			}
			record.PublicKey = rsaPub
		}

	case "ed25519":
		if len(pubkeyData) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid ed25519 key size: %d", len(pubkeyData))
		}
		record.PublicKey = ed25519.PublicKey(pubkeyData)

	default:
		return nil, fmt.Errorf("unknown key type: %s", record.Key)
	}

	return record, nil
}

// verifyWithKey verifies a signature with the given public key.
func verifyWithKey(key any, hash crypto.Hash, data, signature []byte) error {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, hash, data, signature)
	case ed25519.PublicKey:
		if !ed25519.Verify(k, data, signature) {
			return ErrSignatureFailed
		}
		return nil
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, data, signature) {
			return ErrSignatureFailed
		}
		return nil
	default:
		return fmt.Errorf("%w: %T", ErrAlgorithmUnknown, key)
	}
}

// isTLD checks if a domain is a top-level domain.
func isTLD(domain string) bool {
	if domain == "" {
		return false
	}
	// Get the eTLD+1 and compare
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		// If we can't determine, assume it's a TLD
		return true
	}
	// If domain equals eTLD+1, it's not a TLD
	// If domain has fewer labels than eTLD+1, it's a TLD
	return strings.Count(domain, ".") < strings.Count(eTLDPlusOne, ".")
}

// headerData stores a parsed header.
type headerData struct {
	raw  []byte // complete header including name: value
	lkey string // lowercase header name
}

// parseHeaders parses message headers.
func parseHeaders(r *bufio.Reader) ([]headerData, int, error) {
	var headers []headerData
	offset := 0

	for {
		// Read the header line
		line, err := readHeaderLine(r)
		if err != nil && err != io.EOF {
			return nil, 0, err
		}

		// Empty line signals end of headers
		if len(line) == 0 || (len(line) == 2 && line[0] == '\r' && line[1] == '\n') {
			offset += len(line)
			break
		}

		offset += len(line)

		// Skip continuation lines (they're part of the previous header)
		if line[0] == ' ' || line[0] == '\t' {
			if len(headers) > 0 {
				headers[len(headers)-1].raw = append(headers[len(headers)-1].raw, line...)
			}
			continue
		}

		// Parse header name
		before, _, ok := bytes.Cut(line, []byte{':'})
		if !ok {
			continue // Skip malformed headers
		}

		name := string(bytes.TrimSpace(before))
		headers = append(headers, headerData{
			raw:  line,
			lkey: strings.ToLower(name),
		})

		if err == io.EOF {
			break
		}
	}

	return headers, offset, nil
}

// readHeaderLine reads a complete header line (including folded lines).
func readHeaderLine(r *bufio.Reader) ([]byte, error) {
	var line []byte

	for {
		part, err := r.ReadBytes('\n')
		if len(part) > 0 {
			line = append(line, part...)
		}
		if err != nil {
			return line, err
		}

		// Check if next line is a continuation
		next, err := r.Peek(1)
		if err != nil || len(next) == 0 {
			return line, nil
		}
		if next[0] != ' ' && next[0] != '\t' {
			return line, nil
		}
	}
}

// extractHeaderValue extracts the value from a raw header (after the colon).
func extractHeaderValue(raw []byte) string {
	colonIdx := bytes.IndexByte(raw, ':')
	if colonIdx == -1 {
		return ""
	}
	value := string(raw[colonIdx+1:])
	// Remove trailing CRLF
	value = strings.TrimRight(value, "\r\n")
	return value
}

// atReader provides io.Reader over io.ReaderAt with an offset.
type atReader struct {
	r      io.ReaderAt
	offset int64
}

func (r *atReader) Read(p []byte) (int, error) {
	n, err := r.r.ReadAt(p, r.offset)
	r.offset += int64(n)
	return n, err
}
