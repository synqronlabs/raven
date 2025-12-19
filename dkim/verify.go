package dkim

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/publicsuffix"

	ravendns "github.com/synqronlabs/raven/dns"
)

// Verifier provides DKIM signature verification.
type Verifier struct {
	// Resolver is the DNS resolver to use.
	Resolver ravendns.Resolver

	// IgnoreTestMode ignores the t=y flag in DKIM records.
	// When false (default), signatures from domains in test mode
	// that fail verification return StatusNone instead of StatusFail.
	IgnoreTestMode bool

	// Policy is a function that can reject signatures based on policy.
	// Return an error to reject the signature with StatusPolicy.
	// If nil, all signatures are accepted.
	Policy func(*Signature) error

	// MinRSAKeyBits is the minimum RSA key size to accept.
	// Default is 1024 (per RFC 8301).
	MinRSAKeyBits int
}

// Verify verifies all DKIM-Signature headers in the message.
// Returns a result for each signature found.
func (v *Verifier) Verify(ctx context.Context, message []byte) ([]Result, error) {
	return v.VerifyReader(ctx, bytes.NewReader(message))
}

// VerifyReader verifies all DKIM-Signature headers from a reader.
func (v *Verifier) VerifyReader(ctx context.Context, message io.ReaderAt) ([]Result, error) {
	// Parse headers
	br := bufio.NewReader(&atReader{r: message, offset: 0})
	headers, bodyOffset, err := parseHeaders(br)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHeaderMalformed, err)
	}

	var results []Result

	// Find all DKIM-Signature headers
	for _, hdr := range headers {
		if hdr.lkey != "dkim-signature" {
			continue
		}

		// Parse the signature
		sig, verifySig, err := ParseSignature(string(hdr.raw))
		if err != nil {
			results = append(results, Result{
				Status: StatusPermerror,
				Err:    fmt.Errorf("parsing signature: %w", err),
			})
			continue
		}

		// Check signature parameters
		hashFunc, headerCanon, bodyCanon, err := v.checkSignatureParams(sig)
		if err != nil {
			results = append(results, Result{
				Status:    StatusPermerror,
				Signature: sig,
				Err:       err,
			})
			continue
		}

		// Apply policy
		if v.Policy != nil {
			if err := v.Policy(sig); err != nil {
				results = append(results, Result{
					Status:    StatusPolicy,
					Signature: sig,
					Err:       fmt.Errorf("%w: %v", ErrPolicy, err),
				})
				continue
			}
		}

		// Verify the signature
		status, record, authentic, err := v.verifySignature(
			ctx, sig, hashFunc, headerCanon, bodyCanon,
			headers, verifySig, message, bodyOffset,
		)
		results = append(results, Result{
			Status:          status,
			Signature:       sig,
			Record:          record,
			RecordAuthentic: authentic,
			Err:             err,
		})
	}

	return results, nil
}

// checkSignatureParams validates signature parameters.
func (v *Verifier) checkSignatureParams(sig *Signature) (crypto.Hash, Canonicalization, Canonicalization, error) {
	// From header must be signed
	hasFrom := false
	for _, h := range sig.SignedHeaders {
		if strings.EqualFold(h, "from") {
			hasFrom = true
			break
		}
	}
	if !hasFrom {
		return 0, "", "", fmt.Errorf("%w: From header must be signed", ErrFromRequired)
	}

	// Check expiration
	if sig.ExpireTime >= 0 && sig.ExpireTime < timeNow().Unix() {
		return 0, "", "", fmt.Errorf("%w: expired at %d", ErrSigExpired, sig.ExpireTime)
	}

	// Check domain is not a TLD (must have at least 2 labels)
	// This prevents signing as "com" or other top-level domains
	// RFC 6376 Section 3.5 and publicsuffix considerations
	if isTLD(sig.Domain) {
		return 0, "", "", fmt.Errorf("%w: %s", ErrTLD, sig.Domain)
	}

	// Get hash algorithm
	hashAlg := sig.AlgorithmHash()
	h, ok := getHash(hashAlg)
	if !ok {
		return 0, "", "", fmt.Errorf("%w: %s", ErrHashAlgorithmUnknown, hashAlg)
	}

	// Parse canonicalization
	headerCanon := sig.HeaderCanon()
	bodyCanon := sig.BodyCanon()

	// Validate canonicalization algorithms
	if headerCanon != CanonSimple && headerCanon != CanonRelaxed {
		return 0, "", "", fmt.Errorf("%w: header %s", ErrCanonicalizationUnknown, headerCanon)
	}
	if bodyCanon != CanonSimple && bodyCanon != CanonRelaxed {
		return 0, "", "", fmt.Errorf("%w: body %s", ErrCanonicalizationUnknown, bodyCanon)
	}

	// Check query methods (only dns/txt is supported)
	if len(sig.QueryMethods) > 0 {
		hasDNS := false
		for _, m := range sig.QueryMethods {
			if strings.EqualFold(m, "dns/txt") {
				hasDNS = true
				break
			}
		}
		if !hasDNS {
			return 0, "", "", fmt.Errorf("%w: only dns/txt supported", ErrQueryMethod)
		}
	}

	return h, headerCanon, bodyCanon, nil
}

// verifySignature performs the actual signature verification.
func (v *Verifier) verifySignature(
	ctx context.Context,
	sig *Signature,
	hashFunc crypto.Hash,
	headerCanon, bodyCanon Canonicalization,
	headers []headerData,
	verifySig []byte,
	message io.ReaderAt,
	bodyOffset int,
) (Status, *Record, bool, error) {
	// Lookup the DKIM record
	record, txt, authentic, err := v.lookup(ctx, sig.Selector, sig.Domain)
	if err != nil {
		if IsTemporaryError(err) {
			return StatusTemperror, nil, authentic, err
		}
		return StatusPermerror, nil, authentic, err
	}

	// Verify against the record
	status, err := v.verifyWithRecord(
		record, sig, hashFunc, headerCanon, bodyCanon,
		headers, verifySig, message, bodyOffset,
	)

	// Handle test mode
	if !v.IgnoreTestMode && record.IsTesting() && status == StatusFail {
		return StatusNone, record, authentic, nil
	}

	_ = txt // For debugging
	return status, record, authentic, err
}

// verifyWithRecord verifies the signature against a DKIM record.
func (v *Verifier) verifyWithRecord(
	record *Record,
	sig *Signature,
	hashFunc crypto.Hash,
	headerCanon, bodyCanon Canonicalization,
	headers []headerData,
	verifySig []byte,
	message io.ReaderAt,
	bodyOffset int,
) (Status, error) {
	// Check if key is revoked
	if record.PublicKey == nil {
		return StatusPermerror, ErrKeyRevoked
	}

	// Check hash algorithm is allowed
	if !record.HashAllowed(sig.AlgorithmHash()) {
		return StatusPermerror, fmt.Errorf("%w: record allows %v, signature uses %s",
			ErrHashAlgNotAllowed, record.Hashes, sig.AlgorithmHash())
	}

	// Check key type matches
	if !strings.EqualFold(record.Key, sig.AlgorithmSign()) {
		return StatusPermerror, fmt.Errorf("%w: record specifies %s, signature uses %s",
			ErrSigAlgMismatch, record.Key, sig.AlgorithmSign())
	}

	// Check RSA key size
	if rsaKey, ok := record.PublicKey.(*rsa.PublicKey); ok {
		minBits := v.MinRSAKeyBits
		if minBits == 0 {
			minBits = 1024 // RFC 8301 minimum
		}
		if rsaKey.N.BitLen() < minBits {
			return StatusPermerror, fmt.Errorf("%w: %d bits, minimum %d",
				ErrWeakKey, rsaKey.N.BitLen(), minBits)
		}
	}

	// Check service allowed
	if !record.ServiceAllowed("email") {
		return StatusPermerror, ErrKeyNotForEmail
	}

	// Check strict domain alignment if required
	if record.RequireStrictAlignment() && sig.Identity != "" {
		atIdx := strings.LastIndex(sig.Identity, "@")
		if atIdx >= 0 {
			identityDomain := strings.ToLower(sig.Identity[atIdx+1:])
			if identityDomain != sig.Domain {
				return StatusPermerror, fmt.Errorf("%w: strict alignment required",
					ErrDomainIdentityMismatch)
			}
		}
	}

	// Body length not supported (security risk)
	if sig.Length >= 0 {
		return StatusPermerror, fmt.Errorf("body length limit (l=) not supported")
	}

	// Calculate data hash (headers + signature header)
	dataHash, err := computeDataHash(hashFunc.New(), headerCanon, headers, sig.SignedHeaders, verifySig)
	if err != nil {
		return StatusPermerror, fmt.Errorf("computing data hash: %w", err)
	}

	// Verify signature
	if err := verifyWithKey(record.PublicKey, hashFunc, dataHash, sig.Signature); err != nil {
		return StatusFail, fmt.Errorf("%w: %v", ErrSigVerify, err)
	}

	// Calculate body hash
	bodyReader := &atReader{r: message, offset: int64(bodyOffset)}
	bodyHash, err := computeBodyHashReader(hashFunc.New(), bodyCanon, bodyReader)
	if err != nil {
		return StatusTemperror, fmt.Errorf("computing body hash: %w", err)
	}

	// Compare body hashes
	if !bytes.Equal(sig.BodyHash, bodyHash) {
		return StatusFail, fmt.Errorf("%w: expected %x, got %x",
			ErrBodyHashMismatch, sig.BodyHash, bodyHash)
	}

	return StatusPass, nil
}

// lookup retrieves and parses the DKIM record from DNS.
func (v *Verifier) lookup(ctx context.Context, selector, domain string) (*Record, string, bool, error) {
	// Build the DNS name: <selector>._domainkey.<domain>
	name := selector + "._domainkey." + domain

	result, err := v.Resolver.LookupTXT(ctx, name)
	if err != nil {
		if ravendns.IsNotFound(err) {
			return nil, "", result.Authentic, fmt.Errorf("%w: %s", ErrNoRecord, name)
		}
		return nil, "", result.Authentic, fmt.Errorf("%w: %v", ErrDNS, err)
	}

	// Find a valid DKIM record
	var dkimRecord *Record
	var dkimTxt string

	for _, txt := range result.Records {
		record, isDKIM, err := ParseRecord(txt)
		if err != nil && isDKIM {
			// This looks like a DKIM record but is invalid
			return nil, txt, result.Authentic, fmt.Errorf("%w: %v", ErrSyntax, err)
		}
		if err != nil || !isDKIM {
			continue
		}

		// Found a valid DKIM record
		if dkimRecord != nil {
			// Multiple records is an error
			return nil, "", result.Authentic, fmt.Errorf("%w: %s", ErrMultipleRecords, name)
		}
		dkimRecord = record
		dkimTxt = txt
	}

	if dkimRecord == nil {
		return nil, "", result.Authentic, fmt.Errorf("%w: %s", ErrNoRecord, name)
	}

	return dkimRecord, dkimTxt, result.Authentic, nil
}

// IsTemporaryError returns true if the error is temporary.
func IsTemporaryError(err error) bool {
	if err == nil {
		return false
	}
	// Check if it's a DNS temporary error
	if ravendns.IsTemporary(err) {
		return true
	}
	// ErrDNS wraps DNS errors which may be temporary
	if errors.Is(err, ErrDNS) {
		// Unwrap to check if the underlying error is temporary
		var unwrapped error = err
		for unwrapped != nil {
			if ravendns.IsTemporary(unwrapped) {
				return true
			}
			unwrapped = errors.Unwrap(unwrapped)
		}
		// DNS errors are generally temporary unless we get NXDOMAIN
		return true
	}
	// Multiple records is a temporary error (might be fixed by DNS admin)
	if errors.Is(err, ErrMultipleRecords) {
		return true
	}
	return false
}

// Verify is a convenience function to verify DKIM signatures.
func Verify(ctx context.Context, resolver ravendns.Resolver, message []byte) ([]Result, error) {
	v := &Verifier{Resolver: resolver}
	return v.Verify(ctx, message)
}

// VerifyReader is a convenience function to verify DKIM signatures from a reader.
func VerifyReader(ctx context.Context, resolver ravendns.Resolver, message io.ReaderAt) ([]Result, error) {
	v := &Verifier{Resolver: resolver}
	return v.VerifyReader(ctx, message)
}

// atReader wraps an io.ReaderAt to provide io.Reader.
type atReader struct {
	r      io.ReaderAt
	offset int64
}

func (r *atReader) Read(p []byte) (n int, err error) {
	n, err = r.r.ReadAt(p, r.offset)
	r.offset += int64(n)
	return n, err
}

// isTLD checks if a domain is at or above the organizational domain level.
// A domain is considered a TLD if it's a public suffix (like "com", "co.uk")
// or doesn't have at least one label below the public suffix.
// Uses the Public Suffix List from publicsuffix.org for accurate detection.
func isTLD(domain string) bool {
	// Empty domain is invalid
	if domain == "" {
		return true
	}

	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")

	// Use EffectiveTLDPlusOne to check if the domain is at the organizational level
	// If domain equals its eTLD+1, it's at the organizational domain level (acceptable)
	// If EffectiveTLDPlusOne returns an error, the domain is likely a public suffix itself
	etldPlusOne, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		// Domain is a public suffix (TLD) or invalid
		return true
	}

	// If the domain equals its eTLD+1, it's a valid organizational domain
	// If it's shorter than eTLD+1, it's a TLD (shouldn't happen given the above check)
	return !strings.EqualFold(domain, etldPlusOne) && !strings.HasSuffix(strings.ToLower(domain), "."+strings.ToLower(etldPlusOne))
}
