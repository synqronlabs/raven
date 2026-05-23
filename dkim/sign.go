package dkim

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Signer provides DKIM message signing.
type Signer struct {
	// Domain is the signing domain (d= tag).
	Domain string

	// Selector is the selector for the signing key (s= tag).
	Selector string

	// PrivateKey is the signing key.
	// Supported types: *rsa.PrivateKey, ed25519.PrivateKey
	PrivateKey crypto.Signer

	// Headers is the list of headers to sign.
	// If empty, DefaultSignedHeaders is used.
	Headers []string

	// HeaderCanonicalization is the header canonicalization algorithm.
	// Default is CanonRelaxed.
	HeaderCanonicalization Canonicalization

	// BodyCanonicalization is the body canonicalization algorithm.
	// Default is CanonRelaxed.
	BodyCanonicalization Canonicalization

	// Hash is the hash algorithm name (e.g., "sha256").
	// Default is "sha256".
	Hash string

	// Identity is the signing identity (i= tag).
	// If empty, defaults to "@" + Domain.
	Identity string

	// Expiration is the signature validity period.
	// If zero, no expiration is set.
	Expiration time.Duration

	// OversignHeaders causes header names to be repeated to prevent header addition.
	// When enabled, each header in Headers is signed one more time than it appears
	// in the message, which prevents additional headers with the same name from
	// being added later.
	OversignHeaders bool
}

// Sign signs the message and returns the DKIM-Signature header.
// The message should be the complete RFC 5322 message (headers + body).
func (s *Signer) Sign(message []byte) (string, error) {
	return s.SignReader(bytes.NewReader(message), int64(len(message)))
}

// SignReader signs a complete RFC 5322 message from a seekable reader and
// returns the DKIM-Signature header. Message headers are parsed into memory, but
// the body is canonicalized from the reader without materializing it.
func (s *Signer) SignReader(message io.ReaderAt, size int64) (string, error) {
	if message == nil {
		return "", errors.New("dkim: message reader is nil")
	}
	headers, bodyOffset, err := parseReaderHeaders(message)
	if err != nil {
		return "", fmt.Errorf("parsing message headers: %w", err)
	}
	if err := validateSingleFrom(headers); err != nil {
		return "", err
	}
	if size < int64(bodyOffset) {
		return "", fmt.Errorf("dkim: message size %d is smaller than body offset %d", size, bodyOffset)
	}

	bodyReader := func() io.Reader {
		return io.NewSectionReader(message, int64(bodyOffset), size-int64(bodyOffset))
	}
	return s.signWithCachedBodyHashReader(headers, bodyReader, make(map[bodyHashKey][]byte))
}

// getAlgorithm determines the signing algorithm based on the private key type.
func (s *Signer) getAlgorithm() (Algorithm, string, error) {
	hashAlg := s.Hash
	if hashAlg == "" {
		hashAlg = "sha256"
	}

	switch s.PrivateKey.(type) {
	case *rsa.PrivateKey:
		switch strings.ToLower(hashAlg) {
		case "sha256":
			return AlgRSASHA256, "sha256", nil
		case "sha1":
			return AlgRSASHA1, "sha1", nil
		default:
			return "", "", fmt.Errorf("%w: %s", ErrHashAlgorithmUnknown, hashAlg)
		}

	case ed25519.PrivateKey:
		// Ed25519 always uses SHA256
		return AlgEd25519SHA256, "sha256", nil

	default:
		return "", "", fmt.Errorf("%w: %T", ErrSigAlgorithmUnknown, s.PrivateKey)
	}
}

// bodyHashKey is used to cache body hashes by canonicalization and hash algorithm.
type bodyHashKey struct {
	simple bool   // true for simple, false for relaxed canonicalization
	hash   string // lowercase hash algorithm (e.g., "sha256")
}

// SignMultiple signs the message with multiple selectors.
// Returns multiple DKIM-Signature headers concatenated.
// This function caches body hashes to avoid recomputation when multiple
// signers use the same canonicalization and hash algorithm.
func SignMultiple(message []byte, signers []Signer) (string, error) {
	return SignMultipleReader(bytes.NewReader(message), int64(len(message)), signers)
}

// SignMultipleReader signs a complete RFC 5322 message from a seekable reader
// with multiple selectors. Body hashes are cached by canonicalization and hash
// algorithm, and each uncached body pass reads from message without buffering it.
func SignMultipleReader(message io.ReaderAt, size int64, signers []Signer) (string, error) {
	if len(signers) == 0 {
		return "", nil
	}
	if message == nil {
		return "", errors.New("dkim: message reader is nil")
	}

	// Parse message once for all signers
	headers, bodyOffset, err := parseReaderHeaders(message)
	if err != nil {
		return "", fmt.Errorf("parsing message headers: %w", err)
	}
	if size < int64(bodyOffset) {
		return "", fmt.Errorf("dkim: message size %d is smaller than body offset %d", size, bodyOffset)
	}

	// Verify exactly one From header exists
	if err := validateSingleFrom(headers); err != nil {
		return "", err
	}

	// Cache for body hashes to avoid recomputation
	bodyHashes := make(map[bodyHashKey][]byte)
	bodyReader := func() io.Reader {
		return io.NewSectionReader(message, int64(bodyOffset), size-int64(bodyOffset))
	}

	var result strings.Builder

	for i := range signers {
		s := &signers[i]

		sig, err := s.signWithCachedBodyHashReader(headers, bodyReader, bodyHashes)
		if err != nil {
			return "", fmt.Errorf("signer %d: %w", i, err)
		}
		result.WriteString(sig)
	}

	return result.String(), nil
}

func parseReaderHeaders(message io.ReaderAt) ([]headerData, int, error) {
	br := bufio.NewReader(&atReader{r: message, offset: 0})
	return parseHeaders(br)
}

func validateSingleFrom(headers []headerData) error {
	fromCount := 0
	for _, h := range headers {
		if h.lkey == "from" {
			fromCount++
		}
	}
	if fromCount == 0 {
		return ErrFromRequired
	}
	if fromCount > 1 {
		return fmt.Errorf("%w: message has %d From headers, need exactly 1", ErrFromRequired, fromCount)
	}
	return nil
}

// signWithCachedBodyHash signs the message using cached body hashes.
func (s *Signer) signWithCachedBodyHash(headers []headerData, body []byte, bodyHashes map[bodyHashKey][]byte) (string, error) {
	return s.signWithCachedBodyHashReader(headers, func() io.Reader {
		return bytes.NewReader(body)
	}, bodyHashes)
}

func (s *Signer) signWithCachedBodyHashReader(headers []headerData, bodyReader func() io.Reader, bodyHashes map[bodyHashKey][]byte) (string, error) {
	// Build the signature
	sig := NewSignature()
	sig.Version = 1
	sig.Domain = s.Domain
	sig.Selector = s.Selector

	// Determine algorithm
	alg, hashAlg, err := s.getAlgorithm()
	if err != nil {
		return "", fmt.Errorf("determining signing algorithm: %w", err)
	}
	sig.Algorithm = string(alg)

	// Set canonicalization
	headerCanon := s.HeaderCanonicalization
	if headerCanon == "" {
		headerCanon = CanonRelaxed
	}
	bodyCanon := s.BodyCanonicalization
	if bodyCanon == "" {
		bodyCanon = CanonRelaxed
	}
	sig.Canonicalization = string(headerCanon) + "/" + string(bodyCanon)

	// Set signed headers
	signedHeaders := s.Headers
	if len(signedHeaders) == 0 {
		signedHeaders = DefaultSignedHeaders
	}

	// Ensure "from" is included
	hasFromInSigned := false
	for _, h := range signedHeaders {
		if strings.EqualFold(h, "from") {
			hasFromInSigned = true
			break
		}
	}
	if !hasFromInSigned {
		signedHeaders = append([]string{"From"}, signedHeaders...)
	}

	// Filter to only headers present in the message
	presentHeaders := make(map[string]int)
	for _, h := range headers {
		presentHeaders[h.lkey]++
	}

	var finalSignedHeaders []string
	for _, h := range signedHeaders {
		lh := strings.ToLower(h)
		if presentHeaders[lh] > 0 {
			finalSignedHeaders = append(finalSignedHeaders, h)
		}
	}

	// Oversign headers (add each header name one more time to prevent additions)
	if s.OversignHeaders {
		headerCounts := make(map[string]int)
		for _, h := range finalSignedHeaders {
			headerCounts[strings.ToLower(h)]++
		}
		for _, h := range finalSignedHeaders {
			lh := strings.ToLower(h)
			count := presentHeaders[lh]
			for headerCounts[lh] < count+1 {
				finalSignedHeaders = append(finalSignedHeaders, h)
				headerCounts[lh]++
			}
		}
	}

	sig.SignedHeaders = finalSignedHeaders

	// Set identity
	if s.Identity != "" {
		sig.Identity = s.Identity
	}

	// Set timestamp
	sig.SignTime = timeNow().Unix()

	// Set expiration
	if s.Expiration > 0 {
		sig.ExpireTime = sig.SignTime + int64(s.Expiration.Seconds())
	}

	h, _ := getHash(hashAlg)

	// Check cache for body hash
	hk := bodyHashKey{
		simple: bodyCanon == CanonSimple,
		hash:   strings.ToLower(hashAlg),
	}

	var bodyHash []byte
	if cached, ok := bodyHashes[hk]; ok {
		// Use cached body hash
		bodyHash = cached
	} else {
		bodyHash, err = computeBodyHashReader(h.New(), bodyCanon, bodyReader())
		if err != nil {
			return "", fmt.Errorf("computing body hash: %w", err)
		}
		bodyHashes[hk] = bodyHash
	}
	sig.BodyHash = bodyHash

	sigHeader, _ := sig.Header(false)

	// Calculate data hash (headers + signature header)
	dataHash, err := computeDataHash(h.New(), headerCanon, headers, finalSignedHeaders, []byte(sigHeader))
	if err != nil {
		return "", fmt.Errorf("computing data hash: %w", err)
	}

	// Sign the hash
	signature, err := signWithKey(s.PrivateKey, h, dataHash)
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	sig.Signature = signature

	finalHeader, _ := sig.Header(true)

	return finalHeader + "\r\n", nil
}
