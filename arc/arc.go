package arc

import (
	"crypto"
	"errors"
)

// Status represents the result of ARC chain validation per RFC 8617.
type Status string

const (
	// StatusNone indicates no ARC headers are present.
	StatusNone Status = "none"

	// StatusPass indicates all ARC sets validated successfully.
	StatusPass Status = "pass"

	// StatusFail indicates ARC validation failed.
	StatusFail Status = "fail"
)

// ChainValidationStatus represents the chain validation status (cv= tag).
type ChainValidationStatus string

const (
	// ChainValidationNone indicates no prior ARC chain.
	ChainValidationNone ChainValidationStatus = "none"

	// ChainValidationPass indicates the prior ARC chain validated.
	ChainValidationPass ChainValidationStatus = "pass"

	// ChainValidationFail indicates the prior ARC chain failed validation.
	ChainValidationFail ChainValidationStatus = "fail"
)

// Algorithm represents an ARC signing algorithm.
// ARC uses the same algorithms as DKIM.
type Algorithm string

const (
	// AlgRSASHA256 is the RSA-SHA256 algorithm (required by RFC 8617).
	AlgRSASHA256 Algorithm = "rsa-sha256"

	// AlgRSASHA1 is the deprecated RSA-SHA1 algorithm.
	AlgRSASHA1 Algorithm = "rsa-sha1"

	// AlgEd25519SHA256 is the Ed25519-SHA256 algorithm (RFC 8463).
	AlgEd25519SHA256 Algorithm = "ed25519-sha256"
)

// Canonicalization represents header/body canonicalization algorithms.
// ARC uses the same canonicalization as DKIM.
type Canonicalization string

const (
	// CanonSimple uses the "simple" canonicalization algorithm.
	CanonSimple Canonicalization = "simple"

	// CanonRelaxed uses the "relaxed" canonicalization algorithm.
	CanonRelaxed Canonicalization = "relaxed"
)

// Common errors for ARC processing.
var (
	// ErrNoARCHeaders indicates no ARC headers were found in the message.
	ErrNoARCHeaders = errors.New("arc: no ARC headers found")

	// ErrInvalidChain indicates the ARC chain is structurally invalid.
	ErrInvalidChain = errors.New("arc: invalid ARC chain structure")

	// ErrMissingSet indicates a required ARC set is missing.
	ErrMissingSet = errors.New("arc: missing ARC set")

	// ErrDuplicateSet indicates duplicate ARC sets with the same instance number.
	ErrDuplicateSet = errors.New("arc: duplicate ARC set instance")

	// ErrGapInChain indicates a gap in the ARC chain instance numbers.
	ErrGapInChain = errors.New("arc: gap in ARC chain instance numbers")

	// ErrInvalidInstance indicates an invalid instance number.
	ErrInvalidInstance = errors.New("arc: invalid instance number")

	// ErrInstanceTooHigh indicates the instance number exceeds the limit.
	ErrInstanceTooHigh = errors.New("arc: instance number exceeds limit (50)")

	// ErrSealFailed indicates the ARC-Seal verification failed.
	ErrSealFailed = errors.New("arc: seal verification failed")

	// ErrMessageSignatureFailed indicates the ARC-Message-Signature verification failed.
	ErrMessageSignatureFailed = errors.New("arc: message signature verification failed")

	// ErrChainValidationMismatch indicates the cv= tag doesn't match the actual chain state.
	ErrChainValidationMismatch = errors.New("arc: chain validation status mismatch")

	// ErrDNS indicates a DNS lookup error occurred.
	ErrDNS = errors.New("arc: DNS lookup error")

	// ErrNoRecord indicates no DNS record was found.
	ErrNoRecord = errors.New("arc: no DNS record found")

	// ErrSyntax indicates a syntax error in an ARC header.
	ErrSyntax = errors.New("arc: syntax error")

	// ErrMissingTag indicates a required tag is missing.
	ErrMissingTag = errors.New("arc: missing required tag")

	// ErrInvalidVersion indicates an invalid version tag.
	ErrInvalidVersion = errors.New("arc: invalid version")

	// ErrAlgorithmUnknown indicates an unknown signing algorithm.
	ErrAlgorithmUnknown = errors.New("arc: unknown algorithm")

	// ErrHashUnknown indicates an unknown hash algorithm.
	ErrHashUnknown = errors.New("arc: unknown hash algorithm")

	// ErrCanonicalizationUnknown indicates an unknown canonicalization algorithm.
	ErrCanonicalizationUnknown = errors.New("arc: unknown canonicalization")

	// ErrKeyRevoked indicates the signing key has been revoked.
	ErrKeyRevoked = errors.New("arc: key has been revoked")

	// ErrWeakKey indicates the key is too weak.
	ErrWeakKey = errors.New("arc: key is too weak")

	// ErrExpired indicates the signature has expired.
	ErrExpired = errors.New("arc: signature expired")

	// ErrBodyHashMismatch indicates the body hash doesn't match.
	ErrBodyHashMismatch = errors.New("arc: body hash mismatch")

	// ErrSignatureFailed indicates signature verification failed.
	ErrSignatureFailed = errors.New("arc: signature verification failed")

	// ErrInvalidAuthResults indicates invalid Authentication-Results header.
	ErrInvalidAuthResults = errors.New("arc: invalid Authentication-Results")

	// ErrTLD indicates the domain is a top-level domain.
	ErrTLD = errors.New("arc: domain is a top-level domain")

	// ErrFromRequired indicates the From header must be signed.
	ErrFromRequired = errors.New("arc: From header must be signed")
)

// MaxInstance is the maximum allowed ARC instance number per RFC 8617.
const MaxInstance = 50

// Result represents the result of ARC chain validation.
type Result struct {
	// Status is the overall chain validation status.
	Status Status

	// OldestPass is the instance number of the oldest passing ARC set.
	// This is useful for policy decisions about trusted intermediaries.
	// Zero if no sets passed.
	OldestPass int

	// Sets contains the parsed ARC sets, ordered by instance number.
	Sets []*Set

	// Err contains any error that occurred during validation.
	Err error

	// FailedInstance is the instance number where validation failed.
	// Zero if validation passed or no sets were present.
	FailedInstance int

	// FailedReason provides details about why validation failed.
	FailedReason string
}

// getHash returns the crypto.Hash for a given hash algorithm name.
func getHash(name string) (crypto.Hash, bool) {
	switch name {
	case "sha256":
		return crypto.SHA256, true
	case "sha1":
		return crypto.SHA1, true
	default:
		return 0, false
	}
}
