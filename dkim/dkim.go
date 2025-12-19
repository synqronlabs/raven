// Package dkim implements DomainKeys Identified Mail (DKIM) signatures per RFC 6376.
//
// DKIM allows a sender to associate a domain name with an email message,
// thus vouching for its authenticity. A message is signed by adding a
// DKIM-Signature header, which contains a cryptographic signature of the
// message headers and body.
//
// This implementation supports:
//   - RSA-SHA256 (required by RFC 6376)
//   - RSA-SHA1 (deprecated, but supported for compatibility)
//   - Ed25519-SHA256 (RFC 8463)
//   - ECDSA-SHA256 (P-256, P-384, P-521 curves)
//
// # Basic Usage
//
// Signing a message:
//
//	signer := dkim.Signer{
//	    Domain:     "example.com",
//	    Selector:   "selector1",
//	    PrivateKey: privateKey,
//	}
//	signature, err := signer.Sign(message)
//
// Verifying a message:
//
//	results, err := dkim.Verify(ctx, resolver, message)
//	for _, r := range results {
//	    if r.Status == dkim.StatusPass {
//	        // Signature verified
//	    }
//	}
package dkim

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"time"
)

// Status represents the result of DKIM verification per RFC 8601.
type Status string

const (
	// StatusNone indicates the message was not signed.
	StatusNone Status = "none"

	// StatusPass indicates the signature was verified successfully.
	StatusPass Status = "pass"

	// StatusFail indicates the signature verification failed.
	StatusFail Status = "fail"

	// StatusPolicy indicates the signature is not accepted by policy.
	StatusPolicy Status = "policy"

	// StatusNeutral indicates the signature could not be processed.
	StatusNeutral Status = "neutral"

	// StatusTemperror indicates a temporary error (e.g., DNS timeout).
	StatusTemperror Status = "temperror"

	// StatusPermerror indicates a permanent error (e.g., invalid syntax).
	StatusPermerror Status = "permerror"
)

// Algorithm represents a DKIM signing algorithm.
type Algorithm string

const (
	// AlgRSASHA256 is the RSA-SHA256 algorithm (required by RFC 6376).
	AlgRSASHA256 Algorithm = "rsa-sha256"

	// AlgRSASHA1 is the deprecated RSA-SHA1 algorithm.
	AlgRSASHA1 Algorithm = "rsa-sha1"

	// AlgEd25519SHA256 is the Ed25519-SHA256 algorithm (RFC 8463).
	AlgEd25519SHA256 Algorithm = "ed25519-sha256"

	// AlgECDSASHA256 is ECDSA with SHA256 (for P-256, P-384, P-521 curves).
	AlgECDSASHA256 Algorithm = "ecdsa-sha256"
)

// Canonicalization represents header/body canonicalization algorithms.
type Canonicalization string

const (
	// CanonSimple uses the "simple" canonicalization algorithm.
	CanonSimple Canonicalization = "simple"

	// CanonRelaxed uses the "relaxed" canonicalization algorithm.
	CanonRelaxed Canonicalization = "relaxed"
)

// Common errors.
var (
	// DNS lookup errors.
	ErrNoRecord        = errors.New("dkim: no DKIM DNS record found")
	ErrMultipleRecords = errors.New("dkim: multiple DKIM DNS records found")
	ErrDNS             = errors.New("dkim: DNS lookup failed")
	ErrSyntax          = errors.New("dkim: syntax error in DKIM record")

	// Signature verification errors.
	ErrSigAlgMismatch          = errors.New("dkim: signature algorithm mismatch with DNS record")
	ErrHashAlgNotAllowed       = errors.New("dkim: hash algorithm not allowed by DNS record")
	ErrKeyNotForEmail          = errors.New("dkim: DNS record not allowed for email")
	ErrDomainIdentityMismatch  = errors.New("dkim: domain and identity mismatch")
	ErrSigExpired              = errors.New("dkim: signature has expired")
	ErrHashAlgorithmUnknown    = errors.New("dkim: unknown hash algorithm")
	ErrBodyHashMismatch        = errors.New("dkim: body hash does not match")
	ErrSigVerify               = errors.New("dkim: signature verification failed")
	ErrSigAlgorithmUnknown     = errors.New("dkim: unknown signature algorithm")
	ErrCanonicalizationUnknown = errors.New("dkim: unknown canonicalization")
	ErrHeaderMalformed         = errors.New("dkim: mail header is malformed")
	ErrFromRequired            = errors.New("dkim: From header is required")
	ErrQueryMethod             = errors.New("dkim: no recognized query method")
	ErrKeyRevoked              = errors.New("dkim: key has been revoked")
	ErrWeakKey                 = errors.New("dkim: key is too weak")
	ErrPolicy                  = errors.New("dkim: signature rejected by policy")
	ErrMissingTag              = errors.New("dkim: missing required tag")
	ErrDuplicateTag            = errors.New("dkim: duplicate tag")
	ErrInvalidVersion          = errors.New("dkim: invalid version")
	ErrTLD                     = errors.New("dkim: signed domain is top-level domain")
	ErrBodyHashLength          = errors.New("dkim: body hash length mismatch")
)

// Result represents the result of verifying a single DKIM-Signature.
type Result struct {
	// Status is the verification result.
	Status Status

	// Signature is the parsed DKIM-Signature header.
	Signature *Signature

	// Record is the parsed DKIM DNS record.
	Record *Record

	// RecordAuthentic indicates if the DNS record was DNSSEC-validated.
	RecordAuthentic bool

	// Err contains any error that occurred during verification.
	Err error
}

// DefaultSignedHeaders is the default list of headers to sign.
// These headers are commonly signed for message integrity.
var DefaultSignedHeaders = []string{
	"From",
	"To",
	"Cc",
	"Subject",
	"Date",
	"Message-ID",
	"In-Reply-To",
	"References",
	"MIME-Version",
	"Content-Type",
	"Content-Transfer-Encoding",
	"Content-Disposition",
	"Reply-To",
}

// MinimumSignedHeaders is the minimum set of headers that should be signed.
var MinimumSignedHeaders = []string{
	"From",
	"To",
	"Subject",
	"Date",
}

// timeNow is used for testing.
var timeNow = time.Now

// cryptoRand is the random source for signing.
var cryptoRand = rand.Reader

// signWithKey signs data with the given private key.
func signWithKey(key crypto.Signer, hash crypto.Hash, data []byte) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k.Sign(cryptoRand, data, hash)
	case ed25519.PrivateKey:
		// Ed25519 uses PureEdDSA, not pre-hashed data
		return k.Sign(cryptoRand, data, crypto.Hash(0))
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(cryptoRand, k, data)
	default:
		return nil, ErrSigAlgorithmUnknown
	}
}

// verifyWithKey verifies a signature with the given public key.
func verifyWithKey(key any, hash crypto.Hash, data, signature []byte) error {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, hash, data, signature)
	case ed25519.PublicKey:
		if !ed25519.Verify(k, data, signature) {
			return ErrSigVerify
		}
		return nil
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, data, signature) {
			return ErrSigVerify
		}
		return nil
	default:
		return ErrSigAlgorithmUnknown
	}
}
