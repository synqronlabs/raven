package dkim

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net"
	"testing"

	ravendns "github.com/synqronlabs/raven/dns"
)

// benchMessage is a realistic RFC 5322 message used for signing/verification benchmarks.
var benchMessage = []byte("From: sender@example.com\r\n" +
	"To: recipient@example.org\r\n" +
	"Subject: Benchmark Test Message\r\n" +
	"Date: Mon, 10 Mar 2026 12:00:00 +0000\r\n" +
	"Message-ID: <bench@example.com>\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"\r\n" +
	"This is a benchmark test message body with enough content to make the\r\n" +
	"body hash computation non-trivial. It simulates a typical short email.\r\n")

// benchSignatureHeader is a pre-formatted DKIM-Signature header for ParseSignature benchmarks.
const benchSignatureHeader = `DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=bench;` +
	` c=relaxed/relaxed; q=dns/txt; t=1741608000; x=1741694400;` +
	` h=from:to:subject:date:message-id;` +
	` bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;` +
	` b=c2lnbmF0dXJlYmFzZTY0ZGF0YWhlcmVmb3JiZW5jaG1hcms=`

// benchResolver is a minimal ravendns.Resolver stub used in DKIM verification benchmarks.
type benchDKIMResolver struct {
	records map[string][]string
}

func (r *benchDKIMResolver) LookupTXT(_ context.Context, name string) (ravendns.Result[string], error) {
	recs, ok := r.records[name]
	if !ok {
		return ravendns.Result[string]{}, ravendns.ErrDNSNotFound
	}
	return ravendns.Result[string]{Records: recs}, nil
}
func (*benchDKIMResolver) LookupIP(_ context.Context, _ string) (ravendns.Result[net.IP], error) {
	return ravendns.Result[net.IP]{}, nil
}
func (*benchDKIMResolver) LookupMX(_ context.Context, _ string) (ravendns.Result[*net.MX], error) {
	return ravendns.Result[*net.MX]{}, nil
}
func (*benchDKIMResolver) LookupAddr(_ context.Context, _ net.IP) (ravendns.Result[string], error) {
	return ravendns.Result[string]{}, nil
}

// setupRSASigner returns a Signer backed by a freshly generated RSA-2048 key
// together with the matching DKIM TXT record string.
func setupRSASigner(b *testing.B) (*Signer, string) {
	b.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey: %v", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		b.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	record := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pubBytes)
	signer := &Signer{
		Domain:                 "example.com",
		Selector:               "bench",
		PrivateKey:             key,
		Headers:                []string{"From", "To", "Subject", "Date", "Message-ID"},
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
	}
	return signer, record
}

// setupEd25519Signer returns a Signer backed by a freshly generated Ed25519 key
// together with the matching DKIM TXT record string.
// Ed25519 DKIM records store the raw 32-byte public key (not PKIX-wrapped).
func setupEd25519Signer(b *testing.B) (*Signer, string) {
	b.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("ed25519.GenerateKey: %v", err)
	}
	// RFC 8463: the p= tag for Ed25519 is the raw 32-byte public key,
	// not a PKIX-encoded SubjectPublicKeyInfo blob.
	record := "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString([]byte(pub))
	signer := &Signer{
		Domain:                 "example.com",
		Selector:               "bench-ed",
		PrivateKey:             priv,
		Headers:                []string{"From", "To", "Subject", "Date", "Message-ID"},
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
	}
	return signer, record
}

// BenchmarkSignRSA measures (*Signer).Sign with an RSA-2048 key (relaxed/relaxed).
func BenchmarkSignRSA(b *testing.B) {
	signer, _ := setupRSASigner(b)
	b.ResetTimer()
	for b.Loop() {
		if _, err := signer.Sign(benchMessage); err != nil {
			b.Fatalf("Sign: %v", err)
		}
	}
}

// BenchmarkSignEd25519 measures (*Signer).Sign with an Ed25519 key (relaxed/relaxed).
func BenchmarkSignEd25519(b *testing.B) {
	signer, _ := setupEd25519Signer(b)
	b.ResetTimer()
	for b.Loop() {
		if _, err := signer.Sign(benchMessage); err != nil {
			b.Fatalf("Sign: %v", err)
		}
	}
}

// BenchmarkVerifyRSA measures (*Verifier).Verify for a single valid RSA-2048 signature.
// DNS is served from an in-process map; the benchmark cost reflects header parsing,
// canonicalization, and RSA verification only.
func BenchmarkVerifyRSA(b *testing.B) {
	signer, record := setupRSASigner(b)

	sigHeader, err := signer.Sign(benchMessage)
	if err != nil {
		b.Fatalf("Sign: %v", err)
	}
	signedMsg := append([]byte(sigHeader), benchMessage...)

	resolver := &benchDKIMResolver{
		records: map[string][]string{
			"bench._domainkey.example.com": {record},
		},
	}
	verifier := &Verifier{Resolver: resolver}
	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		results, err := verifier.Verify(ctx, signedMsg)
		if err != nil {
			b.Fatalf("Verify: %v", err)
		}
		if len(results) == 0 || results[0].Status != StatusPass {
			b.Fatalf("expected StatusPass, got %v", results)
		}
	}
}

// BenchmarkVerifyEd25519 measures (*Verifier).Verify for a single valid Ed25519 signature.
func BenchmarkVerifyEd25519(b *testing.B) {
	signer, record := setupEd25519Signer(b)

	sigHeader, err := signer.Sign(benchMessage)
	if err != nil {
		b.Fatalf("Sign: %v", err)
	}
	signedMsg := append([]byte(sigHeader), benchMessage...)

	resolver := &benchDKIMResolver{
		records: map[string][]string{
			"bench-ed._domainkey.example.com": {record},
		},
	}
	verifier := &Verifier{Resolver: resolver}
	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		results, err := verifier.Verify(ctx, signedMsg)
		if err != nil {
			b.Fatalf("Verify: %v", err)
		}
		if len(results) == 0 || results[0].Status != StatusPass {
			b.Fatalf("expected StatusPass, got %v", results)
		}
	}
}

// BenchmarkParseSignature measures ParseSignature for a reasonably full header.
func BenchmarkParseSignature(b *testing.B) {
	for b.Loop() {
		if _, _, err := ParseSignature(benchSignatureHeader); err != nil {
			b.Fatalf("ParseSignature: %v", err)
		}
	}
}

// BenchmarkParseRecord measures ParseRecord for a minimal but realistic DKIM TXT record.
// The record is generated once from a live RSA key so the public key bytes are valid.
func BenchmarkParseRecord(b *testing.B) {
	// Build a genuinely valid DKIM TXT record using a live RSA keypair.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey: %v", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		b.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	record := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pubBytes)

	b.ResetTimer()
	for b.Loop() {
		if _, _, err := ParseRecord(record); err != nil {
			b.Fatalf("ParseRecord: %v", err)
		}
	}
}

// BenchmarkCanonicalizeHeaderRelaxed measures the header canonicalization hot path.
func BenchmarkCanonicalizeHeaderRelaxed(b *testing.B) {
	header := "Subject:   Re: [mailing-list]  some topic here   with  trailing spaces   "
	for b.Loop() {
		if _, err := canonicalizeHeaderRelaxed(header); err != nil {
			b.Fatalf("canonicalizeHeaderRelaxed: %v", err)
		}
	}
}

// BenchmarkSignMultipleRSA measures SignMultiple for two RSA signers sharing a body hash.
func BenchmarkSignMultipleRSA(b *testing.B) {
	signer1, _ := setupRSASigner(b)
	signer2, _ := setupRSASigner(b)
	// Use different selectors to make them distinct.
	signer2.Selector = "bench2"
	signers := []Signer{*signer1, *signer2}

	b.ResetTimer()
	for b.Loop() {
		if _, err := SignMultiple(benchMessage, signers); err != nil {
			b.Fatalf("SignMultiple: %v", err)
		}
	}
}
