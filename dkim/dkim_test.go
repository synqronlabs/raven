package dkim

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"hash"
	"io"
	"strings"
	"testing"
	"time"
)

func TestParseSignature(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantErr   bool
		checkFunc func(t *testing.T, sig *Signature)
	}{
		{
			name: "valid RSA signature",
			header: `DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1;
	c=relaxed/simple; q=dns/txt; t=1234567890; x=1234657890;
	h=from:to:subject:date; bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;
	b=c2lnbmF0dXJl`,
			wantErr: false,
			checkFunc: func(t *testing.T, sig *Signature) {
				if sig.Version != 1 {
					t.Errorf("version = %d, want 1", sig.Version)
				}
				if sig.Algorithm != "rsa-sha256" {
					t.Errorf("algorithm = %s, want rsa-sha256", sig.Algorithm)
				}
				if sig.Domain != "example.com" {
					t.Errorf("domain = %s, want example.com", sig.Domain)
				}
				if sig.Selector != "selector1" {
					t.Errorf("selector = %s, want selector1", sig.Selector)
				}
				if len(sig.SignedHeaders) != 4 {
					t.Errorf("len(signedHeaders) = %d, want 4", len(sig.SignedHeaders))
				}
			},
		},
		{
			name: "valid Ed25519 signature",
			header: `DKIM-Signature: v=1; a=ed25519-sha256; d=example.org; s=ed;
	h=from:to:subject; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=dGVzdHNpZ25hdHVyZXRlc3RzaWduYXR1cmV0ZXN0c2lnbmF0dXJldGVzdHNpZ24=`,
			wantErr: false,
			checkFunc: func(t *testing.T, sig *Signature) {
				if sig.Algorithm != "ed25519-sha256" {
					t.Errorf("algorithm = %s, want ed25519-sha256", sig.Algorithm)
				}
			},
		},
		{
			name:    "missing version",
			header:  `DKIM-Signature: a=rsa-sha256; d=example.com; s=sel; h=from; bh=dGVzdA==; b=dGVzdA==`,
			wantErr: true,
		},
		{
			name:    "invalid version",
			header:  `DKIM-Signature: v=2; a=rsa-sha256; d=example.com; s=sel; h=from; bh=dGVzdA==; b=dGVzdA==`,
			wantErr: true,
		},
		{
			name:    "missing domain",
			header:  `DKIM-Signature: v=1; a=rsa-sha256; s=sel; h=from; bh=dGVzdA==; b=dGVzdA==`,
			wantErr: true,
		},
		{
			name:    "missing selector",
			header:  `DKIM-Signature: v=1; a=rsa-sha256; d=example.com; h=from; bh=dGVzdA==; b=dGVzdA==`,
			wantErr: true,
		},
		{
			name:    "duplicate tag",
			header:  `DKIM-Signature: v=1; v=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=dGVzdA==; b=dGVzdA==`,
			wantErr: true,
		},
		{
			name:    "not a DKIM-Signature header",
			header:  `From: test@example.com`,
			wantErr: true,
		},
		{
			// Domain name must always be A-labels (punycode), not U-labels.
			// This tests internationalized domain name support per RFC 6376.
			name: "internationalized domain (A-label/punycode)",
			header: `DKIM-Signature: v=1; a=rsa-sha256; d=xn--h-bga.mox.example; s=xn--yr2021-pua;
	i=test@xn--h-bga.mox.example; t=1643719203; h=From:To:Subject:Date;
	bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=; b=dGVzdA==`,
			wantErr: false,
			checkFunc: func(t *testing.T, sig *Signature) {
				if sig.Domain != "xn--h-bga.mox.example" {
					t.Errorf("domain = %s, want xn--h-bga.mox.example", sig.Domain)
				}
				if sig.Selector != "xn--yr2021-pua" {
					t.Errorf("selector = %s, want xn--yr2021-pua", sig.Selector)
				}
				if sig.Identity != "test@xn--h-bga.mox.example" {
					t.Errorf("identity = %s, want test@xn--h-bga.mox.example", sig.Identity)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, _, err := ParseSignature(tt.header)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSignature() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, sig)
			}
		})
	}
}

func TestSignatureHeader(t *testing.T) {
	// Use a valid 32-byte SHA256 body hash
	bodyHash := make([]byte, 32)
	for i := range bodyHash {
		bodyHash[i] = byte(i)
	}

	sig := &Signature{
		Version:          1,
		Algorithm:        "rsa-sha256",
		Domain:           "example.com",
		Selector:         "selector1",
		Canonicalization: "relaxed/relaxed",
		SignedHeaders:    []string{"from", "to", "subject"},
		BodyHash:         bodyHash,
		Signature:        []byte("test signature data here1234"),
		SignTime:         1234567890,
		ExpireTime:       1534567890, // Must be after SignTime
	}

	header, err := sig.Header(true)
	if err != nil {
		t.Fatalf("Header() error = %v", err)
	}

	// Parse back to verify
	parsed, _, err := ParseSignature(header)
	if err != nil {
		t.Fatalf("ParseSignature() error = %v", err)
	}

	if parsed.Domain != sig.Domain {
		t.Errorf("domain = %s, want %s", parsed.Domain, sig.Domain)
	}
	if parsed.Selector != sig.Selector {
		t.Errorf("selector = %s, want %s", parsed.Selector, sig.Selector)
	}
	if parsed.Algorithm != sig.Algorithm {
		t.Errorf("algorithm = %s, want %s", parsed.Algorithm, sig.Algorithm)
	}
}

func TestParseRecord(t *testing.T) {
	// Valid RSA public key for testing
	validRSAPubKey := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7/eFqG3MnlmOHvZBqPFZX/Nah8le7H92CVfzMoj2hgCQ8JaXbDxEG5XwP7t8LSqkcanRhAyX0YtlJX9b5YfSZuNU0OZEVW0345Xacy44sWq5n0lBG9KwYYWEhNHurL6fIyZHqZxkJx+ALeC4pAOYklAUe5EyQ6ONLlZsRtyO/OqOwocsbD5ndOjdmT+1lYoLOIFGSyloA84591QQvgX0+rL2wQv5ZUrFivG6wB7IZ9hc3/73reToRAo5XRD/Y6Zp9SW8oRQXGxl07Ia+jl6ZGyMvjBx1WVznyU1L5gBCYjInvwi3K1PxMhuMi/QmvYgk7P33l6rKYY4c2bzPH7JGcQIDAQAB"

	tests := []struct {
		name      string
		txt       string
		wantErr   bool
		isDKIM    bool
		checkFunc func(t *testing.T, record *Record)
	}{
		{
			name:    "valid RSA record",
			txt:     "v=DKIM1; k=rsa; p=" + validRSAPubKey,
			wantErr: false,
			isDKIM:  true,
			checkFunc: func(t *testing.T, record *Record) {
				if record.Version != "DKIM1" {
					t.Errorf("version = %s, want DKIM1", record.Version)
				}
				if record.Key != "rsa" {
					t.Errorf("key = %s, want rsa", record.Key)
				}
				if record.PublicKey == nil {
					t.Error("publicKey is nil")
				}
			},
		},
		{
			name:    "Ed25519 record",
			txt:     "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
			wantErr: false,
			isDKIM:  true,
			checkFunc: func(t *testing.T, record *Record) {
				if record.Key != "ed25519" {
					t.Errorf("key = %s, want ed25519", record.Key)
				}
			},
		},
		{
			name:    "revoked key",
			txt:     "v=DKIM1; k=rsa; p=",
			wantErr: false,
			isDKIM:  true,
			checkFunc: func(t *testing.T, record *Record) {
				if record.PublicKey != nil {
					t.Error("publicKey should be nil for revoked key")
				}
			},
		},
		{
			name:    "with flags",
			txt:     "v=DKIM1; k=rsa; t=y:s; p=" + validRSAPubKey,
			wantErr: false,
			isDKIM:  true,
			checkFunc: func(t *testing.T, record *Record) {
				if !record.IsTesting() {
					t.Error("should be testing")
				}
				if !record.RequireStrictAlignment() {
					t.Error("should require strict alignment")
				}
			},
		},
		{
			name:    "with hash algorithms",
			txt:     "v=DKIM1; h=sha256; p=" + validRSAPubKey,
			wantErr: false,
			isDKIM:  true,
			checkFunc: func(t *testing.T, record *Record) {
				if !record.HashAllowed("sha256") {
					t.Error("sha256 should be allowed")
				}
				if record.HashAllowed("sha1") {
					t.Error("sha1 should not be allowed")
				}
			},
		},
		{
			name:    "not a DKIM record",
			txt:     "some random text record",
			wantErr: true,
			isDKIM:  false,
		},
		{
			name:    "missing public key",
			txt:     "v=DKIM1; k=rsa",
			wantErr: true,
			isDKIM:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record, isDKIM, err := ParseRecord(tt.txt)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecord() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if isDKIM != tt.isDKIM {
				t.Errorf("isDKIM = %v, want %v", isDKIM, tt.isDKIM)
			}
			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, record)
			}
		})
	}
}

func TestRecordToTXT(t *testing.T) {
	// Generate a valid RSA key pair for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	record := &Record{
		Version:   "DKIM1",
		Key:       "rsa",
		Hashes:    []string{"sha256"},
		Services:  []string{"email"},
		Flags:     []string{"y"},
		PublicKey: &privateKey.PublicKey,
	}

	txt, err := record.ToTXT()
	if err != nil {
		t.Fatalf("ToTXT() error = %v", err)
	}

	// Parse back
	parsed, isDKIM, err := ParseRecord(txt)
	if err != nil {
		t.Fatalf("ParseRecord() error = %v", err)
	}
	if !isDKIM {
		t.Error("should be DKIM record")
	}
	if parsed.Version != record.Version {
		t.Errorf("version = %s, want %s", parsed.Version, record.Version)
	}
}

func TestSignAndVerifyRSA(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	message := []byte("From: sender@example.com\r\n" +
		"To: recipient@example.org\r\n" +
		"Subject: Test Message\r\n" +
		"Date: Thu, 18 Dec 2025 12:00:00 +0000\r\n" +
		"MIME-Version: 1.0\r\n" +
		"\r\n" +
		"This is a test message.\r\n")

	signer := &Signer{
		Domain:                 "example.com",
		Selector:               "test",
		PrivateKey:             privateKey,
		Headers:                []string{"From", "To", "Subject", "Date"},
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
	}

	sigHeader, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if sigHeader == "" {
		t.Error("signature header is empty")
	}

	// Parse the signature to verify structure
	sig, _, err := ParseSignature(sigHeader[:len(sigHeader)-2]) // Remove trailing CRLF
	if err != nil {
		t.Fatalf("ParseSignature() error = %v", err)
	}

	if sig.Domain != "example.com" {
		t.Errorf("domain = %s, want example.com", sig.Domain)
	}
	if sig.Selector != "test" {
		t.Errorf("selector = %s, want test", sig.Selector)
	}
	if sig.Algorithm != "rsa-sha256" {
		t.Errorf("algorithm = %s, want rsa-sha256", sig.Algorithm)
	}
}

func TestSignAndVerifyEd25519(t *testing.T) {
	// Generate Ed25519 key pair
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	message := []byte("From: sender@example.com\r\n" +
		"To: recipient@example.org\r\n" +
		"Subject: Test Message\r\n" +
		"Date: Thu, 18 Dec 2025 12:00:00 +0000\r\n" +
		"\r\n" +
		"This is a test message.\r\n")

	signer := &Signer{
		Domain:                 "example.com",
		Selector:               "ed25519",
		PrivateKey:             privateKey,
		Headers:                []string{"From", "To", "Subject", "Date"},
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
	}

	sigHeader, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Parse the signature
	sig, _, err := ParseSignature(sigHeader[:len(sigHeader)-2])
	if err != nil {
		t.Fatalf("ParseSignature() error = %v", err)
	}

	if sig.Algorithm != "ed25519-sha256" {
		t.Errorf("algorithm = %s, want ed25519-sha256", sig.Algorithm)
	}
}

func TestSignAndVerifyECDSA(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			// Generate ECDSA key pair
			privateKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}

			message := []byte("From: sender@example.com\r\n" +
				"To: recipient@example.org\r\n" +
				"Subject: Test Message\r\n" +
				"Date: Thu, 18 Dec 2025 12:00:00 +0000\r\n" +
				"\r\n" +
				"This is a test message.\r\n")

			signer := &Signer{
				Domain:                 "example.com",
				Selector:               "ecdsa",
				PrivateKey:             privateKey,
				Headers:                []string{"From", "To", "Subject", "Date"},
				HeaderCanonicalization: CanonRelaxed,
				BodyCanonicalization:   CanonRelaxed,
			}

			sigHeader, err := signer.Sign(message)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			// Parse the signature
			sig, _, err := ParseSignature(sigHeader[:len(sigHeader)-2])
			if err != nil {
				t.Fatalf("ParseSignature() error = %v", err)
			}

			if sig.Algorithm != "ecdsa-sha256" {
				t.Errorf("algorithm = %s, want ecdsa-sha256", sig.Algorithm)
			}
		})
	}
}

func TestCanonicalizationRelaxed(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "lowercase name",
			header: "SUBJECT: Test",
			want:   "subject:Test",
		},
		{
			name:   "compress whitespace",
			header: "Subject:  Test   Value  ",
			want:   "subject:Test Value",
		},
		{
			name:   "unfold header",
			header: "Subject: Test\r\n\t continuation",
			want:   "subject:Test continuation",
		},
		{
			name:   "trim trailing whitespace",
			header: "Subject: Test   ",
			want:   "subject:Test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := canonicalizeHeaderRelaxed(tt.header)
			if err != nil {
				t.Fatalf("canonicalizeHeaderRelaxed() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("canonicalizeHeaderRelaxed() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBodyHashSimple(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"simple body", "Hello World\r\n"},
		{"multiple lines", "Line 1\r\nLine 2\r\n"},
		{"trailing CRLF", "Body\r\n\r\n\r\n"},
		{"no trailing CRLF", "Body"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := getHashInstance("sha256")
			_, err := bodyHashSimple(h, newStringReader(tt.body))
			if err != nil {
				t.Fatalf("bodyHashSimple() error = %v", err)
			}
		})
	}
}

func TestBodyHashRelaxed(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"simple body", "Hello World\r\n"},
		{"whitespace", "Hello   World  \r\n"},
		{"trailing empty lines", "Body\r\n\r\n\r\n"},
		{"tabs", "Hello\tWorld\r\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := getHashInstance("sha256")
			_, err := bodyHashRelaxed(h, newStringReader(tt.body))
			if err != nil {
				t.Fatalf("bodyHashRelaxed() error = %v", err)
			}
		})
	}
}

func TestSignerExpiration(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	message := []byte("From: sender@example.com\r\n" +
		"To: recipient@example.org\r\n" +
		"Subject: Test Message\r\n" +
		"Date: Thu, 18 Dec 2025 12:00:00 +0000\r\n" +
		"\r\n" +
		"This is a test message.\r\n")

	signer := &Signer{
		Domain:     "example.com",
		Selector:   "test",
		PrivateKey: privateKey,
		Headers:    []string{"From", "To", "Subject", "Date"},
		Expiration: 24 * time.Hour,
	}

	sigHeader, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	sig, _, err := ParseSignature(sigHeader[:len(sigHeader)-2])
	if err != nil {
		t.Fatalf("ParseSignature() error = %v", err)
	}

	if sig.ExpireTime < 0 {
		t.Error("expireTime should be set")
	}
	if sig.ExpireTime <= sig.SignTime {
		t.Error("expireTime should be after signTime")
	}
}

func TestOversignHeaders(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	message := []byte("From: sender@example.com\r\n" +
		"To: recipient@example.org\r\n" +
		"Subject: Test Message\r\n" +
		"Date: Thu, 18 Dec 2025 12:00:00 +0000\r\n" +
		"\r\n" +
		"This is a test message.\r\n")

	signer := &Signer{
		Domain:          "example.com",
		Selector:        "test",
		PrivateKey:      privateKey,
		Headers:         []string{"From", "To", "Subject", "Date"},
		OversignHeaders: true,
	}

	sigHeader, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	sig, _, err := ParseSignature(sigHeader[:len(sigHeader)-2])
	if err != nil {
		t.Fatalf("ParseSignature() error = %v", err)
	}

	// With oversigning, each header should appear twice in the signed headers list
	counts := make(map[string]int)
	for _, h := range sig.SignedHeaders {
		counts[strings.ToLower(h)]++
	}

	for h, count := range counts {
		if count < 2 {
			t.Errorf("header %s appears %d times, want >= 2", h, count)
		}
	}
}

func TestIsTLD(t *testing.T) {
	tests := []struct {
		domain string
		isTLD  bool
	}{
		// TLDs - should return true
		{"com", true},
		{"org", true},
		{"uk", true},
		{"co.uk", true},  // Multi-label public suffix
		{"com.au", true}, // Multi-label public suffix
		{"co.jp", true},  // Multi-label public suffix
		{"", true},       // Empty domain

		// Valid organizational domains - should return false
		{"example.com", false},
		{"example.org", false},
		{"example.co.uk", false},    // eTLD+1 for co.uk
		{"example.com.au", false},   // eTLD+1 for com.au
		{"mail.example.com", false}, // Subdomain

		// Subdomains - should return false
		{"sub.example.com", false},
		{"deep.sub.example.co.uk", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := isTLD(tt.domain)
			if got != tt.isTLD {
				t.Errorf("isTLD(%q) = %v, want %v", tt.domain, got, tt.isTLD)
			}
		})
	}
}

func getHashInstance(algorithm string) hash.Hash {
	h, _ := getHash(algorithm)
	return h.New()
}

// newStringReader creates a simple string reader for tests using standard library
func newStringReader(s string) io.Reader {
	return strings.NewReader(s)
}

// TestSignMultiple tests signing a message with multiple selectors.
func TestSignMultiple(t *testing.T) {
	// Generate RSA key pair
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey RSA: %v", err)
	}

	// Generate Ed25519 key pair
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey Ed25519: %v", err)
	}

	// Generate ECDSA key pair
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey ECDSA: %v", err)
	}

	message := []byte("From: sender@example.com\r\n" +
		"To: recipient@example.org\r\n" +
		"Subject: Test Multiple Signatures\r\n" +
		"Date: Thu, 18 Dec 2025 12:00:00 +0000\r\n" +
		"Message-ID: <test@example.com>\r\n" +
		"\r\n" +
		"This is a test message with multiple DKIM signatures.\r\n")

	signers := []Signer{
		{
			Domain:                 "example.com",
			Selector:               "rsa1",
			PrivateKey:             rsaKey,
			Headers:                []string{"From", "To", "Subject", "Date"},
			HeaderCanonicalization: CanonRelaxed,
			BodyCanonicalization:   CanonRelaxed,
		},
		{
			Domain:                 "example.com",
			Selector:               "rsa2",
			PrivateKey:             rsaKey,
			Headers:                []string{"From", "To", "Subject", "Date", "Message-ID"},
			HeaderCanonicalization: CanonRelaxed,
			BodyCanonicalization:   CanonSimple, // Different body canonicalization
		},
		{
			Domain:                 "example.com",
			Selector:               "ed25519",
			PrivateKey:             ed25519Key,
			Headers:                []string{"From", "To", "Subject", "Date"},
			HeaderCanonicalization: CanonRelaxed,
			BodyCanonicalization:   CanonRelaxed,
		},
		{
			Domain:                 "example.com",
			Selector:               "ecdsa",
			PrivateKey:             ecdsaKey,
			Headers:                []string{"From", "To", "Subject"},
			HeaderCanonicalization: CanonSimple,
			BodyCanonicalization:   CanonSimple,
		},
	}

	// Sign with multiple selectors
	sigHeaders, err := SignMultiple(message, signers)
	if err != nil {
		t.Fatalf("SignMultiple() error = %v", err)
	}

	// Count the number of DKIM-Signature headers
	sigCount := strings.Count(sigHeaders, "DKIM-Signature:")
	if sigCount != 4 {
		t.Errorf("expected 4 DKIM-Signature headers, got %d", sigCount)
	}

	// Parse each signature header
	headers := strings.Split(sigHeaders, "DKIM-Signature:")
	parsedCount := 0
	for _, h := range headers {
		if strings.TrimSpace(h) == "" {
			continue
		}
		sig, stripped, err := ParseSignature("DKIM-Signature:" + h)
		if err != nil {
			t.Errorf("ParseSignature() error = %v", err)
			continue
		}
		parsedCount++

		// Verify b= value was stripped
		if strings.Contains(string(stripped), "b=") {
			// b= should be present but empty
			if !strings.Contains(string(stripped), "b=;") && !strings.HasSuffix(strings.TrimSpace(string(stripped)), "b=") {
				t.Errorf("stripped header should have empty b= value")
			}
		}

		// Verify domain
		if sig.Domain != "example.com" {
			t.Errorf("domain = %s, want example.com", sig.Domain)
		}

		// Verify algorithm matches key type
		switch sig.Selector {
		case "rsa1", "rsa2":
			if sig.Algorithm != "rsa-sha256" {
				t.Errorf("selector %s: algorithm = %s, want rsa-sha256", sig.Selector, sig.Algorithm)
			}
		case "ed25519":
			if sig.Algorithm != "ed25519-sha256" {
				t.Errorf("selector %s: algorithm = %s, want ed25519-sha256", sig.Selector, sig.Algorithm)
			}
		case "ecdsa":
			if sig.Algorithm != "ecdsa-sha256" {
				t.Errorf("selector %s: algorithm = %s, want ecdsa-sha256", sig.Selector, sig.Algorithm)
			}
		}
	}

	if parsedCount != 4 {
		t.Errorf("expected to parse 4 signatures, got %d", parsedCount)
	}
}

// TestSignMultipleBodyHashCaching tests that body hashes are cached correctly.
func TestSignMultipleBodyHashCaching(t *testing.T) {
	// Generate RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Use a body with trailing whitespace that will produce different hashes
	// for simple vs relaxed canonicalization.
	// Relaxed removes trailing whitespace from lines, simple does not.
	message := []byte("From: sender@example.com\r\n" +
		"To: recipient@example.org\r\n" +
		"Subject: Test Body Hash Caching\r\n" +
		"\r\n" +
		"Line with trailing spaces   \r\n" +
		"Another line with tabs\t\t\r\n" +
		"Final line.\r\n")

	// Two signers with same canonicalization should share body hash
	signers := []Signer{
		{
			Domain:                 "example.com",
			Selector:               "sel1",
			PrivateKey:             rsaKey,
			Headers:                []string{"From", "To", "Subject"},
			HeaderCanonicalization: CanonRelaxed,
			BodyCanonicalization:   CanonRelaxed,
		},
		{
			Domain:                 "example.com",
			Selector:               "sel2",
			PrivateKey:             rsaKey,
			Headers:                []string{"From", "To"},
			HeaderCanonicalization: CanonRelaxed,
			BodyCanonicalization:   CanonRelaxed, // Same as sel1
		},
		{
			Domain:                 "example.com",
			Selector:               "sel3",
			PrivateKey:             rsaKey,
			Headers:                []string{"From"},
			HeaderCanonicalization: CanonRelaxed,
			BodyCanonicalization:   CanonSimple, // Different - should have different body hash
		},
	}

	sigHeaders, err := SignMultiple(message, signers)
	if err != nil {
		t.Fatalf("SignMultiple() error = %v", err)
	}

	// Parse signatures and collect body hashes
	bodyHashes := make(map[string]string) // selector -> body hash
	headers := strings.Split(sigHeaders, "DKIM-Signature:")
	for _, h := range headers {
		if strings.TrimSpace(h) == "" {
			continue
		}
		sig, _, err := ParseSignature("DKIM-Signature:" + h)
		if err != nil {
			t.Errorf("ParseSignature() error = %v", err)
			continue
		}
		bodyHashes[sig.Selector] = string(sig.BodyHash)
	}

	// sel1 and sel2 should have same body hash (same relaxed/relaxed)
	if bodyHashes["sel1"] != bodyHashes["sel2"] {
		t.Errorf("sel1 and sel2 should have same body hash (same canonicalization)")
	}

	// sel3 should have different body hash (simple body canon)
	if bodyHashes["sel1"] == bodyHashes["sel3"] {
		t.Errorf("sel1 and sel3 should have different body hash (different body canonicalization)")
	}
}

// TestSignMultipleEmpty tests SignMultiple with empty signers.
func TestSignMultipleEmpty(t *testing.T) {
	message := []byte("From: sender@example.com\r\n\r\nTest\r\n")

	result, err := SignMultiple(message, nil)
	if err != nil {
		t.Fatalf("SignMultiple(nil) error = %v", err)
	}
	if result != "" {
		t.Errorf("expected empty result, got %q", result)
	}

	result, err = SignMultiple(message, []Signer{})
	if err != nil {
		t.Fatalf("SignMultiple([]) error = %v", err)
	}
	if result != "" {
		t.Errorf("expected empty result, got %q", result)
	}
}

// TestSignMultipleErrors tests error handling in SignMultiple.
func TestSignMultipleErrors(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Message with no From header
	messageNoFrom := []byte("To: recipient@example.org\r\n\r\nTest\r\n")

	signers := []Signer{
		{
			Domain:     "example.com",
			Selector:   "test",
			PrivateKey: rsaKey,
		},
	}

	_, err := SignMultiple(messageNoFrom, signers)
	if err == nil {
		t.Error("expected error for message without From header")
	}

	// Message with multiple From headers
	messageMultiFrom := []byte("From: a@example.com\r\nFrom: b@example.com\r\n\r\nTest\r\n")

	_, err = SignMultiple(messageMultiFrom, signers)
	if err == nil {
		t.Error("expected error for message with multiple From headers")
	}
}

// TestSignErrors tests error handling during single-signer Sign.
func TestSignErrors(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	signer := &Signer{
		Domain:     "example.com",
		Selector:   "test",
		PrivateKey: rsaKey,
		Headers:    []string{"From", "To", "Subject"},
	}

	tests := []struct {
		name    string
		message string
		wantErr bool
	}{
		{
			name:    "no From header",
			message: "To: recipient@example.org\r\n\r\nTest\r\n",
			wantErr: true,
		},
		{
			name:    "multiple From headers",
			message: "From: a@example.com\r\nFrom: b@example.com\r\n\r\nTest\r\n",
			wantErr: true,
		},
		{
			name:    "empty header key",
			message: ":\r\n\r\nTest\r\n",
			wantErr: true,
		},
		{
			name:    "header with space before colon",
			message: " From: sender@example.com\r\n\r\nTest\r\n",
			wantErr: true,
		},
		{
			name:    "message without body separator",
			message: "From: sender@example.com",
			wantErr: true,
		},
		{
			name:    "valid message",
			message: "From: sender@example.com\r\nTo: recipient@example.org\r\n\r\nTest\r\n",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := signer.Sign([]byte(tt.message))
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
