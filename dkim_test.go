package raven

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

// Test RSA key pair for DKIM tests (2048 bits)
var testDKIMPrivateKey *rsa.PrivateKey
var testDKIMPublicKey *rsa.PublicKey

func init() {
	// Generate a test key pair
	var err error
	testDKIMPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate test key: " + err.Error())
	}
	testDKIMPublicKey = &testDKIMPrivateKey.PublicKey
}

// mockDNSResolver creates a mock DNS resolver for testing.
func mockDNSResolver(domain, selector string, publicKey *rsa.PublicKey) func(string) ([]string, error) {
	record, _ := FormatDKIMPublicKeyRecord(publicKey)
	expectedDomain := selector + "._domainkey." + domain
	return func(name string) ([]string, error) {
		if name == expectedDomain {
			return []string{record}, nil
		}
		return nil, &mockDNSError{isNotFound: true}
	}
}

type mockDNSError struct {
	isNotFound bool
	isTimeout  bool
}

func (e *mockDNSError) Error() string {
	if e.isNotFound {
		return "dns: name not found"
	}
	if e.isTimeout {
		return "dns: timeout"
	}
	return "dns: error"
}

func TestDKIMSignAndVerify(t *testing.T) {
	// Create a test mail
	mail := NewMail()
	mail.SetFrom(MailboxAddress{LocalPart: "sender", Domain: "example.com"})
	mail.AddRecipient(MailboxAddress{LocalPart: "recipient", Domain: "example.org"})
	mail.AddHeader("From", "sender@example.com")
	mail.AddHeader("To", "recipient@example.org")
	mail.AddHeader("Subject", "Test DKIM Signing")
	mail.AddHeader("Date", "Thu, 12 Dec 2024 10:00:00 +0000")
	mail.AddHeader("Message-ID", "<test123@example.com>")
	mail.Content.Body = []byte("This is a test message.\r\n")

	// Sign the mail
	opts := &DKIMSignOptions{
		Domain:     "example.com",
		Selector:   "selector1",
		PrivateKey: testDKIMPrivateKey,
	}

	err := mail.SignDKIM(opts)
	if err != nil {
		t.Fatalf("Failed to sign mail: %v", err)
	}

	// Check that DKIM-Signature header was added
	if !mail.HasDKIMSignature() {
		t.Fatal("DKIM-Signature header not found after signing")
	}

	// Verify the signature
	verifyOpts := &DKIMVerifyOptions{
		DNSResolver: mockDNSResolver("example.com", "selector1", testDKIMPublicKey),
	}

	results := mail.VerifyDKIM(verifyOpts)
	if len(results) == 0 {
		t.Fatal("No verification results returned")
	}

	if results[0].Status != DKIMStatusPass {
		t.Errorf("Expected DKIMStatusPass, got %s: %v", results[0].Status, results[0].Error)
	}

	if results[0].Domain != "example.com" {
		t.Errorf("Expected domain example.com, got %s", results[0].Domain)
	}

	if results[0].Selector != "selector1" {
		t.Errorf("Expected selector selector1, got %s", results[0].Selector)
	}
}

func TestDKIMSignWithCustomHeaders(t *testing.T) {
	mail := NewMail()
	mail.SetFrom(MailboxAddress{LocalPart: "sender", Domain: "example.com"})
	mail.AddHeader("From", "sender@example.com")
	mail.AddHeader("To", "recipient@example.org")
	mail.AddHeader("Subject", "Custom Headers Test")
	mail.AddHeader("X-Custom-Header", "custom value")
	mail.Content.Body = []byte("Test body.\r\n")

	opts := &DKIMSignOptions{
		Domain:     "example.com",
		Selector:   "test",
		PrivateKey: testDKIMPrivateKey,
		Headers:    []string{"From", "To", "Subject", "X-Custom-Header"},
	}

	err := mail.SignDKIM(opts)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify
	verifyOpts := &DKIMVerifyOptions{
		DNSResolver: mockDNSResolver("example.com", "test", testDKIMPublicKey),
	}

	results := mail.VerifyDKIM(verifyOpts)
	if results[0].Status != DKIMStatusPass {
		t.Errorf("Verification failed: %v", results[0].Error)
	}

	// Check signed headers
	sig := results[0].Signature
	foundCustom := false
	for _, h := range sig.SignedHeaders {
		if strings.EqualFold(h, "X-Custom-Header") {
			foundCustom = true
			break
		}
	}
	if !foundCustom {
		t.Error("X-Custom-Header not in signed headers")
	}
}

func TestDKIMSignFromHeaderRequired(t *testing.T) {
	mail := NewMail()
	mail.SetFrom(MailboxAddress{LocalPart: "sender", Domain: "example.com"})
	mail.AddHeader("From", "sender@example.com")
	mail.AddHeader("To", "recipient@example.org")
	mail.Content.Body = []byte("Test.\r\n")

	// Headers list without From
	opts := &DKIMSignOptions{
		Domain:     "example.com",
		Selector:   "test",
		PrivateKey: testDKIMPrivateKey,
		Headers:    []string{"To", "Subject"}, // No From
	}

	err := mail.SignDKIM(opts)
	if err != nil {
		t.Fatalf("SignDKIM failed: %v", err)
	}

	// Verify that From was added to signed headers
	verifyOpts := &DKIMVerifyOptions{
		DNSResolver: mockDNSResolver("example.com", "test", testDKIMPublicKey),
	}

	results := mail.VerifyDKIM(verifyOpts)
	if results[0].Status != DKIMStatusPass {
		t.Errorf("Verification failed: %v", results[0].Error)
	}

	// Check that From is in signed headers
	hasFrom := false
	for _, h := range results[0].Signature.SignedHeaders {
		if strings.EqualFold(h, "From") {
			hasFrom = true
			break
		}
	}
	if !hasFrom {
		t.Error("From header should be automatically added to signed headers")
	}
}

func TestDKIMVerifyExpiredSignature(t *testing.T) {
	mail := NewMail()
	mail.SetFrom(MailboxAddress{LocalPart: "sender", Domain: "example.com"})
	mail.AddHeader("From", "sender@example.com")
	mail.AddHeader("Subject", "Expiration Test")
	mail.Content.Body = []byte("Test.\r\n")

	// Sign with expiration in the past
	opts := &DKIMSignOptions{
		Domain:     "example.com",
		Selector:   "test",
		PrivateKey: testDKIMPrivateKey,
		Expiration: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}

	err := mail.SignDKIM(opts)
	if err != nil {
		t.Fatalf("SignDKIM failed: %v", err)
	}

	// Verify should fail due to expiration
	verifyOpts := &DKIMVerifyOptions{
		DNSResolver:      mockDNSResolver("example.com", "test", testDKIMPublicKey),
		IgnoreExpiration: false,
	}

	results := mail.VerifyDKIM(verifyOpts)
	if results[0].Status != DKIMStatusFail {
		t.Errorf("Expected DKIMStatusFail for expired signature, got %s", results[0].Status)
	}

	if results[0].Error != ErrDKIMSignatureExpired {
		t.Errorf("Expected ErrDKIMSignatureExpired, got %v", results[0].Error)
	}

	// Verify with expiration ignored
	verifyOpts.IgnoreExpiration = true
	results = mail.VerifyDKIM(verifyOpts)
	if results[0].Status != DKIMStatusPass {
		t.Errorf("Expected DKIMStatusPass with expiration ignored, got %s: %v", results[0].Status, results[0].Error)
	}
}

func TestDKIMVerifyKeyNotFound(t *testing.T) {
	mail := NewMail()
	mail.SetFrom(MailboxAddress{LocalPart: "sender", Domain: "example.com"})
	mail.AddHeader("From", "sender@example.com")
	mail.Content.Body = []byte("Test.\r\n")

	opts := &DKIMSignOptions{
		Domain:     "example.com",
		Selector:   "missing",
		PrivateKey: testDKIMPrivateKey,
	}

	err := mail.SignDKIM(opts)
	if err != nil {
		t.Fatalf("SignDKIM failed: %v", err)
	}

	// Mock DNS that returns not found
	verifyOpts := &DKIMVerifyOptions{
		DNSResolver: func(name string) ([]string, error) {
			return nil, &mockDNSError{isNotFound: true}
		},
	}

	results := mail.VerifyDKIM(verifyOpts)
	// Key not found can be either TEMPFAIL or PERMFAIL depending on implementation
	// Since our mock doesn't implement net.DNSError interface properly, it will be TEMPFAIL
	if results[0].Status != DKIMStatusFail && results[0].Status != DKIMStatusTempError {
		t.Errorf("Expected DKIMStatusFail or DKIMStatusTempError, got %s", results[0].Status)
	}
}

func TestDKIMVerifyTamperedBody(t *testing.T) {
	mail := NewMail()
	mail.SetFrom(MailboxAddress{LocalPart: "sender", Domain: "example.com"})
	mail.AddHeader("From", "sender@example.com")
	mail.Content.Body = []byte("Original message.\r\n")

	opts := &DKIMSignOptions{
		Domain:     "example.com",
		Selector:   "test",
		PrivateKey: testDKIMPrivateKey,
	}

	err := mail.SignDKIM(opts)
	if err != nil {
		t.Fatalf("SignDKIM failed: %v", err)
	}

	// Tamper with the body
	mail.Content.Body = []byte("Modified message.\r\n")

	verifyOpts := &DKIMVerifyOptions{
		DNSResolver: mockDNSResolver("example.com", "test", testDKIMPublicKey),
	}

	results := mail.VerifyDKIM(verifyOpts)
	if results[0].Status != DKIMStatusFail {
		t.Errorf("Expected DKIMStatusFail for tampered body, got %s", results[0].Status)
	}

	if results[0].Error != ErrDKIMBodyHashMismatch {
		t.Errorf("Expected ErrDKIMBodyHashMismatch, got %v", results[0].Error)
	}
}

func TestDKIMVerifyTamperedHeader(t *testing.T) {
	mail := NewMail()
	mail.SetFrom(MailboxAddress{LocalPart: "sender", Domain: "example.com"})
	mail.AddHeader("From", "sender@example.com")
	mail.AddHeader("Subject", "Original Subject")
	mail.Content.Body = []byte("Test.\r\n")

	opts := &DKIMSignOptions{
		Domain:     "example.com",
		Selector:   "test",
		PrivateKey: testDKIMPrivateKey,
		Headers:    []string{"From", "Subject"},
	}

	err := mail.SignDKIM(opts)
	if err != nil {
		t.Fatalf("SignDKIM failed: %v", err)
	}

	// Tamper with the Subject header
	for i, h := range mail.Content.Headers {
		if strings.EqualFold(h.Name, "Subject") {
			mail.Content.Headers[i].Value = "Modified Subject"
			break
		}
	}

	verifyOpts := &DKIMVerifyOptions{
		DNSResolver: mockDNSResolver("example.com", "test", testDKIMPublicKey),
	}

	results := mail.VerifyDKIM(verifyOpts)
	if results[0].Status != DKIMStatusFail {
		t.Errorf("Expected DKIMStatusFail for tampered header, got %s", results[0].Status)
	}
}

func TestDKIMCanonicalizationSimpleBody(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "empty body",
			input:    []byte{},
			expected: []byte("\r\n"),
		},
		{
			name:     "body without trailing CRLF",
			input:    []byte("Hello"),
			expected: []byte("Hello\r\n"),
		},
		{
			name:     "body with single trailing CRLF",
			input:    []byte("Hello\r\n"),
			expected: []byte("Hello\r\n"),
		},
		{
			name:     "body with multiple trailing CRLFs",
			input:    []byte("Hello\r\n\r\n\r\n"),
			expected: []byte("Hello\r\n"),
		},
		{
			name:     "body with whitespace preserved",
			input:    []byte("Hello  World\r\n"),
			expected: []byte("Hello  World\r\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := canonicalizeBodySimple(tt.input)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("canonicalizeBodySimple(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDKIMCanonicalizationRelaxedBody(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "empty body",
			input:    []byte{},
			expected: []byte{},
		},
		{
			name:     "body with trailing whitespace",
			input:    []byte("Hello   \r\n"),
			expected: []byte("Hello\r\n"),
		},
		{
			name:     "body with multiple spaces",
			input:    []byte("Hello    World\r\n"),
			expected: []byte("Hello World\r\n"),
		},
		{
			name:     "body with tabs",
			input:    []byte("Hello\t\tWorld\r\n"),
			expected: []byte("Hello World\r\n"),
		},
		{
			name:     "body with trailing empty lines",
			input:    []byte("Hello\r\n\r\n\r\n"),
			expected: []byte("Hello\r\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := canonicalizeBodyRelaxed(tt.input)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("canonicalizeBodyRelaxed(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDKIMCanonicalizationSimpleHeader(t *testing.T) {
	tests := []struct {
		name     string
		hdrName  string
		hdrValue string
		expected string
	}{
		{
			name:     "simple header",
			hdrName:  "From",
			hdrValue: "test@example.com",
			expected: "From: test@example.com",
		},
		{
			name:     "header with case",
			hdrName:  "Subject",
			hdrValue: "Test Subject",
			expected: "Subject: Test Subject",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := canonicalizeHeaderSimple(tt.hdrName, tt.hdrValue)
			if result != tt.expected {
				t.Errorf("canonicalizeHeaderSimple(%q, %q) = %q, want %q", tt.hdrName, tt.hdrValue, result, tt.expected)
			}
		})
	}
}

func TestDKIMCanonicalizationRelaxedHeader(t *testing.T) {
	tests := []struct {
		name     string
		hdrName  string
		hdrValue string
		expected string
	}{
		{
			name:     "lowercase header name",
			hdrName:  "FROM",
			hdrValue: "test@example.com",
			expected: "from:test@example.com",
		},
		{
			name:     "reduce whitespace",
			hdrName:  "Subject",
			hdrValue: "Test    Subject",
			expected: "subject:Test Subject",
		},
		{
			name:     "trim trailing whitespace",
			hdrName:  "Subject",
			hdrValue: "Test Subject   ",
			expected: "subject:Test Subject",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := canonicalizeHeaderRelaxed(tt.hdrName, tt.hdrValue)
			if result != tt.expected {
				t.Errorf("canonicalizeHeaderRelaxed(%q, %q) = %q, want %q", tt.hdrName, tt.hdrValue, result, tt.expected)
			}
		})
	}
}

func TestParseDKIMSignature(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		check       func(*DKIMSignature) error
	}{
		{
			name:        "valid signature",
			input:       "v=1; a=rsa-sha256; d=example.com; s=selector; h=from:to; bh=MTIz; b=YWJj",
			expectError: false,
			check: func(sig *DKIMSignature) error {
				if sig.Version != "1" {
					return errors.New("wrong version")
				}
				if sig.Algorithm != DKIMAlgorithmRSASHA256 {
					return errors.New("wrong algorithm")
				}
				if sig.Domain != "example.com" {
					return errors.New("wrong domain")
				}
				if sig.Selector != "selector" {
					return errors.New("wrong selector")
				}
				return nil
			},
		},
		{
			name:        "missing version",
			input:       "a=rsa-sha256; d=example.com; s=selector; h=from; bh=MTIz; b=YWJj",
			expectError: true,
		},
		{
			name:        "missing domain",
			input:       "v=1; a=rsa-sha256; s=selector; h=from; bh=MTIz; b=YWJj",
			expectError: true,
		},
		{
			name:        "missing selector",
			input:       "v=1; a=rsa-sha256; d=example.com; h=from; bh=MTIz; b=YWJj",
			expectError: true,
		},
		{
			name:        "with canonicalization",
			input:       "v=1; a=rsa-sha256; d=example.com; s=selector; c=relaxed/simple; h=from; bh=MTIz; b=YWJj",
			expectError: false,
			check: func(sig *DKIMSignature) error {
				if sig.HeaderCanonicalization != DKIMCanonicalizationRelaxed {
					return errors.New("wrong header canonicalization")
				}
				if sig.BodyCanonicalization != DKIMCanonicalizationSimple {
					return errors.New("wrong body canonicalization")
				}
				return nil
			},
		},
		{
			name:        "with timestamp and expiration",
			input:       "v=1; a=rsa-sha256; d=example.com; s=selector; h=from; t=1234567890; x=1234567900; bh=MTIz; b=YWJj",
			expectError: false,
			check: func(sig *DKIMSignature) error {
				if !sig.TimestampSet {
					return errors.New("timestamp not set")
				}
				if !sig.ExpirationSet {
					return errors.New("expiration not set")
				}
				if sig.Timestamp.Unix() != 1234567890 {
					return errors.New("wrong timestamp")
				}
				if sig.Expiration.Unix() != 1234567900 {
					return errors.New("wrong expiration")
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := parseDKIMSignature(tt.input)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if tt.check != nil {
				if err := tt.check(sig); err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func TestParseDKIMPublicKey(t *testing.T) {
	// Generate a test public key record
	pubKeyDER, _ := x509.MarshalPKIXPublicKey(testDKIMPublicKey)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyDER)

	tests := []struct {
		name        string
		input       string
		expectError bool
		errorType   error
	}{
		{
			name:        "valid key",
			input:       "v=DKIM1; k=rsa; p=" + pubKeyB64,
			expectError: false,
		},
		{
			name:        "key without version",
			input:       "k=rsa; p=" + pubKeyB64,
			expectError: false,
		},
		{
			name:        "revoked key",
			input:       "v=DKIM1; k=rsa; p=",
			expectError: true,
			errorType:   ErrDKIMKeyRevoked,
		},
		{
			name:        "missing p tag",
			input:       "v=DKIM1; k=rsa",
			expectError: true,
		},
		{
			name:        "invalid version",
			input:       "v=DKIM2; k=rsa; p=" + pubKeyB64,
			expectError: true,
		},
		{
			name:        "with service types",
			input:       "v=DKIM1; k=rsa; s=email; p=" + pubKeyB64,
			expectError: false,
		},
		{
			name:        "with flags",
			input:       "v=DKIM1; k=rsa; t=y:s; p=" + pubKeyB64,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := parseDKIMPublicKey(tt.input)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				if tt.errorType != nil && !errors.Is(err, tt.errorType) {
					t.Errorf("Expected error %v, got %v", tt.errorType, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if key.PublicKey == nil {
				t.Error("Public key is nil")
			}
		})
	}
}

func TestGenerateDKIMKeyPair(t *testing.T) {
	// Test minimum key size
	_, err := GenerateDKIMKeyPair(512)
	if err == nil {
		t.Error("Expected error for key size below 1024")
	}

	// Test valid key sizes
	for _, bits := range []int{1024, 2048, 4096} {
		key, err := GenerateDKIMKeyPair(bits)
		if err != nil {
			t.Errorf("Failed to generate %d-bit key: %v", bits, err)
			continue
		}
		if key.Size()*8 != bits {
			t.Errorf("Expected %d-bit key, got %d bits", bits, key.Size()*8)
		}
	}
}

func TestFormatDKIMPublicKeyRecord(t *testing.T) {
	record, err := FormatDKIMPublicKeyRecord(testDKIMPublicKey)
	if err != nil {
		t.Fatalf("Failed to format public key: %v", err)
	}

	if !strings.HasPrefix(record, "v=DKIM1; k=rsa; p=") {
		t.Errorf("Invalid record format: %s", record)
	}

	// Verify the record can be parsed back
	key, err := parseDKIMPublicKey(record)
	if err != nil {
		t.Fatalf("Failed to parse generated record: %v", err)
	}

	if key.PublicKey == nil {
		t.Error("Parsed public key is nil")
	}
}

func TestParseDKIMPrivateKey(t *testing.T) {
	// Encode the test private key as PEM
	keyDER := x509.MarshalPKCS1PrivateKey(testDKIMPrivateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyDER,
	})

	// Parse it back
	parsed, err := ParseDKIMPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("Failed to parse PEM key: %v", err)
	}

	// Verify it works by signing
	mail := NewMail()
	mail.AddHeader("From", "test@example.com")
	mail.Content.Body = []byte("Test.\r\n")

	err = mail.SignDKIM(&DKIMSignOptions{
		Domain:     "example.com",
		Selector:   "test",
		PrivateKey: parsed,
	})
	if err != nil {
		t.Errorf("Failed to sign with parsed key: %v", err)
	}
}

func TestDKIMNoSignature(t *testing.T) {
	mail := NewMail()
	mail.AddHeader("From", "test@example.com")
	mail.Content.Body = []byte("Test.\r\n")

	results := mail.VerifyDKIM(nil)
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	if results[0].Status != DKIMStatusNone {
		t.Errorf("Expected DKIMStatusNone, got %s", results[0].Status)
	}
}

func TestDKIMMultipleSignatures(t *testing.T) {
	mail := NewMail()
	mail.AddHeader("From", "sender@example.com")
	mail.AddHeader("Subject", "Multi-sig test")
	mail.Content.Body = []byte("Test.\r\n")

	// Sign with first domain
	key1, _ := GenerateDKIMKeyPair(2048)
	err := mail.SignDKIM(&DKIMSignOptions{
		Domain:     "domain1.com",
		Selector:   "s1",
		PrivateKey: key1,
	})
	if err != nil {
		t.Fatalf("First signature failed: %v", err)
	}

	// Sign with second domain
	key2, _ := GenerateDKIMKeyPair(2048)
	err = mail.SignDKIM(&DKIMSignOptions{
		Domain:     "domain2.com",
		Selector:   "s2",
		PrivateKey: key2,
	})
	if err != nil {
		t.Fatalf("Second signature failed: %v", err)
	}

	// Should have two signatures
	sigs := mail.GetDKIMSignatures()
	if len(sigs) != 2 {
		t.Errorf("Expected 2 signatures, got %d", len(sigs))
	}
}

func TestDKIMValidateDomain(t *testing.T) {
	tests := []struct {
		domain    string
		expectErr bool
	}{
		{"example.com", false},
		{"sub.example.com", false},
		{"a.b.c.d.example.com", false},
		{"", true},
		{"example..com", true},
		{"-example.com", true},
		{"example.com-", true},
	}

	for _, tt := range tests {
		err := ValidateDKIMDomain(tt.domain)
		if tt.expectErr && err == nil {
			t.Errorf("ValidateDKIMDomain(%q) expected error, got nil", tt.domain)
		}
		if !tt.expectErr && err != nil {
			t.Errorf("ValidateDKIMDomain(%q) unexpected error: %v", tt.domain, err)
		}
	}
}

func TestDKIMValidateSelector(t *testing.T) {
	tests := []struct {
		selector  string
		expectErr bool
	}{
		{"selector1", false},
		{"default", false},
		{"2024jan", false},
		{"", true},
		{"-selector", true},
		{"selector-", true},
	}

	for _, tt := range tests {
		err := ValidateDKIMSelector(tt.selector)
		if tt.expectErr && err == nil {
			t.Errorf("ValidateDKIMSelector(%q) expected error, got nil", tt.selector)
		}
		if !tt.expectErr && err != nil {
			t.Errorf("ValidateDKIMSelector(%q) unexpected error: %v", tt.selector, err)
		}
	}
}

func TestDKIMDisallowSHA1ForSigning(t *testing.T) {
	mail := NewMail()
	mail.AddHeader("From", "test@example.com")
	mail.Content.Body = []byte("Test.\r\n")

	err := mail.SignDKIM(&DKIMSignOptions{
		Domain:     "example.com",
		Selector:   "test",
		PrivateKey: testDKIMPrivateKey,
		Algorithm:  DKIMAlgorithmRSASHA1, // Should fail
	})

	if err == nil {
		t.Error("Expected error when trying to sign with SHA-1")
	}
}

func TestDKIMVerifySHA1Disabled(t *testing.T) {
	// Create a signature that claims to use SHA-1
	// (We'll manually craft a header for this test)
	mail := NewMail()
	mail.AddHeader("DKIM-Signature", "v=1; a=rsa-sha1; d=example.com; s=test; h=from; bh=MTIz; b=YWJj")
	mail.AddHeader("From", "test@example.com")
	mail.Content.Body = []byte("Test.\r\n")

	verifyOpts := &DKIMVerifyOptions{
		DNSResolver: mockDNSResolver("example.com", "test", testDKIMPublicKey),
		AllowSHA1:   false, // Default
	}

	results := mail.VerifyDKIM(verifyOpts)
	if results[0].Status != DKIMStatusFail {
		t.Errorf("Expected fail for SHA-1 signature, got %s", results[0].Status)
	}
}

func TestDKIMMinKeySize(t *testing.T) {
	// Generate a small key (this is for testing only!)
	smallKey, _ := rsa.GenerateKey(rand.Reader, 1024)

	mail := NewMail()
	mail.AddHeader("From", "test@example.com")
	mail.Content.Body = []byte("Test.\r\n")

	err := mail.SignDKIM(&DKIMSignOptions{
		Domain:     "example.com",
		Selector:   "test",
		PrivateKey: smallKey,
	})
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	// Verify with high minimum key size
	verifyOpts := &DKIMVerifyOptions{
		DNSResolver: mockDNSResolver("example.com", "test", &smallKey.PublicKey),
		MinKeyBits:  2048, // Require 2048 bits
	}

	results := mail.VerifyDKIM(verifyOpts)
	if results[0].Status != DKIMStatusFail {
		t.Errorf("Expected fail for small key, got %s", results[0].Status)
	}

	// Verify with lower minimum
	verifyOpts.MinKeyBits = 1024
	results = mail.VerifyDKIM(verifyOpts)
	if results[0].Status != DKIMStatusPass {
		t.Errorf("Expected pass with lower minimum, got %s: %v", results[0].Status, results[0].Error)
	}
}
