package arc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	ravendns "github.com/synqronlabs/raven/dns"
)

// TestParseAuthenticationResults tests parsing of ARC-Authentication-Results headers.
func TestParseAuthenticationResults(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		wantInst int
		wantAuth string
		wantErr  bool
	}{
		{
			name:     "valid simple",
			value:    "i=1; example.com; spf=pass",
			wantInst: 1,
			wantAuth: "example.com",
			wantErr:  false,
		},
		{
			name:     "valid with multiple results",
			value:    "i=2; mx.example.com; dkim=pass header.d=example.com; spf=pass smtp.mailfrom=sender@example.com",
			wantInst: 2,
			wantAuth: "mx.example.com",
			wantErr:  false,
		},
		{
			name:    "missing instance",
			value:   "example.com; spf=pass",
			wantErr: true,
		},
		{
			name:    "invalid instance",
			value:   "i=abc; example.com; spf=pass",
			wantErr: true,
		},
		{
			name:    "instance too high",
			value:   "i=51; example.com; spf=pass",
			wantErr: true,
		},
		{
			name:    "instance zero",
			value:   "i=0; example.com; spf=pass",
			wantErr: true,
		},
		{
			name:    "missing authserv-id",
			value:   "i=1;",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aar, err := ParseAuthenticationResults(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAuthenticationResults() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if aar.Instance != tt.wantInst {
				t.Errorf("Instance = %d, want %d", aar.Instance, tt.wantInst)
			}
			if aar.AuthServID != tt.wantAuth {
				t.Errorf("AuthServID = %q, want %q", aar.AuthServID, tt.wantAuth)
			}
		})
	}
}

// TestParseMessageSignature tests parsing of ARC-Message-Signature headers.
func TestParseMessageSignature(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		wantInst int
		wantAlg  string
		wantErr  bool
	}{
		{
			name: "valid RSA-SHA256",
			value: "i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector;" +
				" h=From:To:Subject:Date; bh=YWJj; b=c2ln",
			wantInst: 1,
			wantAlg:  "rsa-sha256",
			wantErr:  false,
		},
		{
			name: "valid Ed25519",
			value: "i=2; a=ed25519-sha256; c=simple/simple; d=example.org; s=sel2;" +
				" h=From:To:Subject; bh=ZGVm; b=c2lnbg==",
			wantInst: 2,
			wantAlg:  "ed25519-sha256",
			wantErr:  false,
		},
		{
			name:    "missing required tag",
			value:   "i=1; a=rsa-sha256; d=example.com; s=selector; h=From; b=sig=",
			wantErr: true, // missing bh
		},
		{
			name:    "invalid instance",
			value:   "i=abc; a=rsa-sha256; d=example.com; s=selector; h=From; bh=abc=; b=sig=",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms, _, err := ParseMessageSignature(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMessageSignature() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if ms.Instance != tt.wantInst {
				t.Errorf("Instance = %d, want %d", ms.Instance, tt.wantInst)
			}
			if ms.Algorithm != tt.wantAlg {
				t.Errorf("Algorithm = %q, want %q", ms.Algorithm, tt.wantAlg)
			}
		})
	}
}

// TestParseSeal tests parsing of ARC-Seal headers.
func TestParseSeal(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		wantInst int
		wantCV   ChainValidationStatus
		wantErr  bool
	}{
		{
			name:     "valid cv=none",
			value:    "i=1; a=rsa-sha256; cv=none; d=example.com; s=selector; b=sig=",
			wantInst: 1,
			wantCV:   ChainValidationNone,
			wantErr:  false,
		},
		{
			name:     "valid cv=pass",
			value:    "i=2; a=rsa-sha256; cv=pass; d=example.com; s=selector; b=sig=",
			wantInst: 2,
			wantCV:   ChainValidationPass,
			wantErr:  false,
		},
		{
			name:     "valid cv=fail",
			value:    "i=3; a=rsa-sha256; cv=fail; d=example.com; s=selector; b=sig=",
			wantInst: 3,
			wantCV:   ChainValidationFail,
			wantErr:  false,
		},
		{
			name:    "missing cv",
			value:   "i=1; a=rsa-sha256; d=example.com; s=selector; b=sig=",
			wantErr: true,
		},
		{
			name:    "invalid cv",
			value:   "i=1; a=rsa-sha256; cv=invalid; d=example.com; s=selector; b=sig=",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seal, _, err := ParseSeal(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSeal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if seal.Instance != tt.wantInst {
				t.Errorf("Instance = %d, want %d", seal.Instance, tt.wantInst)
			}
			if seal.ChainValidation != tt.wantCV {
				t.Errorf("ChainValidation = %q, want %q", seal.ChainValidation, tt.wantCV)
			}
		})
	}
}

// TestMessageSignatureHeader tests ARC-Message-Signature header generation.
func TestMessageSignatureHeader(t *testing.T) {
	ms := &MessageSignature{
		Instance:         1,
		Version:          1,
		Algorithm:        "rsa-sha256",
		Domain:           "example.com",
		Selector:         "selector",
		Canonicalization: "relaxed/relaxed",
		SignedHeaders:    []string{"From", "To", "Subject"},
		BodyHash:         []byte{0x01, 0x02, 0x03},
		Signature:        []byte{0x04, 0x05, 0x06},
		Timestamp:        1234567890,
	}

	header := ms.Header(true)

	// Check required components
	if !strings.Contains(header, "ARC-Message-Signature:") {
		t.Error("missing header name")
	}
	if !strings.Contains(header, "i=1") {
		t.Error("missing instance")
	}
	if !strings.Contains(header, "a=rsa-sha256") {
		t.Error("missing algorithm")
	}
	if !strings.Contains(header, "d=example.com") {
		t.Error("missing domain")
	}
	if !strings.Contains(header, "s=selector") {
		t.Error("missing selector")
	}
	if !strings.Contains(header, "c=relaxed/relaxed") {
		t.Error("missing canonicalization")
	}
	if !strings.Contains(header, "h=From:To:Subject") {
		t.Error("missing signed headers")
	}
	if !strings.Contains(header, "bh=") {
		t.Error("missing body hash")
	}
	if !strings.Contains(header, "b=") {
		t.Error("missing signature")
	}
}

// TestSealHeader tests ARC-Seal header generation.
func TestSealHeader(t *testing.T) {
	seal := &Seal{
		Instance:        2,
		Version:         1,
		Algorithm:       "rsa-sha256",
		Domain:          "example.com",
		Selector:        "arc-seal",
		ChainValidation: ChainValidationPass,
		Signature:       []byte{0x01, 0x02, 0x03},
		Timestamp:       1234567890,
	}

	header := seal.Header(true)

	if !strings.Contains(header, "ARC-Seal:") {
		t.Error("missing header name")
	}
	if !strings.Contains(header, "i=2") {
		t.Error("missing instance")
	}
	if !strings.Contains(header, "cv=pass") {
		t.Error("missing chain validation")
	}
	if !strings.Contains(header, "d=example.com") {
		t.Error("missing domain")
	}
	if !strings.Contains(header, "s=arc-seal") {
		t.Error("missing selector")
	}
}

// TestExtractARCSets tests extraction of ARC sets from headers.
func TestExtractARCSets(t *testing.T) {
	tests := []struct {
		name     string
		headers  []headerData
		wantSets int
		wantErr  bool
	}{
		{
			name:     "no ARC headers",
			headers:  []headerData{},
			wantSets: 0,
			wantErr:  true, // ErrNoARCHeaders
		},
		{
			name: "single complete set",
			headers: []headerData{
				{raw: []byte("ARC-Authentication-Results: i=1; example.com; spf=pass\r\n"), lkey: "arc-authentication-results"},
				{raw: []byte("ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel; h=From; bh=abc=; b=sig=\r\n"), lkey: "arc-message-signature"},
				{raw: []byte("ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; b=sig=\r\n"), lkey: "arc-seal"},
			},
			wantSets: 1,
			wantErr:  false,
		},
		{
			name: "incomplete set - missing seal",
			headers: []headerData{
				{raw: []byte("ARC-Authentication-Results: i=1; example.com; spf=pass\r\n"), lkey: "arc-authentication-results"},
				{raw: []byte("ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel; h=From; bh=abc=; b=sig=\r\n"), lkey: "arc-message-signature"},
			},
			wantSets: 0,
			wantErr:  true, // ErrMissingSet
		},
		{
			name: "gap in chain",
			headers: []headerData{
				{raw: []byte("ARC-Authentication-Results: i=1; example.com; spf=pass\r\n"), lkey: "arc-authentication-results"},
				{raw: []byte("ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel; h=From; bh=abc=; b=sig=\r\n"), lkey: "arc-message-signature"},
				{raw: []byte("ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; b=sig=\r\n"), lkey: "arc-seal"},
				{raw: []byte("ARC-Authentication-Results: i=3; example.com; spf=pass\r\n"), lkey: "arc-authentication-results"},
				{raw: []byte("ARC-Message-Signature: i=3; a=rsa-sha256; d=example.com; s=sel; h=From; bh=abc=; b=sig=\r\n"), lkey: "arc-message-signature"},
				{raw: []byte("ARC-Seal: i=3; a=rsa-sha256; cv=pass; d=example.com; s=sel; b=sig=\r\n"), lkey: "arc-seal"},
			},
			wantSets: 0,
			wantErr:  true, // ErrGapInChain
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sets, err := extractARCSets(tt.headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractARCSets() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && len(sets) != tt.wantSets {
				t.Errorf("got %d sets, want %d", len(sets), tt.wantSets)
			}
		})
	}
}

// TestChainValidationStatus tests ChainValidationStatus handling.
func TestChainValidationStatus(t *testing.T) {
	tests := []struct {
		result *Result
		want   ChainValidationStatus
	}{
		{nil, ChainValidationNone},
		{&Result{Status: StatusNone}, ChainValidationNone},
		{&Result{Status: StatusPass}, ChainValidationPass},
		{&Result{Status: StatusFail}, ChainValidationFail},
	}

	for _, tt := range tests {
		got := GetARCChainStatus(tt.result)
		if got != tt.want {
			t.Errorf("GetARCChainStatus(%v) = %v, want %v", tt.result, got, tt.want)
		}
	}
}

// TestEvaluateARCForDMARC tests trusted domain evaluation.
func TestEvaluateARCForDMARC(t *testing.T) {
	result := &Result{
		Status: StatusPass,
		Sets: []*Set{
			{Instance: 1, Seal: &Seal{Domain: "example.com"}},
			{Instance: 2, Seal: &Seal{Domain: "trusted.org"}},
			{Instance: 3, Seal: &Seal{Domain: "other.net"}},
		},
	}

	trusted, oldest := EvaluateARCForDMARC(result, []string{"trusted.org"})
	if !trusted {
		t.Error("expected trusted=true")
	}
	if oldest != 2 {
		t.Errorf("oldest = %d, want 2", oldest)
	}

	trusted, _ = EvaluateARCForDMARC(result, []string{"notthere.com"})
	if trusted {
		t.Error("expected trusted=false for non-matching domain")
	}

	// Test with fail status
	failResult := &Result{Status: StatusFail}
	trusted, _ = EvaluateARCForDMARC(failResult, []string{"trusted.org"})
	if trusted {
		t.Error("expected trusted=false for failed result")
	}
}

// TestCanonicalization tests header and body canonicalization.
func TestCanonicalization(t *testing.T) {
	tests := []struct {
		name   string
		header []byte
		want   string
	}{
		{
			name:   "simple header",
			header: []byte("From: test@example.com\r\n"),
			want:   "from:test@example.com",
		},
		{
			name:   "header with whitespace",
			header: []byte("Subject:   Hello   World  \r\n"),
			want:   "subject:Hello World",
		},
		{
			name:   "folded header",
			header: []byte("Subject: Hello\r\n\tWorld\r\n"),
			want:   "subject:Hello World",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := canonicalizeHeaderRelaxed(tt.header)
			if err != nil {
				t.Errorf("canonicalizeHeaderRelaxed() error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("canonicalizeHeaderRelaxed() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestIsTLD tests top-level domain detection.
func TestIsTLD(t *testing.T) {
	tests := []struct {
		domain string
		want   bool
	}{
		{"com", true},
		{"org", true},
		{"example.com", false},
		{"sub.example.com", false},
		{"co.uk", true},
		{"example.co.uk", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			if got := isTLD(tt.domain); got != tt.want {
				t.Errorf("isTLD(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

// mockResolver implements ravendns.Resolver for testing.
type mockResolver struct {
	txtRecords map[string][]string
}

func (m *mockResolver) LookupTXT(ctx context.Context, domain string) (ravendns.Result[string], error) {
	records, ok := m.txtRecords[domain]
	if !ok {
		return ravendns.Result[string]{}, ravendns.ErrDNSNotFound
	}
	return ravendns.Result[string]{Records: records}, nil
}

func (m *mockResolver) LookupIP(ctx context.Context, domain string) (ravendns.Result[net.IP], error) {
	return ravendns.Result[net.IP]{}, nil
}

func (m *mockResolver) LookupMX(ctx context.Context, domain string) (ravendns.Result[*net.MX], error) {
	return ravendns.Result[*net.MX]{}, nil
}

func (m *mockResolver) LookupAddr(ctx context.Context, ip net.IP) (ravendns.Result[string], error) {
	return ravendns.Result[string]{}, nil
}

// generateTestKey generates a test RSA key pair.
func generateTestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubkeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	dkimRecord := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pubkeyBytes)
	return key, dkimRecord
}

// TestSealAndVerify tests the complete seal and verify cycle.
func TestSealAndVerify(t *testing.T) {
	privateKey, dkimRecord := generateTestKey(t)

	resolver := &mockResolver{
		txtRecords: map[string][]string{
			"arc._domainkey.example.com": {dkimRecord},
		},
	}

	message := []byte("From: sender@example.com\r\n" +
		"To: recipient@example.org\r\n" +
		"Subject: Test\r\n" +
		"Date: Thu, 19 Dec 2024 10:00:00 +0000\r\n" +
		"Message-ID: <test@example.com>\r\n" +
		"\r\n" +
		"This is a test message.\r\n")

	// Create sealer
	sealer := &Sealer{
		Domain:                 "example.com",
		Selector:               "arc",
		PrivateKey:             privateKey,
		Headers:                []string{"From", "To", "Subject", "Date", "Message-ID"},
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
		Clock: func() time.Time {
			return time.Unix(1734607200, 0)
		},
	}

	// Seal the message
	result, err := sealer.Seal(message, "example.com", "spf=pass; dkim=pass", ChainValidationNone)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	if result.Instance != 1 {
		t.Errorf("Instance = %d, want 1", result.Instance)
	}

	// Build the sealed message
	sealedMessage := []byte(result.Seal + "\r\n" +
		result.MessageSignature + "\r\n" +
		result.AuthenticationResults + "\r\n" +
		string(message))

	// Verify the sealed message
	verifier := &Verifier{
		Resolver:      resolver,
		MinRSAKeyBits: 1024,
		Clock: func() time.Time {
			return time.Unix(1734607200, 0)
		},
	}

	verifyResult, err := verifier.Verify(context.Background(), sealedMessage)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if verifyResult.Status != StatusPass {
		t.Errorf("Status = %s, want pass (err: %v, reason: %s)",
			verifyResult.Status, verifyResult.Err, verifyResult.FailedReason)
	}

	if len(verifyResult.Sets) != 1 {
		t.Errorf("Sets = %d, want 1", len(verifyResult.Sets))
	}
}

// TestMultipleSets tests sealing multiple ARC sets.
func TestMultipleSets(t *testing.T) {
	privateKey, dkimRecord := generateTestKey(t)

	resolver := &mockResolver{
		txtRecords: map[string][]string{
			"arc._domainkey.example.com":   {dkimRecord},
			"arc._domainkey.forwarder.org": {dkimRecord},
		},
	}

	message := []byte("From: sender@example.com\r\n" +
		"To: recipient@example.org\r\n" +
		"Subject: Test\r\n" +
		"Date: Thu, 19 Dec 2024 10:00:00 +0000\r\n" +
		"Message-ID: <test@example.com>\r\n" +
		"\r\n" +
		"This is a test message.\r\n")

	fixedTime := time.Unix(1734607200, 0)

	// First seal (origin)
	sealer1 := &Sealer{
		Domain:                 "example.com",
		Selector:               "arc",
		PrivateKey:             privateKey,
		Headers:                []string{"From", "To", "Subject", "Date", "Message-ID"},
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
		Clock:                  func() time.Time { return fixedTime },
	}

	result1, err := sealer1.Seal(message, "example.com", "spf=pass; dkim=pass", ChainValidationNone)
	if err != nil {
		t.Fatalf("First Seal() error = %v", err)
	}

	// Build first sealed message
	sealed1 := []byte(result1.Seal + "\r\n" +
		result1.MessageSignature + "\r\n" +
		result1.AuthenticationResults + "\r\n" +
		string(message))

	// Verify first seal
	verifier := &Verifier{
		Resolver:      resolver,
		MinRSAKeyBits: 1024,
		Clock:         func() time.Time { return fixedTime },
	}

	verify1, _ := verifier.Verify(context.Background(), sealed1)
	if verify1.Status != StatusPass {
		t.Fatalf("First verification failed: %s (%v)", verify1.FailedReason, verify1.Err)
	}

	// Second seal (forwarder)
	sealer2 := &Sealer{
		Domain:                 "forwarder.org",
		Selector:               "arc",
		PrivateKey:             privateKey,
		Headers:                []string{"From", "To", "Subject", "Date", "Message-ID", "ARC-Authentication-Results", "ARC-Message-Signature", "ARC-Seal"},
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
		Clock:                  func() time.Time { return fixedTime },
	}

	result2, err := sealer2.Seal(sealed1, "forwarder.org", "arc=pass; spf=fail", ChainValidationPass)
	if err != nil {
		t.Fatalf("Second Seal() error = %v", err)
	}

	if result2.Instance != 2 {
		t.Errorf("Instance = %d, want 2", result2.Instance)
	}

	// Build second sealed message
	sealed2 := []byte(result2.Seal + "\r\n" +
		result2.MessageSignature + "\r\n" +
		result2.AuthenticationResults + "\r\n" +
		string(sealed1))

	// Verify second seal
	verify2, _ := verifier.Verify(context.Background(), sealed2)
	if verify2.Status != StatusPass {
		t.Errorf("Second verification failed: %s (%v)", verify2.FailedReason, verify2.Err)
	}

	if len(verify2.Sets) != 2 {
		t.Errorf("Sets = %d, want 2", len(verify2.Sets))
	}
}

// TestNoARCHeaders tests verification of a message without ARC headers.
func TestNoARCHeaders(t *testing.T) {
	message := []byte("From: sender@example.com\r\n" +
		"To: recipient@example.org\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"No ARC headers.\r\n")

	verifier := &Verifier{
		Resolver: &mockResolver{txtRecords: map[string][]string{}},
	}

	result, err := verifier.Verify(context.Background(), message)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if result.Status != StatusNone {
		t.Errorf("Status = %s, want none", result.Status)
	}
}

// TestInvalidChainValidation tests cv= tag validation.
func TestInvalidChainValidation(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	message := []byte("From: sender@example.com\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"Body\r\n")

	sealer := &Sealer{
		Domain:     "example.com",
		Selector:   "arc",
		PrivateKey: privateKey,
	}

	// First seal should require cv=none
	_, err := sealer.Seal(message, "example.com", "spf=pass", ChainValidationPass)
	if err == nil {
		t.Error("expected error for cv=pass on first seal")
	}

	// Second seal should not allow cv=none
	sealedWithFirst := []byte("ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=sig=\r\n" +
		"ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=arc; h=From; bh=abc=; b=sig=\r\n" +
		"ARC-Authentication-Results: i=1; example.com; spf=pass\r\n" +
		string(message))

	_, err = sealer.Seal(sealedWithFirst, "example.com", "arc=pass", ChainValidationNone)
	if err == nil {
		t.Error("expected error for cv=none on subsequent seal")
	}
}

// TestRemoveSignature tests the b= tag removal for verification.
func TestRemoveSignature(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "simple signature",
			header: "ARC-Seal: i=1; a=rsa-sha256; b=abc123def456",
			want:   "ARC-Seal: i=1; a=rsa-sha256; b=",
		},
		{
			name:   "signature with semicolon after",
			header: "ARC-Seal: i=1; a=rsa-sha256; b=abc123; d=example.com",
			want:   "ARC-Seal: i=1; a=rsa-sha256; b=; d=example.com",
		},
		{
			name:   "no signature",
			header: "ARC-Seal: i=1; a=rsa-sha256",
			want:   "ARC-Seal: i=1; a=rsa-sha256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(removeSignature([]byte(tt.header)))
			if got != tt.want {
				t.Errorf("removeSignature() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestAlgorithmHelpers tests algorithm parsing helpers.
func TestAlgorithmHelpers(t *testing.T) {
	ms := &MessageSignature{Algorithm: "rsa-sha256"}
	if ms.AlgorithmSign() != "rsa" {
		t.Errorf("AlgorithmSign() = %s, want rsa", ms.AlgorithmSign())
	}
	if ms.AlgorithmHash() != "sha256" {
		t.Errorf("AlgorithmHash() = %s, want sha256", ms.AlgorithmHash())
	}

	seal := &Seal{Algorithm: "ed25519-sha256"}
	if seal.AlgorithmSign() != "ed25519" {
		t.Errorf("Seal.AlgorithmSign() = %s, want ed25519", seal.AlgorithmSign())
	}
	if seal.AlgorithmHash() != "sha256" {
		t.Errorf("Seal.AlgorithmHash() = %s, want sha256", seal.AlgorithmHash())
	}
}

// TestCanonicalizationHelpers tests canonicalization parsing.
func TestCanonicalizationHelpers(t *testing.T) {
	tests := []struct {
		canon      string
		wantHeader Canonicalization
		wantBody   Canonicalization
	}{
		{"relaxed/relaxed", CanonRelaxed, CanonRelaxed},
		{"simple/simple", CanonSimple, CanonSimple},
		{"relaxed/simple", CanonRelaxed, CanonSimple},
		{"simple/relaxed", CanonSimple, CanonRelaxed},
		{"relaxed", CanonRelaxed, CanonSimple}, // default body is simple
		{"", CanonSimple, CanonSimple},         // both default to simple
	}

	for _, tt := range tests {
		ms := &MessageSignature{Canonicalization: tt.canon}
		if ms.HeaderCanon() != tt.wantHeader {
			t.Errorf("HeaderCanon(%q) = %s, want %s", tt.canon, ms.HeaderCanon(), tt.wantHeader)
		}
		if ms.BodyCanon() != tt.wantBody {
			t.Errorf("BodyCanon(%q) = %s, want %s", tt.canon, ms.BodyCanon(), tt.wantBody)
		}
	}
}

// Benchmarks

func BenchmarkSeal(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	message := []byte("From: sender@example.com\r\n" +
		"To: recipient@example.org\r\n" +
		"Subject: Test Message\r\n" +
		"Date: Thu, 19 Dec 2024 10:00:00 +0000\r\n" +
		"Message-ID: <test@example.com>\r\n" +
		"\r\n" +
		"This is the body of the test message.\r\n")

	sealer := &Sealer{
		Domain:                 "example.com",
		Selector:               "arc",
		PrivateKey:             privateKey,
		Headers:                []string{"From", "To", "Subject", "Date", "Message-ID"},
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sealer.Seal(message, "example.com", "spf=pass", ChainValidationNone)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	privateKey, dkimRecord := func() (*rsa.PrivateKey, string) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		pubkeyBytes, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		return key, "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pubkeyBytes)
	}()

	resolver := &mockResolver{
		txtRecords: map[string][]string{
			"arc._domainkey.example.com": {dkimRecord},
		},
	}

	message := []byte("From: sender@example.com\r\n" +
		"To: recipient@example.org\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"Body\r\n")

	sealer := &Sealer{
		Domain:                 "example.com",
		Selector:               "arc",
		PrivateKey:             privateKey,
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
	}

	result, _ := sealer.Seal(message, "example.com", "spf=pass", ChainValidationNone)
	sealedMessage := []byte(result.Seal + "\r\n" +
		result.MessageSignature + "\r\n" +
		result.AuthenticationResults + "\r\n" +
		string(message))

	verifier := &Verifier{
		Resolver:      resolver,
		MinRSAKeyBits: 1024,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := verifier.Verify(context.Background(), sealedMessage)
		if err != nil {
			b.Fatal(err)
		}
	}
}
