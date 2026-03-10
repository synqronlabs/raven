package arc

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	ravendns "github.com/synqronlabs/raven/dns"
	ravenmail "github.com/synqronlabs/raven/mail"
)

type errReader struct {
	err error
}

func (r errReader) Read(_ []byte) (int, error) {
	return 0, r.err
}

type errReaderAt struct {
	err error
}

func (r errReaderAt) ReadAt(_ []byte, _ int64) (int, error) {
	return 0, r.err
}

type resolverWithErrors struct {
	txtRecords map[string][]string
	txtErrors  map[string]error
}

func (r *resolverWithErrors) LookupTXT(_ context.Context, domain string) (ravendns.Result[string], error) {
	if err, ok := r.txtErrors[domain]; ok {
		return ravendns.Result[string]{}, err
	}
	if records, ok := r.txtRecords[domain]; ok {
		return ravendns.Result[string]{Records: records}, nil
	}
	return ravendns.Result[string]{}, ravendns.ErrDNSNotFound
}

func (*resolverWithErrors) LookupIP(_ context.Context, _ string) (ravendns.Result[net.IP], error) {
	return ravendns.Result[net.IP]{}, nil
}

func (*resolverWithErrors) LookupMX(_ context.Context, _ string) (ravendns.Result[*net.MX], error) {
	return ravendns.Result[*net.MX]{}, nil
}

func (*resolverWithErrors) LookupAddr(_ context.Context, _ net.IP) (ravendns.Result[string], error) {
	return ravendns.Result[string]{}, nil
}

func sha256Sum(data string) []byte {
	sum := sha256.Sum256([]byte(data))
	return sum[:]
}

func generateEd25519Record() (ed25519.PrivateKey, string) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return privateKey, "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(publicKey)
}

func testRawMessage() []byte {
	return []byte("From: sender@example.com\r\n" +
		"To: recipient@example.org\r\n" +
		"Subject: Test\r\n" +
		"Date: Thu, 19 Dec 2024 10:00:00 +0000\r\n" +
		"Message-ID: <test@example.com>\r\n" +
		"\r\n" +
		"This is a test message.\r\n")
}

func parseTestHeaders(t *testing.T, message []byte) ([]headerData, int) {
	t.Helper()
	headers, bodyOffset, err := parseHeaders(bufio.NewReader(bytes.NewReader(message)))
	if err != nil {
		t.Fatalf("parseHeaders() error = %v", err)
	}
	return headers, bodyOffset
}

func buildSignedMessage(t *testing.T, privateKey crypto.Signer, domain, selector string, resolver ravendns.Resolver) ([]byte, *SealResult, *Verifier) {
	t.Helper()
	sealer := &Sealer{
		Domain:                 domain,
		Selector:               selector,
		PrivateKey:             privateKey,
		Headers:                []string{"From", "To", "Subject", "Date", "Message-ID"},
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
		Clock:                  func() time.Time { return time.Unix(1734607200, 0) },
	}
	result, err := sealer.Seal(testRawMessage(), domain, "spf=pass; dkim=pass", ChainValidationNone)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	message := []byte(result.Seal + "\r\n" + result.MessageSignature + "\r\n" + result.AuthenticationResults + "\r\n" + string(testRawMessage()))
	verifier := &Verifier{
		Resolver:      resolver,
		MinRSAKeyBits: 1024,
		Clock:         func() time.Time { return time.Unix(1734607200, 0) },
	}
	return message, result, verifier
}

func TestBodyHashCanonicalizationRFC(t *testing.T) {
	tests := []struct {
		name    string
		compute func() ([]byte, error)
		want    []byte
		wantErr bool
	}{
		{
			name: "simple empty body becomes CRLF",
			compute: func() ([]byte, error) {
				return bodyHashSimple(sha256.New(), strings.NewReader(""), -1)
			},
			want: sha256Sum("\r\n"),
		},
		{
			name: "relaxed empty body stays empty",
			compute: func() ([]byte, error) {
				return bodyHashRelaxed(sha256.New(), strings.NewReader(""), -1)
			},
			want: sha256Sum(""),
		},
		{
			name: "relaxed whitespace-only body stays empty",
			compute: func() ([]byte, error) {
				return bodyHashRelaxed(sha256.New(), strings.NewReader(" \r\n\t\r\n"), -1)
			},
			want: sha256Sum(""),
		},
		{
			name: "relaxed non-empty body adds final CRLF",
			compute: func() ([]byte, error) {
				return bodyHashRelaxed(sha256.New(), strings.NewReader("abc"), -1)
			},
			want: sha256Sum("abc\r\n"),
		},
		{
			name: "computeBodyHash selects simple canonicalization",
			compute: func() ([]byte, error) {
				return computeBodyHash(sha256.New(), CanonSimple, strings.NewReader("abc"), -1)
			},
			want: sha256Sum("abc\r\n"),
		},
		{
			name: "computeBodyHash length limit truncates canonicalized body",
			compute: func() ([]byte, error) {
				return computeBodyHash(sha256.New(), CanonRelaxed, strings.NewReader("abc"), 0)
			},
			want: sha256Sum(""),
		},
		{
			name: "simple canonicalization bubbles read errors",
			compute: func() ([]byte, error) {
				return bodyHashSimple(sha256.New(), errReader{err: io.ErrUnexpectedEOF}, -1)
			},
			wantErr: true,
		},
		{
			name: "relaxed canonicalization bubbles read errors",
			compute: func() ([]byte, error) {
				return bodyHashRelaxed(sha256.New(), errReader{err: io.ErrUnexpectedEOF}, -1)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.compute()
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("hash mismatch = %x, want %x", got, tt.want)
			}
		})
	}
}

func TestAdditionalCanonicalizationCoverage(t *testing.T) {
	simpleTrailing, err := bodyHashSimple(sha256.New(), strings.NewReader("a\r\n\r\n\r\n"), -1)
	if err != nil {
		t.Fatalf("bodyHashSimple(trailing) error = %v", err)
	}
	if !bytes.Equal(simpleTrailing, sha256Sum("a\r\n")) {
		t.Fatalf("unexpected simple trailing hash")
	}

	simpleLimited, err := bodyHashSimple(sha256.New(), strings.NewReader("abcd"), 2)
	if err != nil {
		t.Fatalf("bodyHashSimple(limit) error = %v", err)
	}
	if !bytes.Equal(simpleLimited, sha256Sum("ab")) {
		t.Fatalf("unexpected simple limited hash")
	}

	relaxedWithInteriorEmpty, err := bodyHashRelaxed(sha256.New(), strings.NewReader("a\r\n\r\n\tb\r\n"), -1)
	if err != nil {
		t.Fatalf("bodyHashRelaxed(interior empty) error = %v", err)
	}
	if !bytes.Equal(relaxedWithInteriorEmpty, sha256Sum("a\r\n\r\n b\r\n")) {
		t.Fatalf("unexpected relaxed interior-empty hash")
	}

	relaxedLimited, err := bodyHashRelaxed(sha256.New(), strings.NewReader("a\r\n\r\nb\r\n"), 2)
	if err != nil {
		t.Fatalf("bodyHashRelaxed(limit) error = %v", err)
	}
	if !bytes.Equal(relaxedLimited, sha256Sum("ab")) {
		t.Fatalf("unexpected relaxed limited hash")
	}
}

func TestParserAndTagHelpers(t *testing.T) {
	ms, _, err := ParseMessageSignature("i=1; v=99; a=rsa-sha256; d=example.com; s=sel; h=From; bh=YWJj; b=ZGVm")
	if err != nil {
		t.Fatalf("ParseMessageSignature() error = %v", err)
	}
	if ms.Canonicalization != "simple/simple" {
		t.Fatalf("Canonicalization = %q, want simple/simple", ms.Canonicalization)
	}

	if _, _, err := ParseMessageSignature("i=1; a=rsa-sha256; d=example.com; s=sel; h= ; bh=YWJj; b=ZGVm"); err == nil {
		t.Fatal("expected error for empty h= tag")
	}

	if _, _, err := ParseMessageSignature("i=1; a=rsa-sha256; d=example.com; s=sel; h=From; l=abc; bh=YWJj; b=ZGVm"); err == nil {
		t.Fatal("expected error for invalid l= tag")
	}
	if _, _, err := ParseMessageSignature("i=1; a=rsa-sha256; d=example.com; s=sel; h=From; t=abc; bh=YWJj; b=ZGVm"); err == nil {
		t.Fatal("expected error for invalid t= tag")
	}
	if _, _, err := ParseMessageSignature("i=1; a=rsa-sha256; d=example.com; s=sel; h=From; x=abc; bh=YWJj; b=ZGVm"); err == nil {
		t.Fatal("expected error for invalid x= tag")
	}
	msWithLX, _, err := ParseMessageSignature("i=1; a=rsa-sha256; d=example.com; s=sel; h=From; l=5; t=7; x=9; bh=YWJj; b=ZGVm")
	if err != nil {
		t.Fatalf("ParseMessageSignature(valid l/t/x) error = %v", err)
	}
	if msWithLX.Length != 5 || msWithLX.Timestamp != 7 || msWithLX.Expiration != 9 {
		t.Fatalf("unexpected parsed l/t/x values: %+v", msWithLX)
	}
	if _, _, err := ParseMessageSignature("i=51; a=rsa-sha256; d=example.com; s=sel; h=From; bh=YWJj; b=ZGVm"); err == nil {
		t.Fatal("expected instance range error")
	}

	seal, _, err := ParseSeal("i=1; v=99; a=rsa-sha256; cv=none; d=example.com; s=sel; b=ZGVm")
	if err != nil {
		t.Fatalf("ParseSeal() error = %v", err)
	}
	if seal.Version != 1 {
		t.Fatalf("Version = %d, want 1", seal.Version)
	}

	if _, _, err := ParseSeal("i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; h=From; b=ZGVm"); err == nil {
		t.Fatal("expected error for h= in ARC-Seal")
	}
	if _, _, err := ParseSeal("i=0; a=rsa-sha256; cv=none; d=example.com; s=sel; b=ZGVm"); err == nil {
		t.Fatal("expected error for invalid ARC-Seal instance")
	}
	if _, _, err := ParseSeal("i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; t=abc; b=ZGVm"); err == nil {
		t.Fatal("expected error for invalid ARC-Seal timestamp")
	}

	aar, err := ParseAuthenticationResults("i=1; example.com")
	if err != nil {
		t.Fatalf("ParseAuthenticationResults() error = %v", err)
	}
	if aar.AuthServID != "example.com" || aar.Results != "" {
		t.Fatalf("unexpected AAR parse result: %+v", aar)
	}
	if _, err := ParseAuthenticationResults("i=1"); err == nil {
		t.Fatal("expected missing semicolon error")
	}

	tags, err := parseTags("a=1; ignored; b=2")
	if err != nil {
		t.Fatalf("parseTags() error = %v", err)
	}
	if len(tags) != 2 || tags["a"] != "1" || tags["b"] != "2" {
		t.Fatalf("unexpected tags: %#v", tags)
	}

	if _, err := parseTags("a=1; a=2"); err == nil {
		t.Fatal("expected duplicate tag error")
	}
	if tags, err := parseTags("; =skip; a=1;;"); err != nil || len(tags) != 1 || tags["a"] != "1" {
		t.Fatalf("unexpected parseTags() result for empty parts: %#v, err=%v", tags, err)
	}
}

func TestLowLevelHashInputHelpers(t *testing.T) {
	if _, err := canonicalizeHeaderRelaxed([]byte("broken\r\n")); err == nil {
		t.Fatal("expected syntax error for header without colon")
	}

	amsHeader := []byte("ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel; h=From; bh=YWJj; b=ZGVm\r\n")
	headers := []headerData{{raw: []byte("From: sender@example.com\r\n"), lkey: "from"}}
	if _, err := computeAMSDataHash(sha256.New(), CanonSimple, headers, []string{"From"}, amsHeader); err != nil {
		t.Fatalf("computeAMSDataHash() error = %v", err)
	}
	if _, err := computeAMSDataHash(sha256.New(), CanonSimple, headers, []string{"Subject", "From"}, amsHeader); err != nil {
		t.Fatalf("computeAMSDataHash(missing signed header) error = %v", err)
	}

	badHeaders := []headerData{{raw: []byte("broken\r\n"), lkey: "from"}}
	if _, err := computeAMSDataHash(sha256.New(), CanonRelaxed, badHeaders, []string{"From"}, amsHeader); err == nil {
		t.Fatal("expected canonicalization error from computeAMSDataHash")
	}

	if _, err := computeSealDataHash(sha256.New(), []*Set{{Instance: 1}}, nil); err == nil {
		t.Fatal("expected missing header error from computeSealDataHash")
	}
	sealSet := []*Set{{Instance: 1}}
	sealHeadersForErrors := []headerData{{raw: []byte("ARC-Authentication-Results: i=1; example.com\r\n"), lkey: "arc-authentication-results"}}
	if _, err := computeSealDataHash(sha256.New(), sealSet, sealHeadersForErrors); err == nil {
		t.Fatal("expected missing AMS error from computeSealDataHash")
	}
	sealHeadersForErrors = append(sealHeadersForErrors, headerData{raw: []byte("ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel; h=From; bh=YWJj; b=ZGVm\r\n"), lkey: "arc-message-signature"})
	if _, err := computeSealDataHash(sha256.New(), sealSet, sealHeadersForErrors); err == nil {
		t.Fatal("expected missing ARC-Seal error from computeSealDataHash")
	}
	badSealHeaders := []headerData{
		{raw: []byte("ARC-Authentication-Results: i=1; example.com\r\n"), lkey: "arc-authentication-results"},
		{raw: []byte("ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel; h=From; bh=YWJj; b=ZGVm\r\n"), lkey: "arc-message-signature"},
		{raw: []byte("broken\r\n"), lkey: "arc-seal"},
	}
	if _, err := computeSealDataHash(sha256.New(), sealSet, badSealHeaders); err == nil {
		t.Fatal("expected ARC-Seal canonicalization error from computeSealDataHash")
	}

	newSeal := &Seal{Instance: 2, Algorithm: "rsa-sha256", Domain: "example.com", Selector: "sel", ChainValidation: ChainValidationFail}
	sealHeaders := []headerData{
		{raw: []byte("ARC-Authentication-Results: i=2; example.com\r\n"), lkey: "arc-authentication-results"},
		{raw: []byte("ARC-Message-Signature: i=2; a=rsa-sha256; d=example.com; s=sel; h=From; bh=YWJj; b=ZGVm\r\n"), lkey: "arc-message-signature"},
	}
	if _, err := computeSealDataHashForSigning(crypto.SHA256, 2, sealHeaders, newSeal, true); err != nil {
		t.Fatalf("computeSealDataHashForSigning(newestOnly) error = %v", err)
	}
	if _, err := computeSealDataHashForSigning(crypto.SHA256, 2, []headerData{{raw: []byte("ARC-Authentication-Results: i=2; example.com\r\n"), lkey: "arc-authentication-results"}}, newSeal, true); err == nil {
		t.Fatal("expected missing AMS error from computeSealDataHashForSigning")
	}

	got := string(removeSignature([]byte("ARC-Seal: i=1; b=abc(comment); d=example.com")))
	if got != "ARC-Seal: i=1; b=; d=example.com" {
		t.Fatalf("removeSignature() = %q", got)
	}
}

func TestHeaderParsingHelpers(t *testing.T) {
	raw := "Subject: Hello\r\n\tWorld\r\nBroken\r\nFrom: sender@example.com\r\n\r\nBody"
	headers, bodyOffset, err := parseHeaders(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("parseHeaders() error = %v", err)
	}
	if len(headers) != 2 {
		t.Fatalf("len(headers) = %d, want 2", len(headers))
	}
	if bodyOffset == 0 {
		t.Fatal("expected non-zero body offset")
	}
	if !strings.Contains(string(headers[0].raw), "\tWorld") {
		t.Fatalf("expected folded continuation in raw header: %q", headers[0].raw)
	}

	line, err := readHeaderLine(bufio.NewReader(strings.NewReader("A: B\r\n\tC\r\nD: E\r\n")))
	if err != nil {
		t.Fatalf("readHeaderLine() error = %v", err)
	}
	if string(line) != "A: B\r\n\tC\r\n" {
		t.Fatalf("readHeaderLine() = %q", line)
	}

	if got := extractHeaderValue([]byte("X-Test: value\r\n")); got != " value" {
		t.Fatalf("extractHeaderValue() = %q, want %q", got, " value")
	}
	if got := extractHeaderValue([]byte("invalid")); got != "" {
		t.Fatalf("extractHeaderValue() = %q, want empty string", got)
	}
}

func TestAlgorithmAndKeyHelpers(t *testing.T) {
	if hash, ok := getHash("sha1"); !ok || hash != crypto.SHA1 {
		t.Fatalf("getHash(sha1) = (%v, %v)", hash, ok)
	}
	if _, ok := getHash("bogus"); ok {
		t.Fatal("expected unknown hash to return ok=false")
	}

	if !isAMSSignableHeader("subject") {
		t.Fatal("expected Subject to be signable")
	}
	if isAMSSignableHeader("authentication-results") {
		t.Fatal("Authentication-Results must not be signable in AMS")
	}

	if !isSupportedSignAlgorithm("rsa") || isSupportedSignAlgorithm("bogus") {
		t.Fatal("unexpected sign algorithm support result")
	}
	if !isSupportedCanonicalization("relaxed/simple") || isSupportedCanonicalization("relaxed/bogus") {
		t.Fatal("unexpected canonicalization support result")
	}
	if !isSupportedCanonicalizationPart("simple") || isSupportedCanonicalizationPart("bogus") {
		t.Fatal("unexpected canonicalization part result")
	}
	if (&MessageSignature{Algorithm: "rsa"}).AlgorithmHash() != "" || (&MessageSignature{Algorithm: "rsa"}).AlgorithmSign() != "rsa" {
		t.Fatal("unexpected algorithm parsing for single-part message signature")
	}
	if (&MessageSignature{}).AlgorithmSign() != "" {
		t.Fatal("empty message signature algorithm should return empty signer")
	}
	if (&Seal{Algorithm: "ed25519"}).AlgorithmHash() != "" || (&Seal{Algorithm: "ed25519"}).AlgorithmSign() != "ed25519" {
		t.Fatal("unexpected algorithm parsing for single-part seal")
	}
	if (&Seal{}).AlgorithmSign() != "" {
		t.Fatal("empty seal algorithm should return empty signer")
	}

	if !recordAllowsHash(&DKIMRecord{}, "sha256") {
		t.Fatal("empty hash list should allow all hashes")
	}
	if !recordAllowsHash(&DKIMRecord{Hashes: []string{"sha1", "sha256"}}, "sha256") {
		t.Fatal("expected sha256 to be allowed")
	}
	if recordAllowsHash(&DKIMRecord{Hashes: []string{"sha1"}}, "sha256") {
		t.Fatal("expected sha256 to be rejected")
	}

	if !keyMatchesAlgorithm("", "rsa") || keyMatchesAlgorithm("ed25519", "rsa") {
		t.Fatal("unexpected key/algorithm match result")
	}
}

func TestSignerAndVerifierHelpers(t *testing.T) {
	rsaKey, _ := generateTestKey(t)
	ed25519Key, _ := generateEd25519Record()
	digest := sha256.Sum256([]byte("payload"))

	sealer := &Sealer{PrivateKey: rsaKey}
	if alg, hashName, err := sealer.getAlgorithm(); err != nil || alg != AlgRSASHA256 || hashName != "sha256" {
		t.Fatalf("RSA getAlgorithm() = (%q, %q, %v)", alg, hashName, err)
	}
	sealer.PrivateKey = ed25519Key
	if alg, hashName, err := sealer.getAlgorithm(); err != nil || alg != AlgEd25519SHA256 || hashName != "sha256" {
		t.Fatalf("Ed25519 getAlgorithm() = (%q, %q, %v)", alg, hashName, err)
	}
	sealer.PrivateKey = nil
	if _, _, err := sealer.getAlgorithm(); err == nil {
		t.Fatal("expected unsupported key type error")
	}

	rsaSig, err := signWithKey(rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("signWithKey(RSA) error = %v", err)
	}
	if err := verifyWithKey(&rsaKey.PublicKey, crypto.SHA256, digest[:], rsaSig); err != nil {
		t.Fatalf("verifyWithKey(RSA) error = %v", err)
	}

	edSig, err := signWithKey(ed25519Key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("signWithKey(Ed25519) error = %v", err)
	}
	if err := verifyWithKey(ed25519Key.Public().(ed25519.PublicKey), crypto.SHA256, digest[:], edSig); err != nil {
		t.Fatalf("verifyWithKey(Ed25519) error = %v", err)
	}

	if _, err := signWithKey(nil, crypto.SHA256, digest[:]); err == nil {
		t.Fatal("expected unsupported signer error")
	}
	if err := verifyWithKey(ed25519Key.Public().(ed25519.PublicKey), crypto.SHA256, digest[:], []byte("bad")); err == nil {
		t.Fatal("expected ed25519 verification failure")
	}
	if err := verifyWithKey(struct{}{}, crypto.SHA256, digest[:], rsaSig); err == nil {
		t.Fatal("expected unknown key type error")
	}

	customTime := time.Unix(123, 0)
	if got := (&Sealer{}).now(); got.IsZero() {
		t.Fatal("expected sealer.now() to return current time")
	}
	if got := (&Sealer{Clock: func() time.Time { return customTime }}).now(); !got.Equal(customTime) {
		t.Fatalf("sealer.now() = %v, want %v", got, customTime)
	}
	if got := (&Verifier{}).now(); got.IsZero() {
		t.Fatal("expected verifier.now() to return current time")
	}
	if got := (&Verifier{Clock: func() time.Time { return customTime }}).now(); !got.Equal(customTime) {
		t.Fatalf("verifier.now() = %v, want %v", got, customTime)
	}
}

func TestParseDKIMRecordAndLookupKey(t *testing.T) {
	rsaKey, rsaRecord := generateTestKey(t)
	ed25519Key, ed25519Record := generateEd25519Record()
	pkcs1Record := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey))
	edPKIX, err := x509.MarshalPKIXPublicKey(ed25519Key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey(ed25519) error = %v", err)
	}

	tests := []struct {
		name    string
		record  string
		wantErr bool
	}{
		{name: "invalid version", record: "v=BAD; p=abc", wantErr: true},
		{name: "missing p", record: "v=DKIM1; k=rsa", wantErr: true},
		{name: "invalid base64", record: "v=DKIM1; k=rsa; p=***", wantErr: true},
		{name: "invalid ed25519 size", record: "v=DKIM1; k=ed25519; p=YWJj", wantErr: true},
		{name: "unknown key type", record: "v=DKIM1; k=bogus; p=YWJj", wantErr: true},
		{name: "pkcs1 rsa public key", record: pkcs1Record},
		{name: "unexpected key type in pkix payload", record: "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(edPKIX), wantErr: true},
		{name: "ed25519 record", record: ed25519Record},
		{name: "record with hash restriction", record: rsaRecord + "; h=sha1:sha256"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record, err := parseDKIMRecord(tt.record)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseDKIMRecord() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && strings.Contains(tt.record, "h=sha1:sha256") && len(record.Hashes) != 2 {
				t.Fatalf("expected parsed hash restrictions, got %+v", record.Hashes)
			}
		})
	}

	resolver := &resolverWithErrors{
		txtRecords: map[string][]string{
			"sel._domainkey.example.com":   {rsaRecord},
			"ed._domainkey.example.com":    {ed25519Record},
			"empty._domainkey.example.com": {},
			"bad._domainkey.example.com":   {"v=DKIM1; p=***"},
			"rev._domainkey.example.com":   {"v=DKIM1; k=rsa; p="},
		},
		txtErrors: map[string]error{
			"err._domainkey.example.com": errors.New("dns boom"),
		},
	}
	verifier := &Verifier{Resolver: resolver, MinRSAKeyBits: 4096}

	if _, err := verifier.lookupKey(context.Background(), "sel", "com"); !errors.Is(err, ErrTLD) {
		t.Fatalf("lookupKey(TLD) error = %v", err)
	}
	if _, err := verifier.lookupKey(context.Background(), "missing", "example.com"); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("lookupKey(not found) error = %v", err)
	}
	if _, err := verifier.lookupKey(context.Background(), "err", "example.com"); !errors.Is(err, ErrDNS) {
		t.Fatalf("lookupKey(DNS error) error = %v", err)
	}
	if _, err := verifier.lookupKey(context.Background(), "empty", "example.com"); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("lookupKey(empty records) error = %v", err)
	}
	if _, err := verifier.lookupKey(context.Background(), "bad", "example.com"); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("lookupKey(all invalid records) error = %v", err)
	}
	if _, err := verifier.lookupKey(context.Background(), "rev", "example.com"); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("lookupKey(revoked key) error = %v", err)
	}
	if _, err := verifier.lookupKey(context.Background(), "sel", "example.com"); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("lookupKey(weak key policy) error = %v", err)
	}

	verifier.MinRSAKeyBits = 1024
	record, err := verifier.lookupKey(context.Background(), "ed", "example.com")
	if err != nil {
		t.Fatalf("lookupKey(ed25519) error = %v", err)
	}
	if _, ok := record.PublicKey.(ed25519.PublicKey); !ok {
		t.Fatalf("expected ed25519 public key, got %T", record.PublicKey)
	}
	_ = ed25519Key
}

func TestMailConvenienceFunctions(t *testing.T) {
	privateKey, dkimRecord := generateTestKey(t)
	resolver := &mockResolver{
		txtRecords: map[string][]string{
			"arc._domainkey.example.com": {dkimRecord},
		},
	}

	mail1, err := ravenmail.NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.org").
		Subject("Test").
		MessageID("test@example.com").
		Date(time.Unix(1734607200, 0)).
		TextBody("Body").
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	sealer := &Sealer{
		Domain:                 "example.com",
		Selector:               "arc",
		PrivateKey:             privateKey,
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
		Clock:                  func() time.Time { return time.Unix(1734607200, 0) },
	}
	if err := SignMail(mail1, sealer, "example.com", "spf=pass", ChainValidationNone); err != nil {
		t.Fatalf("SignMail() error = %v", err)
	}
	if len(mail1.Content.Headers) < 3 {
		t.Fatalf("expected ARC headers to be prepended, got %d headers", len(mail1.Content.Headers))
	}
	if mail1.Content.Headers[0].Name != "ARC-Seal" || mail1.Content.Headers[1].Name != "ARC-Message-Signature" || mail1.Content.Headers[2].Name != "ARC-Authentication-Results" {
		t.Fatalf("unexpected ARC header order: %+v", mail1.Content.Headers[:3])
	}
	if strings.Contains(mail1.Content.Headers[1].Value, "\r") || strings.Contains(mail1.Content.Headers[1].Value, "\n") {
		t.Fatalf("ARC-Message-Signature value should be unfolded, got %q", mail1.Content.Headers[1].Value)
	}

	result, err := VerifyMailContext(context.Background(), mail1, resolver)
	if err != nil {
		t.Fatalf("VerifyMailContext() error = %v", err)
	}
	if result.Status != StatusPass {
		t.Fatalf("VerifyMailContext() status = %s, err = %v", result.Status, result.Err)
	}

	mail2, err := ravenmail.NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.org").
		Subject("Test").
		MessageID("test2@example.com").
		Date(time.Unix(1734607200, 0)).
		TextBody("Body").
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if err := QuickSeal(mail2, "example.com", "arc", privateKey, "example.com", "spf=pass", ChainValidationNone); err != nil {
		t.Fatalf("QuickSeal() error = %v", err)
	}

	if got := extractValue("X-Test: value"); got != "value" {
		t.Fatalf("extractValue() = %q, want value", got)
	}
	if got := extractValue("X-Test: one;\r\n\ttwo"); got != "one; two" {
		t.Fatalf("extractValue(unfold) = %q, want %q", got, "one; two")
	}
	if got := extractValue("no-colon"); got != "no-colon" {
		t.Fatalf("extractValue(no colon) = %q", got)
	}

	mail3, err := ravenmail.NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.org").
		Subject("Test").
		Date(time.Unix(1734607200, 0)).
		TextBody("Body").
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if err := SignMail(mail3, &Sealer{Domain: "example.com", Selector: "arc"}, "example.com", "spf=pass", ChainValidationNone); err == nil {
		t.Fatal("expected SignMail() to fail with invalid sealer")
	}
	if err := QuickSeal(mail3, "example.com", "arc", nil, "example.com", "spf=pass", ChainValidationNone); err == nil {
		t.Fatal("expected QuickSeal() to fail with invalid signer")
	}
}

func TestVerifyReaderFailure(t *testing.T) {
	verifier := &Verifier{}
	result, err := verifier.VerifyReader(context.Background(), errReaderAt{err: io.ErrUnexpectedEOF})
	if err != nil {
		t.Fatalf("VerifyReader() error = %v", err)
	}
	if result.Status != StatusFail || result.Err == nil {
		t.Fatalf("unexpected VerifyReader() result: %+v", result)
	}
}

func TestVerifyChainStructuralFailures(t *testing.T) {
	verifier := &Verifier{}

	result, err := verifier.verifyChain(context.Background(), []*Set{{Instance: 1, Seal: &Seal{ChainValidation: ChainValidationPass}}}, nil, nil, 0)
	if err != nil {
		t.Fatalf("verifyChain() error = %v", err)
	}
	if result.Status != StatusFail || !errors.Is(result.Err, ErrChainValidationMismatch) {
		t.Fatalf("expected first cv mismatch failure, got %+v", result)
	}

	result, err = verifier.verifyChain(context.Background(), []*Set{
		{Instance: 1, Seal: &Seal{ChainValidation: ChainValidationNone}},
		{Instance: 2, Seal: &Seal{ChainValidation: ChainValidationNone}},
	}, nil, nil, 0)
	if err != nil {
		t.Fatalf("verifyChain() error = %v", err)
	}
	if result.Status != StatusFail || !errors.Is(result.Err, ErrChainValidationMismatch) {
		t.Fatalf("expected later cv mismatch failure, got %+v", result)
	}

	result, err = verifier.verifyChain(context.Background(), []*Set{
		{Instance: 1, Seal: &Seal{ChainValidation: ChainValidationNone}},
		{Instance: 2, Seal: &Seal{ChainValidation: ChainValidationFail}},
	}, nil, nil, 0)
	if err != nil {
		t.Fatalf("verifyChain() error = %v", err)
	}
	if result.Status != StatusFail || result.FailedInstance != 2 || result.Err != nil {
		t.Fatalf("expected cv=fail short-circuit, got %+v", result)
	}
}

func TestAdditionalExtractionAndParsingCoverage(t *testing.T) {
	if _, err := extractARCSets([]headerData{{raw: []byte("ARC-Authentication-Results: broken\r\n"), lkey: "arc-authentication-results"}}); err == nil {
		t.Fatal("expected AAR parse failure")
	}
	if _, err := extractARCSets([]headerData{{raw: []byte("ARC-Authentication-Results: i=1; example.com\r\n"), lkey: "arc-authentication-results"}, {raw: []byte("ARC-Authentication-Results: i=1; example.com\r\n"), lkey: "arc-authentication-results"}}); err == nil {
		t.Fatal("expected duplicate AAR failure")
	}
	if _, err := extractARCSets([]headerData{{raw: []byte("ARC-Message-Signature: broken\r\n"), lkey: "arc-message-signature"}}); err == nil {
		t.Fatal("expected AMS parse failure")
	}
	if _, err := extractARCSets([]headerData{{raw: []byte("ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel; h=From; bh=YWJj; b=ZGVm\r\n"), lkey: "arc-message-signature"}, {raw: []byte("ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel; h=From; bh=YWJj; b=ZGVm\r\n"), lkey: "arc-message-signature"}}); err == nil {
		t.Fatal("expected duplicate AMS failure")
	}
	if _, err := extractARCSets([]headerData{{raw: []byte("ARC-Seal: broken\r\n"), lkey: "arc-seal"}}); err == nil {
		t.Fatal("expected ARC-Seal parse failure")
	}
	if _, err := extractARCSets([]headerData{{raw: []byte("ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; b=ZGVm\r\n"), lkey: "arc-seal"}, {raw: []byte("ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; b=ZGVm\r\n"), lkey: "arc-seal"}}); err == nil {
		t.Fatal("expected duplicate ARC-Seal failure")
	}
	if _, err := extractARCSets([]headerData{
		{raw: []byte("ARC-Authentication-Results: i=0; example.com\r\n"), lkey: "arc-authentication-results"},
		{raw: []byte("ARC-Message-Signature: i=0; a=rsa-sha256; d=example.com; s=sel; h=From; bh=YWJj; b=ZGVm\r\n"), lkey: "arc-message-signature"},
		{raw: []byte("ARC-Seal: i=0; a=rsa-sha256; cv=none; d=example.com; s=sel; b=ZGVm\r\n"), lkey: "arc-seal"},
	}); err == nil {
		t.Fatal("expected invalid instance extraction failure")
	}
	if _, err := extractARCSets([]headerData{{raw: []byte("ARC-Authentication-Results: i=1; example.com\r\n"), lkey: "arc-authentication-results"}}); err == nil {
		t.Fatal("expected missing AMS/AS failure")
	}
	if _, err := extractARCSets([]headerData{
		{raw: []byte("ARC-Authentication-Results: i=1; example.com\r\n"), lkey: "arc-authentication-results"},
		{raw: []byte("ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel; h=From; bh=YWJj; b=ZGVm\r\n"), lkey: "arc-message-signature"},
		{raw: []byte("ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; b=ZGVm\r\n"), lkey: "arc-seal"},
		{raw: []byte("ARC-Authentication-Results: i=3; example.com\r\n"), lkey: "arc-authentication-results"},
		{raw: []byte("ARC-Message-Signature: i=3; a=rsa-sha256; d=example.com; s=sel; h=From; bh=YWJj; b=ZGVm\r\n"), lkey: "arc-message-signature"},
		{raw: []byte("ARC-Seal: i=3; a=rsa-sha256; cv=pass; d=example.com; s=sel; b=ZGVm\r\n"), lkey: "arc-seal"},
	}); err == nil {
		t.Fatal("expected extra instance failure")
	}
}

func TestAdditionalHelperCoverage(t *testing.T) {
	if isTLD("") {
		t.Fatal("empty domain must not be treated as TLD")
	}

	headers, bodyOffset, err := parseHeaders(bufio.NewReader(strings.NewReader("\tcontinued\r\nHeader: value")))
	if err != nil {
		t.Fatalf("parseHeaders(leading continuation) error = %v", err)
	}
	if len(headers) != 1 || bodyOffset == 0 {
		t.Fatalf("unexpected parseHeaders() result: len=%d bodyOffset=%d", len(headers), bodyOffset)
	}

	line, err := readHeaderLine(bufio.NewReader(strings.NewReader("Header: value")))
	if err != nil && err != io.EOF {
		t.Fatalf("readHeaderLine(no newline) error = %v", err)
	}
	if string(line) != "Header: value" {
		t.Fatalf("unexpected line without newline: %q", line)
	}

	line, err = readHeaderLine(bufio.NewReader(strings.NewReader("Header: value\r\n")))
	if err != nil {
		t.Fatalf("readHeaderLine(final newline) error = %v", err)
	}
	if string(line) != "Header: value\r\n" {
		t.Fatalf("unexpected line with final newline: %q", line)
	}
}

func TestVerifierAndSealerAdditionalErrorCoverage(t *testing.T) {
	privateKey, dkimRecord := generateTestKey(t)
	_, edRecord := generateEd25519Record()
	resolver := &resolverWithErrors{txtRecords: map[string][]string{
		"arc._domainkey.example.com":      {dkimRecord},
		"hashonly._domainkey.example.com": {dkimRecord + "; h=sha1"},
		"edsel._domainkey.example.com":    {edRecord},
		"arc._domainkey.forwarder.org":    {dkimRecord},
	}}
	verifier := &Verifier{Resolver: resolver, MinRSAKeyBits: 1024, Clock: func() time.Time { return time.Unix(1734607200, 0) }}

	message, _, _ := buildSignedMessage(t, privateKey, "example.com", "arc", &mockResolver{txtRecords: map[string][]string{"arc._domainkey.example.com": {dkimRecord}}})
	headers, bodyOffset := parseTestHeaders(t, message)
	sets, err := extractARCSets(headers)
	if err != nil {
		t.Fatalf("extractARCSets() error = %v", err)
	}

	msNoFrom := *sets[0].MessageSignature
	msNoFrom.SignedHeaders = []string{"Subject"}
	if err := verifier.verifyMessageSignature(context.Background(), &msNoFrom, headers, bytes.NewReader(message), bodyOffset); err == nil {
		t.Fatal("expected verifyMessageSignature() to fail when From is unsigned")
	}

	msHashBlocked := *sets[0].MessageSignature
	msHashBlocked.Selector = "hashonly"
	if err := verifier.verifyMessageSignature(context.Background(), &msHashBlocked, headers, bytes.NewReader(message), bodyOffset); err == nil {
		t.Fatal("expected verifyMessageSignature() to fail when key record disallows hash")
	}

	msKeyMismatch := *sets[0].MessageSignature
	msKeyMismatch.Selector = "edsel"
	if err := verifier.verifyMessageSignature(context.Background(), &msKeyMismatch, headers, bytes.NewReader(message), bodyOffset); err == nil {
		t.Fatal("expected verifyMessageSignature() to fail on key/signature mismatch")
	}

	if err := verifier.verifyMessageSignature(context.Background(), sets[0].MessageSignature, headers, errReaderAt{err: io.ErrUnexpectedEOF}, bodyOffset); err == nil {
		t.Fatal("expected verifyMessageSignature() body read failure")
	}

	badHeaders := append([]headerData{}, headers...)
	for i, hdr := range badHeaders {
		if hdr.lkey == "from" {
			badHeaders[i] = headerData{raw: []byte("broken\r\n"), lkey: "from"}
			break
		}
	}
	if err := verifier.verifyMessageSignature(context.Background(), sets[0].MessageSignature, badHeaders, bytes.NewReader(message), bodyOffset); err == nil {
		t.Fatal("expected verifyMessageSignature() header hash failure")
	}

	sealHashBlocked := *sets[0].Seal
	sealHashBlocked.Selector = "hashonly"
	if err := verifier.verifySeal(context.Background(), []*Set{{Instance: 1, Seal: &sealHashBlocked}}, headers); err == nil {
		t.Fatal("expected verifySeal() to fail when key record disallows hash")
	}

	sealKeyMismatch := *sets[0].Seal
	sealKeyMismatch.Selector = "edsel"
	if err := verifier.verifySeal(context.Background(), []*Set{{Instance: 1, Seal: &sealKeyMismatch}}, headers); err == nil {
		t.Fatal("expected verifySeal() to fail on key/signature mismatch")
	}

	if err := verifier.verifySeal(context.Background(), nil, headers); err == nil {
		t.Fatal("expected verifySeal() to fail on empty set list")
	}

	tampered := append([]headerData{}, headers...)
	setsForChain, err := extractARCSets(tampered)
	if err != nil {
		t.Fatalf("extractARCSets() error = %v", err)
	}
	setsForChain[0].Seal.Signature[0] ^= 0xFF
	chainResult, err := verifier.verifyChain(context.Background(), setsForChain, tampered, bytes.NewReader(message), bodyOffset)
	if err != nil {
		t.Fatalf("verifyChain() error = %v", err)
	}
	if chainResult.Status != StatusFail || chainResult.FailedInstance != 1 {
		t.Fatalf("expected verifyChain() seal failure, got %+v", chainResult)
	}

	tooMany := []byte(testRawMessage())
	for i := MaxInstance; i >= 1; i-- {
		tooMany = []byte(
			"ARC-Seal: i=" + strconv.Itoa(i) + "; a=rsa-sha256; cv=none; d=example.com; s=arc; b=ZGVm\r\n" +
				"ARC-Message-Signature: i=" + strconv.Itoa(i) + "; a=rsa-sha256; d=example.com; s=arc; h=From; bh=YWJj; b=ZGVm\r\n" +
				"ARC-Authentication-Results: i=" + strconv.Itoa(i) + "; example.com\r\n" +
				string(tooMany),
		)
	}
	if _, err := (&Sealer{Domain: "example.com", Selector: "arc", PrivateKey: privateKey}).Seal(tooMany, "example.com", "spf=pass", ChainValidationPass); err == nil {
		t.Fatal("expected Seal() to fail when next instance exceeds MaxInstance")
	}

	if _, err := (&Sealer{Domain: "example.com", Selector: "arc", PrivateKey: privateKey, Headers: []string{"Subject"}}).Seal(testRawMessage(), "example.com", "spf=pass", ChainValidationNone); err != nil {
		t.Fatalf("Seal() without From in configured headers should still succeed: %v", err)
	}
}

func TestARCVerificationSemantics(t *testing.T) {
	privateKey, dkimRecord := generateTestKey(t)
	resolver := &mockResolver{
		txtRecords: map[string][]string{
			"arc._domainkey.example.com":   {dkimRecord},
			"arc._domainkey.forwarder.org": {dkimRecord},
		},
	}
	fixedTime := time.Unix(1734607200, 0)

	sealer1 := &Sealer{
		Domain:                 "example.com",
		Selector:               "arc",
		PrivateKey:             privateKey,
		Headers:                []string{"From", "To", "Subject", "Date", "Message-ID"},
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
		Clock:                  func() time.Time { return fixedTime },
	}
	firstSet, err := sealer1.Seal(testRawMessage(), "example.com", "spf=pass; dkim=pass", ChainValidationNone)
	if err != nil {
		t.Fatalf("first Seal() error = %v", err)
	}
	sealed1 := []byte(firstSet.Seal + "\r\n" + firstSet.MessageSignature + "\r\n" + firstSet.AuthenticationResults + "\r\n" + string(testRawMessage()))

	modified := bytes.Replace(sealed1, []byte("This is a test message."), []byte("This message was modified."), 1)
	sealer2 := &Sealer{
		Domain:                 "forwarder.org",
		Selector:               "arc",
		PrivateKey:             privateKey,
		Headers:                []string{"From", "To", "Subject", "Date", "Message-ID", "ARC-Seal", "ARC-Authentication-Results", "ARC-Message-Signature", "Authentication-Results"},
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
		Clock:                  func() time.Time { return fixedTime },
	}
	secondSet, err := sealer2.Seal(modified, "forwarder.org", "arc=pass", ChainValidationPass)
	if err != nil {
		t.Fatalf("second Seal() error = %v", err)
	}
	parsedSecondMS, _, err := ParseMessageSignature(strings.TrimPrefix(secondSet.MessageSignature, "ARC-Message-Signature: "))
	if err != nil {
		t.Fatalf("ParseMessageSignature() error = %v", err)
	}
	for _, name := range parsedSecondMS.SignedHeaders {
		lower := strings.ToLower(name)
		if lower == "authentication-results" || lower == "arc-authentication-results" || lower == "arc-message-signature" || lower == "arc-seal" {
			t.Fatalf("AMS must not sign prohibited header %q", name)
		}
	}

	sealed2 := []byte(secondSet.Seal + "\r\n" + secondSet.MessageSignature + "\r\n" + secondSet.AuthenticationResults + "\r\n" + string(modified))
	verifier := &Verifier{
		Resolver:      resolver,
		MinRSAKeyBits: 1024,
		Clock:         func() time.Time { return fixedTime },
	}
	verifyResult, err := verifier.Verify(context.Background(), sealed2)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verifyResult.Status != StatusPass {
		t.Fatalf("Verify() status = %s, err = %v", verifyResult.Status, verifyResult.Err)
	}
	if verifyResult.OldestPass != 2 {
		t.Fatalf("OldestPass = %d, want 2", verifyResult.OldestPass)
	}

	tamperedFinal := bytes.Replace(sealed2, []byte("This message was modified."), []byte("This message was changed after sealing."), 1)
	failedResult, err := verifier.Verify(context.Background(), tamperedFinal)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if failedResult.Status != StatusFail || failedResult.FailedInstance != 2 {
		t.Fatalf("expected newest AMS failure, got %+v", failedResult)
	}
}

func TestSealingFailureSemantics(t *testing.T) {
	privateKey, _ := generateTestKey(t)
	sealer := &Sealer{Domain: "example.com", Selector: "arc", PrivateKey: privateKey}

	failedChain := []byte("ARC-Seal: i=1; a=rsa-sha256; cv=fail; d=example.com; s=arc; b=sig=\r\n" +
		"ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=arc; h=From; bh=abc=; b=sig=\r\n" +
		"ARC-Authentication-Results: i=1; example.com\r\n" +
		string(testRawMessage()))
	if _, err := sealer.Seal(failedChain, "example.com", "arc=fail", ChainValidationPass); err == nil {
		t.Fatal("expected sealing to stop when most recent cv=fail")
	}

	newSet, err := sealer.Seal(testRawMessage(), "example.com", "arc=fail", ChainValidationNone)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	failedSet, err := sealer.Seal([]byte(newSet.Seal+"\r\n"+newSet.MessageSignature+"\r\n"+newSet.AuthenticationResults+"\r\n"+string(testRawMessage())), "example.com", "arc=fail", ChainValidationFail)
	if err != nil {
		t.Fatalf("Seal(cv=fail) error = %v", err)
	}
	if !strings.Contains(failedSet.Seal, "cv=fail") {
		t.Fatalf("expected cv=fail seal, got %q", failedSet.Seal)
	}
}

func TestDirectVerificationErrorPaths(t *testing.T) {
	privateKey, dkimRecord := generateTestKey(t)
	resolver := &resolverWithErrors{
		txtRecords: map[string][]string{"arc._domainkey.example.com": {dkimRecord}},
		txtErrors:  map[string]error{"err._domainkey.example.com": errors.New("dns boom")},
	}
	verifier := &Verifier{Resolver: resolver, Clock: func() time.Time { return time.Unix(200, 0) }}

	if err := verifier.verifyMessageSignature(context.Background(), &MessageSignature{Algorithm: "bogus-sha256"}, nil, bytes.NewReader(nil), 0); err == nil {
		t.Fatal("expected unknown sign algorithm error")
	}
	if err := verifier.verifyMessageSignature(context.Background(), &MessageSignature{Algorithm: "rsa-bogus"}, nil, bytes.NewReader(nil), 0); err == nil {
		t.Fatal("expected unknown hash algorithm error")
	}
	if err := verifier.verifyMessageSignature(context.Background(), &MessageSignature{Algorithm: "rsa-sha256", Canonicalization: "bogus/bogus"}, nil, bytes.NewReader(nil), 0); err == nil {
		t.Fatal("expected unknown canonicalization error")
	}
	if err := verifier.verifyMessageSignature(context.Background(), &MessageSignature{Algorithm: "rsa-sha256", Expiration: 100, SignedHeaders: []string{"From"}}, nil, bytes.NewReader(nil), 0); err == nil {
		t.Fatal("expected expiration error")
	}
	if err := verifier.verifyMessageSignature(context.Background(), &MessageSignature{Algorithm: "rsa-sha256", SignedHeaders: []string{"Subject"}}, nil, bytes.NewReader(nil), 0); err == nil {
		t.Fatal("expected missing From error")
	}
	if err := verifier.verifyMessageSignature(context.Background(), &MessageSignature{Algorithm: "rsa-sha256", Domain: "example.com", Selector: "err", SignedHeaders: []string{"From"}}, nil, bytes.NewReader(nil), 0); err == nil {
		t.Fatal("expected lookup error")
	}

	bodyHash, err := computeBodyHash(sha256.New(), CanonSimple, strings.NewReader(""), -1)
	if err != nil {
		t.Fatalf("computeBodyHash() error = %v", err)
	}
	ms := &MessageSignature{
		Instance:         1,
		Algorithm:        "rsa-sha256",
		Domain:           "example.com",
		Selector:         "arc",
		Canonicalization: "simple/simple",
		SignedHeaders:    []string{"From"},
		BodyHash:         []byte("wrong"),
	}
	if err := verifier.verifyMessageSignature(context.Background(), ms, []headerData{{raw: []byte("From: sender@example.com\r\n"), lkey: "from"}}, bytes.NewReader([]byte("\r\n")), 0); err == nil {
		t.Fatal("expected body hash mismatch")
	}

	ms.BodyHash = bodyHash
	headers := []headerData{
		{raw: []byte("broken\r\n"), lkey: "from"},
		{raw: []byte(ms.Header(false) + "\r\n"), lkey: "arc-message-signature"},
	}
	if err := verifier.verifyMessageSignature(context.Background(), ms, headers, bytes.NewReader([]byte("\r\n")), 0); err == nil {
		t.Fatal("expected computeAMSDataHash error")
	}

	validMessage, _, validVerifier := buildSignedMessage(t, privateKey, "example.com", "arc", &mockResolver{txtRecords: map[string][]string{"arc._domainkey.example.com": {dkimRecord}}})
	validHeaders, bodyOffset := parseTestHeaders(t, validMessage)
	sets, err := extractARCSets(validHeaders)
	if err != nil {
		t.Fatalf("extractARCSets() error = %v", err)
	}
	sets[0].MessageSignature.Signature[0] ^= 0xFF
	if err := validVerifier.verifyMessageSignature(context.Background(), sets[0].MessageSignature, validHeaders, bytes.NewReader(validMessage), bodyOffset); err == nil {
		t.Fatal("expected AMS signature verification failure")
	}

	if err := verifier.verifySeal(context.Background(), []*Set{{Seal: &Seal{Algorithm: "bogus-sha256"}}}, nil); err == nil {
		t.Fatal("expected unknown ARC-Seal sign algorithm error")
	}
	if err := verifier.verifySeal(context.Background(), []*Set{{Seal: &Seal{Algorithm: "rsa-bogus"}}}, nil); err == nil {
		t.Fatal("expected unknown ARC-Seal hash algorithm error")
	}
	if err := verifier.verifySeal(context.Background(), []*Set{{Seal: &Seal{Instance: 1, Algorithm: "rsa-sha256", Domain: "example.com", Selector: "err"}}}, nil); err == nil {
		t.Fatal("expected ARC-Seal lookup error")
	}
	badSealHeaders := []headerData{{raw: []byte("broken\r\n"), lkey: "arc-authentication-results"}}
	if err := verifier.verifySeal(context.Background(), []*Set{{Instance: 1, Seal: &Seal{Instance: 1, Algorithm: "rsa-sha256", Domain: "example.com", Selector: "arc"}}}, badSealHeaders); err == nil {
		t.Fatal("expected ARC-Seal data hash error")
	}

	validHeaders, _ = parseTestHeaders(t, validMessage)
	sets, err = extractARCSets(validHeaders)
	if err != nil {
		t.Fatalf("extractARCSets() error = %v", err)
	}
	sets[0].Seal.Signature[0] ^= 0xFF
	if err := validVerifier.verifySeal(context.Background(), sets[:1], validHeaders); err == nil {
		t.Fatal("expected ARC-Seal signature verification failure")
	}
}
