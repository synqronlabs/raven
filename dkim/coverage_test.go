package dkim

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	ravendns "github.com/synqronlabs/raven/dns"
	ravenmail "github.com/synqronlabs/raven/mail"
)

type failingReader struct {
	err error
}

func (r failingReader) Read(_ []byte) (int, error) {
	return 0, r.err
}

type failingReaderAt struct {
	err error
}

func (r failingReaderAt) ReadAt(_ []byte, _ int64) (int, error) {
	return 0, r.err
}

type errHash struct {
	writeErr error
	sum      []byte
}

func (h *errHash) Write(p []byte) (int, error) {
	if h.writeErr != nil {
		return 0, h.writeErr
	}
	h.sum = append(h.sum, p...)
	return len(p), nil
}

func (h *errHash) Sum(b []byte) []byte {
	return append(b, h.sum...)
}

func (h *errHash) Reset() {
	h.sum = nil
}

func (*errHash) Size() int {
	return sha256.Size
}

func (*errHash) BlockSize() int {
	return sha256.BlockSize
}

func testMessageBytes() []byte {
	return []byte("From: sender@example.com\r\n" +
		"To: recipient@example.org\r\n" +
		"Subject: Coverage\r\n" +
		"Date: Thu, 18 Dec 2025 12:00:00 +0000\r\n" +
		"Message-ID: <coverage@example.com>\r\n" +
		"\r\n" +
		"Coverage body.\r\n")
}

func testMail() *ravenmail.Mail {
	return &ravenmail.Mail{
		Content: ravenmail.Content{
			Headers: ravenmail.Headers{
				{Name: "From", Value: "sender@example.com"},
				{Name: "To", Value: "recipient@example.org"},
				{Name: "Subject", Value: "Coverage"},
				{Name: "Date", Value: "Thu, 18 Dec 2025 12:00:00 +0000"},
				{Name: "Message-ID", Value: "<coverage@example.com>"},
			},
			Body: []byte("Coverage body.\r\n"),
		},
	}
}

func signAndParseMessage(t *testing.T, signer *Signer, message []byte) ([]byte, []headerData, int, *Signature, []byte) {
	t.Helper()

	sigHeader, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	signedMessage := append([]byte(sigHeader), message...)
	headers, bodyOffset, err := parseMessageHeaders(signedMessage)
	if err != nil {
		t.Fatalf("parseMessageHeaders() error = %v", err)
	}

	if len(headers) == 0 {
		t.Fatal("expected signed message headers")
	}

	sig, verifySig, err := ParseSignature(string(headers[0].raw))
	if err != nil {
		t.Fatalf("ParseSignature() error = %v", err)
	}

	return signedMessage, headers, bodyOffset, sig, verifySig
}

func signMessageWithLength(t *testing.T, signer *Signer, message []byte, bodyLength int64) []byte {
	t.Helper()

	headers, bodyOffset, err := parseMessageHeaders(message)
	if err != nil {
		t.Fatalf("parseMessageHeaders() error = %v", err)
	}

	alg, hashAlg, err := signer.getAlgorithm()
	if err != nil {
		t.Fatalf("getAlgorithm() error = %v", err)
	}

	headerCanon := signer.HeaderCanonicalization
	if headerCanon == "" {
		headerCanon = CanonRelaxed
	}
	bodyCanon := signer.BodyCanonicalization
	if bodyCanon == "" {
		bodyCanon = CanonRelaxed
	}

	sig := NewSignature()
	sig.Version = 1
	sig.Domain = signer.Domain
	sig.Selector = signer.Selector
	sig.Algorithm = string(alg)
	sig.Canonicalization = string(headerCanon) + "/" + string(bodyCanon)
	sig.SignedHeaders = append([]string(nil), signer.Headers...)
	sig.Length = bodyLength
	sig.SignTime = -1
	sig.ExpireTime = -1

	hashFunc, ok := getHash(hashAlg)
	if !ok {
		t.Fatalf("getHash(%q) failed", hashAlg)
	}

	bodyHash, _, err := computeBodyHashLimitedReader(hashFunc.New(), bodyCanon, bytes.NewReader(message[bodyOffset:]), bodyLength)
	if err != nil {
		t.Fatalf("computeBodyHashLimitedReader() error = %v", err)
	}
	sig.BodyHash = bodyHash

	sigHeader, err := sig.Header(false)
	if err != nil {
		t.Fatalf("Header(false) error = %v", err)
	}

	dataHash, err := computeDataHash(hashFunc.New(), headerCanon, headers, sig.SignedHeaders, []byte(sigHeader))
	if err != nil {
		t.Fatalf("computeDataHash() error = %v", err)
	}

	signature, err := signWithKey(signer.PrivateKey, hashFunc, dataHash)
	if err != nil {
		t.Fatalf("signWithKey() error = %v", err)
	}
	sig.Signature = signature

	finalHeader, err := sig.Header(true)
	if err != nil {
		t.Fatalf("Header(true) error = %v", err)
	}

	return append([]byte(finalHeader+"\r\n"), message...)
}

func TestCanonicalizationCoverage(t *testing.T) {
	if _, err := canonicalizeHeaderRelaxed("Subject without colon"); !errors.Is(err, ErrHeaderMalformed) {
		t.Fatalf("canonicalizeHeaderRelaxed() error = %v, want %v", err, ErrHeaderMalformed)
	}

	if _, err := bodyHashSimple(crypto.SHA256.New(), failingReader{err: errors.New("boom")}); err == nil {
		t.Fatal("expected bodyHashSimple() error")
	}

	if _, err := bodyHashRelaxed(crypto.SHA256.New(), failingReader{err: errors.New("boom")}); err == nil {
		t.Fatal("expected bodyHashRelaxed() error")
	}

	goodHeaders := []headerData{{key: "Subject", lkey: "subject", raw: []byte("Subject: value\r\n")}}
	if _, err := computeDataHash(crypto.SHA256.New(), CanonRelaxed, []headerData{{key: "Subject", lkey: "subject", raw: []byte("Subject value\r\n")}}, []string{"Subject"}, []byte("DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=test; h=subject; bh="+base64.StdEncoding.EncodeToString(make([]byte, 32))+"; b=")); err == nil {
		t.Fatal("expected computeDataHash() signed-header canonicalization error")
	}

	if _, err := computeDataHash(crypto.SHA256.New(), CanonRelaxed, goodHeaders, []string{"Subject"}, []byte("DKIM-Signature without colon")); err == nil {
		t.Fatal("expected computeDataHash() signature-header canonicalization error")
	}

	parseCases := []struct {
		name string
		data string
	}{
		{name: "continuation before first header", data: " folded\r\n\r\n"},
		{name: "missing colon", data: "Subject\r\n\r\n"},
		{name: "invalid header name", data: "Bad Header: value\r\n\r\n"},
	}
	for _, tc := range parseCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseHeaders(bufio.NewReader(strings.NewReader(tc.data)))
			if !errors.Is(err, ErrHeaderMalformed) {
				t.Fatalf("parseHeaders() error = %v, want %v", err, ErrHeaderMalformed)
			}
		})
	}

	if h, ok := getHash("sha512"); ok || h != 0 {
		t.Fatalf("getHash(sha512) = (%v, %v), want (0, false)", h, ok)
	}
	if h, ok := getHash("sha1"); !ok || h != crypto.SHA1 {
		t.Fatalf("getHash(sha1) = (%v, %v), want (%v, true)", h, ok, crypto.SHA1)
	}
}

func TestCanonicalizationHashErrorCoverage(t *testing.T) {
	hashErr := errors.New("hash write failed")

	if _, _, err := computeBodyHashLimitedReader(&errHash{writeErr: hashErr}, CanonSimple, strings.NewReader("body"), -1); !strings.Contains(err.Error(), "writing canonicalized body to hash") {
		t.Fatalf("computeBodyHashLimitedReader() error = %v", err)
	}

	if _, _, err := computeBodyHashLimitedReader(crypto.SHA256.New(), CanonSimple, strings.NewReader("body"), 100); !errors.Is(err, ErrBodyHashLength) {
		t.Fatalf("computeBodyHashLimitedReader() error = %v, want %v", err, ErrBodyHashLength)
	}

	if _, err := bodyHashSimple(&errHash{writeErr: hashErr}, strings.NewReader("body")); !strings.Contains(err.Error(), "writing simple canonicalized body to hash") {
		t.Fatalf("bodyHashSimple() error = %v", err)
	}

	if _, err := bodyHashRelaxed(&errHash{writeErr: hashErr}, strings.NewReader("body")); !strings.Contains(err.Error(), "writing relaxed canonicalized body to hash") {
		t.Fatalf("bodyHashRelaxed() error = %v", err)
	}

	canonical, err := canonicalizeBodyRelaxed(strings.NewReader(" \t"))
	if err != nil {
		t.Fatalf("canonicalizeBodyRelaxed() error = %v", err)
	}
	if got, want := string(canonical), "\r\n"; got != want {
		t.Fatalf("canonicalizeBodyRelaxed() = %q, want %q", got, want)
	}
}

func TestSignatureHelpersCoverage(t *testing.T) {
	ed25519Key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

	if err := verifyWithKey(ed25519Key.Public(), crypto.Hash(0), []byte("data"), []byte("bad-signature")); !errors.Is(err, ErrSigVerify) {
		t.Fatalf("verifyWithKey() error = %v, want %v", err, ErrSigVerify)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	dataHash := sha256.Sum256([]byte("data"))
	if _, err := signWithKey(ecdsaKey, crypto.SHA256, dataHash[:]); !errors.Is(err, ErrSigAlgorithmUnknown) {
		t.Fatalf("signWithKey() error = %v, want %v", err, ErrSigAlgorithmUnknown)
	}

	if err := verifyWithKey(&ecdsaKey.PublicKey, crypto.SHA256, []byte("data"), []byte("sig")); !errors.Is(err, ErrSigAlgorithmUnknown) {
		t.Fatalf("verifyWithKey() error = %v, want %v", err, ErrSigAlgorithmUnknown)
	}

	rsaKey := getRSAKey(t)
	sig := &Signature{Algorithm: "rsa", Canonicalization: "relaxed", ExpireTime: 9}
	if sig.AlgorithmSign() != "rsa" {
		t.Fatalf("AlgorithmSign() = %q, want rsa", sig.AlgorithmSign())
	}
	if sig.AlgorithmHash() != "" {
		t.Fatalf("AlgorithmHash() = %q, want empty", sig.AlgorithmHash())
	}
	if sig.HeaderCanon() != CanonRelaxed {
		t.Fatalf("HeaderCanon() = %q, want %q", sig.HeaderCanon(), CanonRelaxed)
	}
	if sig.BodyCanon() != CanonSimple {
		t.Fatalf("BodyCanon() = %q, want %q", sig.BodyCanon(), CanonSimple)
	}

	originalNow := timeNow
	timeNow = func() time.Time { return time.Unix(10, 0) }
	defer func() { timeNow = originalNow }()
	if !sig.IsExpired() {
		t.Fatal("expected IsExpired() to return true")
	}

	if alg, hashAlg, err := (&Signer{PrivateKey: rsaKey, Hash: "sha1"}).getAlgorithm(); err != nil || alg != AlgRSASHA1 || hashAlg != "sha1" {
		t.Fatalf("getAlgorithm() = (%q, %q, %v), want (%q, %q, nil)", alg, hashAlg, err, AlgRSASHA1, "sha1")
	}

	if _, _, err := (&Signer{PrivateKey: ecdsaKey}).getAlgorithm(); !errors.Is(err, ErrSigAlgorithmUnknown) {
		t.Fatalf("getAlgorithm() error = %v, want %v", err, ErrSigAlgorithmUnknown)
	}

	parser := &signatureParser{s: "ab"}
	if got := parser.take(10); got != "ab" {
		t.Fatalf("take() = %q, want ab", got)
	}

	bodyHash := bytes.Repeat([]byte{1}, 32)
	header, err := (&Signature{
		Version:          1,
		Algorithm:        "rsa-sha256",
		Domain:           "example.com",
		Selector:         "sel",
		Identity:         "@example.com",
		Length:           10,
		SignTime:         -1,
		ExpireTime:       -1,
		QueryMethods:     []string{"dns/txt", "custom"},
		Canonicalization: "relaxed/relaxed",
		SignedHeaders:    []string{"from", "subject"},
		CopiedHeaders:    []string{"Subject: spaced value", "X-Test:semicolon;pipe|colon:"},
		BodyHash:         bodyHash,
		Signature:        []byte("sig"),
	}).Header(true)
	if err != nil {
		t.Fatalf("Header() error = %v", err)
	}
	parsed, _, err := ParseSignature(header)
	if err != nil {
		t.Fatalf("ParseSignature() error = %v", err)
	}
	if got, want := parsed.CopiedHeaders[0], "Subject: spaced value"; got != want {
		t.Fatalf("CopiedHeaders[0] = %q, want %q", got, want)
	}
	if got, want := parsed.CopiedHeaders[1], "X-Test:semicolon;pipe|colon:"; got != want {
		t.Fatalf("CopiedHeaders[1] = %q, want %q", got, want)
	}

	parseErrors := []struct {
		name   string
		header string
	}{
		{name: "missing colon", header: "DKIM-Signature v=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=" + base64.StdEncoding.EncodeToString(bodyHash) + "; b=dGVzdA=="},
		{name: "invalid signature encoding", header: "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=" + base64.StdEncoding.EncodeToString(bodyHash) + "; b=*"},
		{name: "invalid body hash encoding", header: "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=*; b=dGVzdA=="},
		{name: "invalid length", header: "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; h=from; l=bad; bh=" + base64.StdEncoding.EncodeToString(bodyHash) + "; b=dGVzdA=="},
		{name: "invalid timestamp", header: "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; h=from; t=bad; bh=" + base64.StdEncoding.EncodeToString(bodyHash) + "; b=dGVzdA=="},
		{name: "invalid expiration", header: "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; h=from; x=bad; bh=" + base64.StdEncoding.EncodeToString(bodyHash) + "; b=dGVzdA=="},
		{name: "sign time after expiration", header: "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; h=from; t=20; x=10; bh=" + base64.StdEncoding.EncodeToString(bodyHash) + "; b=dGVzdA=="},
		{name: "identity mismatch", header: "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; i=user@other.example; h=from; bh=" + base64.StdEncoding.EncodeToString(bodyHash) + "; b=dGVzdA=="},
	}
	for _, tc := range parseErrors {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := ParseSignature(tc.header); err == nil {
				t.Fatal("expected ParseSignature() error")
			}
		})
	}
}

func TestRecordCoverage(t *testing.T) {
	if (&Record{Services: []string{"calendar"}}).ServiceAllowed("email") {
		t.Fatal("ServiceAllowed(email) = true, want false")
	}

	if _, err := (&Record{Version: "bad"}).ToTXT(); err == nil {
		t.Fatal("expected ToTXT() version error")
	}

	ed25519Key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	record := &Record{
		Version:   "DKIM1",
		Key:       "ed25519",
		Notes:     " leading;note",
		Services:  []string{"email"},
		Flags:     []string{"y"},
		PublicKey: ed25519Key.Public(),
	}
	txt, err := record.ToTXT()
	if err != nil {
		t.Fatalf("ToTXT() error = %v", err)
	}
	if !strings.Contains(txt, "n=") {
		t.Fatalf("ToTXT() = %q, want notes tag", txt)
	}
	parsed, isDKIM, err := ParseRecord(txt)
	if err != nil || !isDKIM {
		t.Fatalf("ParseRecord() = (%v, %v, %v), want valid DKIM record", parsed, isDKIM, err)
	}
	if parsed.Notes != record.Notes {
		t.Fatalf("notes = %q, want %q", parsed.Notes, record.Notes)
	}

	if _, err := marshalPublicKey("nope"); err == nil {
		t.Fatal("expected marshalPublicKey() error")
	}

	if got, want := decodeQPSection(encodeQPSection(" leading;note=")), " leading;note="; got != want {
		t.Fatalf("decodeQPSection(encodeQPSection()) = %q, want %q", got, want)
	}

	parseRecordErrors := []string{
		"v=DKIM1; v=DKIM1; p=AAAA",
		"v=DKIM1; p=*",
		"v=DKIM1; k=bogus; p=AAAA",
		"v=DKIM1; k=ed25519; p=AAAA",
	}
	for _, txt := range parseRecordErrors {
		if _, _, err := ParseRecord(txt); err == nil {
			t.Fatalf("expected ParseRecord() error for %q", txt)
		}
	}

	if _, err := parsePublicKey("rsa", []byte("bad")); err == nil {
		t.Fatal("expected parsePublicKey(rsa) error")
	}

	if _, err := parsePublicKey("bogus", []byte("bad")); err == nil {
		t.Fatal("expected parsePublicKey(bogus) error")
	}
}

func TestRecordBranchCoverage(t *testing.T) {
	rsaKey := getRSAKey(t)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if _, err := (&Record{Version: "DKIM1", PublicKey: &ecdsaKey.PublicKey}).ToTXT(); err == nil {
		t.Fatal("expected ToTXT() marshal error")
	}

	pubkey, err := marshalPublicKey(rsaKey.Public())
	if err != nil {
		t.Fatalf("marshalPublicKey() error = %v", err)
	}
	base64Key := base64.StdEncoding.EncodeToString(pubkey)
	whitespaceKey := base64Key[:16] + " \n\t" + base64Key[16:]
	record, isDKIM, err := ParseRecord("x=1;; x=2; v=DKIM1; h=sha256::sha1; s=email::; t=y::s; p=" + whitespaceKey)
	if err != nil || !isDKIM {
		t.Fatalf("ParseRecord() = (%v, %v, %v), want valid DKIM record", record, isDKIM, err)
	}
	if len(record.Hashes) != 2 || len(record.Services) != 1 || len(record.Flags) != 2 {
		t.Fatalf("unexpected parsed record = %+v", record)
	}

	if _, isDKIM, err := ParseRecord("v=DKIM2; p="); err == nil || isDKIM {
		t.Fatalf("ParseRecord(v=DKIM2) = (%v, %v), want non-DKIM error", err, isDKIM)
	}

	ecdsaPKIX, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	if _, err := parsePublicKey("", ecdsaPKIX); err == nil || !strings.Contains(err.Error(), "expected RSA public key") {
		t.Fatalf("parsePublicKey(empty) error = %v", err)
	}
}

func TestSigningCoverage(t *testing.T) {
	rsaKey := getRSAKey(t)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	message := testMessageBytes()

	if _, err := (&Signer{Domain: "example.com", Selector: "sel", PrivateKey: ecdsaKey}).Sign(message); !errors.Is(err, ErrSigAlgorithmUnknown) {
		t.Fatalf("Sign() error = %v, want %v", err, ErrSigAlgorithmUnknown)
	}

	if _, err := SignMultiple(message, []Signer{{Domain: "example.com", Selector: "sel", PrivateKey: rsaKey, Hash: "sha999"}}); !errors.Is(err, ErrHashAlgorithmUnknown) {
		t.Fatalf("SignMultiple() error = %v, want %v", err, ErrHashAlgorithmUnknown)
	}

	if _, err := (&Signer{Domain: "example.com", Selector: "sel", PrivateKey: rsaKey, Hash: "sha999"}).signWithCachedBodyHash([]headerData{{key: "From", lkey: "from", raw: []byte("From: sender@example.com\r\n")}}, []byte("body"), map[bodyHashKey][]byte{}); !errors.Is(err, ErrHashAlgorithmUnknown) {
		t.Fatalf("signWithCachedBodyHash() error = %v, want %v", err, ErrHashAlgorithmUnknown)
	}
}

func TestSignerBranchCoverage(t *testing.T) {
	rsaKey := getRSAKey(t)
	message := testMessageBytes()

	originalNow := timeNow
	timeNow = func() time.Time { return time.Unix(100, 0) }
	defer func() { timeNow = originalNow }()

	defaultHeaderSig, err := (&Signer{Domain: "example.com", Selector: "default", PrivateKey: rsaKey}).Sign(message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	parsedDefault, _, err := ParseSignature(strings.TrimSuffix(defaultHeaderSig, "\r\n"))
	if err != nil {
		t.Fatalf("ParseSignature() error = %v", err)
	}
	if len(parsedDefault.SignedHeaders) == 0 || parsedDefault.Canonicalization != "relaxed/relaxed" {
		t.Fatalf("unexpected default signature = %+v", parsedDefault)
	}

	customSigner := &Signer{
		Domain:     "example.com",
		Selector:   "custom",
		PrivateKey: rsaKey,
		Headers:    []string{"Subject"},
		Identity:   "user@example.com",
		Expiration: 2 * time.Hour,
	}
	customSig, err := customSigner.Sign(message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	parsedCustom, _, err := ParseSignature(strings.TrimSuffix(customSig, "\r\n"))
	if err != nil {
		t.Fatalf("ParseSignature() error = %v", err)
	}
	if parsedCustom.Identity != "user@example.com" || parsedCustom.ExpireTime != 7300 {
		t.Fatalf("unexpected parsed custom signature = %+v", parsedCustom)
	}
	if len(parsedCustom.SignedHeaders) == 0 || !strings.EqualFold(parsedCustom.SignedHeaders[0], "From") {
		t.Fatalf("expected prepended From header, got %+v", parsedCustom.SignedHeaders)
	}

	badRSAKey := *rsaKey
	badRSAKey.PublicKey.N = nil
	badSigner := *customSigner
	badSigner.PrivateKey = &badRSAKey
	if _, err := badSigner.Sign(message); err == nil || !strings.Contains(err.Error(), "signing") {
		t.Fatalf("Sign() error = %v, want signing failure", err)
	}

	if _, err := SignMultiple([]byte("broken message"), []Signer{{Domain: "example.com", Selector: "bad", PrivateKey: rsaKey}}); err == nil || !strings.Contains(err.Error(), "parsing message headers") {
		t.Fatalf("SignMultiple() error = %v, want parse failure", err)
	}

	headers, bodyOffset, err := parseMessageHeaders(message)
	if err != nil {
		t.Fatalf("parseMessageHeaders() error = %v", err)
	}
	body := message[bodyOffset:]

	directDefaultSigner := &Signer{Domain: "example.com", Selector: "cached-default", PrivateKey: rsaKey}
	directDefaultSig, err := directDefaultSigner.signWithCachedBodyHash(headers, body, map[bodyHashKey][]byte{})
	if err != nil {
		t.Fatalf("signWithCachedBodyHash() error = %v", err)
	}
	parsedDirectDefault, _, err := ParseSignature(strings.TrimSuffix(directDefaultSig, "\r\n"))
	if err != nil {
		t.Fatalf("ParseSignature() error = %v", err)
	}
	if len(parsedDirectDefault.SignedHeaders) == 0 {
		t.Fatal("expected signed headers in cached default signature")
	}

	directCustomSigner := &Signer{Domain: "example.com", Selector: "cached-custom", PrivateKey: rsaKey, Headers: []string{"Subject"}, Identity: "user@example.com", Expiration: time.Hour}
	directCustomSig, err := directCustomSigner.signWithCachedBodyHash(headers, body, map[bodyHashKey][]byte{})
	if err != nil {
		t.Fatalf("signWithCachedBodyHash() error = %v", err)
	}
	parsedDirectCustom, _, err := ParseSignature(strings.TrimSuffix(directCustomSig, "\r\n"))
	if err != nil {
		t.Fatalf("ParseSignature() error = %v", err)
	}
	if parsedDirectCustom.Identity != "user@example.com" || len(parsedDirectCustom.SignedHeaders) == 0 || !strings.EqualFold(parsedDirectCustom.SignedHeaders[0], "From") {
		t.Fatalf("unexpected cached custom signature = %+v", parsedDirectCustom)
	}

	badHeaders := []headerData{{key: "Subject", lkey: "subject", raw: []byte("Subject invalid\r\n")}}
	if _, err := directCustomSigner.signWithCachedBodyHash(badHeaders, body, map[bodyHashKey][]byte{}); err == nil || !strings.Contains(err.Error(), "computing data hash") {
		t.Fatalf("signWithCachedBodyHash() error = %v, want data hash failure", err)
	}

	badDirectRSAKey := *rsaKey
	badDirectRSAKey.PublicKey.N = nil
	badDirectSigner := *directCustomSigner
	badDirectSigner.PrivateKey = &badDirectRSAKey
	if _, err := badDirectSigner.signWithCachedBodyHash(headers, body, map[bodyHashKey][]byte{}); err == nil || !strings.Contains(err.Error(), "signing") {
		t.Fatalf("signWithCachedBodyHash() error = %v, want signing failure", err)
	}
}

func TestVerifierCoverage(t *testing.T) {
	rsaKey := getRSAKey(t)
	ed25519Key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	message := testMessageBytes()

	signer := &Signer{
		Domain:                 "example.com",
		Selector:               "sel",
		PrivateKey:             ed25519Key,
		Headers:                []string{"From", "To", "Subject", "Date", "Message-ID"},
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
	}

	signedMessage, headers, bodyOffset, sig, verifySig := signAndParseMessage(t, signer, message)
	record := &Record{Version: "DKIM1", Key: "ed25519", PublicKey: ed25519Key.Public()}

	resolver := ravendns.MockResolver{
		TXT: map[string][]string{
			"sel._domainkey.example.com.": {makeRecord(t, "ed25519", ed25519Key.Public())},
		},
	}

	results, err := Verify(context.Background(), resolver, signedMessage)
	if err != nil || len(results) != 1 || results[0].Status != StatusPass {
		t.Fatalf("Verify() = (%v, %v), want pass", results, err)
	}

	results, err = VerifyReader(context.Background(), resolver, bytes.NewReader(signedMessage))
	if err != nil || len(results) != 1 || results[0].Status != StatusPass {
		t.Fatalf("VerifyReader() = (%v, %v), want pass", results, err)
	}

	verifier := &Verifier{Resolver: resolver}
	if _, err := verifier.VerifyReader(context.Background(), bytes.NewReader([]byte(" broken\r\n\r\n"))); !errors.Is(err, ErrHeaderMalformed) {
		t.Fatalf("VerifyReader() error = %v, want %v", err, ErrHeaderMalformed)
	}

	checkParamCases := []struct {
		name string
		sig  *Signature
		want error
	}{
		{name: "from required", sig: &Signature{Algorithm: "rsa-sha256", Domain: "example.com", SignedHeaders: []string{"to"}, ExpireTime: -1}, want: ErrFromRequired},
		{name: "expired", sig: &Signature{Algorithm: "rsa-sha256", Domain: "example.com", SignedHeaders: []string{"from"}, ExpireTime: 1}, want: ErrSigExpired},
		{name: "tld", sig: &Signature{Algorithm: "rsa-sha256", Domain: "com", SignedHeaders: []string{"from"}, ExpireTime: -1}, want: ErrTLD},
		{name: "unknown hash", sig: &Signature{Algorithm: "rsa-sha999", Domain: "example.com", SignedHeaders: []string{"from"}, ExpireTime: -1}, want: ErrHashAlgorithmUnknown},
		{name: "bad canon", sig: &Signature{Algorithm: "rsa-sha256", Domain: "example.com", SignedHeaders: []string{"from"}, Canonicalization: "bogus/simple", ExpireTime: -1}, want: ErrCanonicalizationUnknown},
		{name: "bad query", sig: &Signature{Algorithm: "rsa-sha256", Domain: "example.com", SignedHeaders: []string{"from"}, Canonicalization: "simple/simple", QueryMethods: []string{"https"}, ExpireTime: -1}, want: ErrQueryMethod},
	}
	originalNow := timeNow
	timeNow = func() time.Time { return time.Unix(10, 0) }
	defer func() { timeNow = originalNow }()
	for _, tc := range checkParamCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := verifier.checkSignatureParams(tc.sig); !errors.Is(err, tc.want) {
				t.Fatalf("checkSignatureParams() error = %v, want %v", err, tc.want)
			}
		})
	}

	verifyRecordCases := []struct {
		name    string
		record  *Record
		sig     *Signature
		status  Status
		want    error
		headers []headerData
		msg     io.ReaderAt
	}{
		{name: "revoked", record: &Record{PublicKey: nil}, sig: &Signature{Algorithm: "ed25519-sha256", Length: -1}, status: StatusPermerror, want: ErrKeyRevoked, headers: headers, msg: bytes.NewReader(signedMessage)},
		{name: "hash not allowed", record: &Record{PublicKey: ed25519Key.Public(), Hashes: []string{"sha1"}, Key: "ed25519", Services: []string{"email"}}, sig: sig, status: StatusPermerror, want: ErrHashAlgNotAllowed, headers: headers, msg: bytes.NewReader(signedMessage)},
		{name: "algorithm mismatch", record: &Record{PublicKey: rsaKey.Public(), Key: "rsa", Services: []string{"email"}}, sig: sig, status: StatusPermerror, want: ErrSigAlgMismatch, headers: headers, msg: bytes.NewReader(signedMessage)},
		{name: "service not email", record: &Record{PublicKey: ed25519Key.Public(), Key: "ed25519", Services: []string{"calendar"}}, sig: sig, status: StatusPermerror, want: ErrKeyNotForEmail, headers: headers, msg: bytes.NewReader(signedMessage)},
		{name: "strict alignment", record: &Record{PublicKey: ed25519Key.Public(), Key: "ed25519", Services: []string{"email"}, Flags: []string{"s"}}, sig: &Signature{Algorithm: "ed25519-sha256", Identity: "user@sub.example.com", Domain: "example.com", Length: -1}, status: StatusPermerror, want: ErrDomainIdentityMismatch, headers: headers, msg: bytes.NewReader(signedMessage)},
		{name: "body length mismatch", record: &Record{PublicKey: ed25519Key.Public(), Key: "ed25519", Services: []string{"email"}}, sig: &Signature{Algorithm: sig.Algorithm, SignedHeaders: sig.SignedHeaders, Signature: sig.Signature, BodyHash: sig.BodyHash, Length: 0}, status: StatusFail, want: ErrBodyHashMismatch, headers: headers, msg: bytes.NewReader(signedMessage)},
		{name: "data hash error", record: &Record{PublicKey: ed25519Key.Public(), Key: "ed25519", Services: []string{"email"}}, sig: &Signature{Algorithm: "ed25519-sha256", SignedHeaders: []string{"subject"}, Signature: sig.Signature, BodyHash: sig.BodyHash, Length: -1}, status: StatusPermerror, want: ErrHeaderMalformed, headers: []headerData{{key: "Subject", lkey: "subject", raw: []byte("Subject invalid\r\n")}}, msg: bytes.NewReader(signedMessage)},
	}
	for _, tc := range verifyRecordCases {
		t.Run(tc.name, func(t *testing.T) {
			status, err := verifier.verifyWithRecord(tc.record, tc.sig, crypto.SHA256, CanonRelaxed, CanonRelaxed, tc.headers, verifySig, tc.msg, bodyOffset)
			if status != tc.status {
				t.Fatalf("verifyWithRecord() status = %q, want %q", status, tc.status)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("verifyWithRecord() error = %v, want %v", err, tc.want)
			}
		})
	}

	status, err := verifier.verifyWithRecord(record, sig, crypto.SHA256, sig.HeaderCanon(), sig.BodyCanon(), headers, verifySig, failingReaderAt{err: errors.New("boom")}, bodyOffset)
	if status != StatusTemperror || err == nil || !strings.Contains(err.Error(), "computing body hash") {
		t.Fatalf("verifyWithRecord() body-read failure = (%q, %v), want temperror with body hash error", status, err)
	}

	testingRecord := &Record{Version: "DKIM1", Key: "ed25519", PublicKey: ed25519Key.Public(), Flags: []string{"y"}}
	testingRecordTXT, err := testingRecord.ToTXT()
	if err != nil {
		t.Fatalf("ToTXT() error = %v", err)
	}
	testModeResolver := ravendns.MockResolver{TXT: map[string][]string{"sel._domainkey.example.com.": {testingRecordTXT}}}
	testModeVerifier := &Verifier{Resolver: testModeResolver}
	tampered := append([]byte(nil), signedMessage...)
	tampered[len(tampered)-3] = 'X'
	results, err = testModeVerifier.Verify(context.Background(), tampered)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(results) != 1 || results[0].Status != StatusNone || results[0].Err != nil {
		t.Fatalf("testing-mode verify = %+v, want status none with nil error", results)
	}

	if IsTemporaryError(nil) {
		t.Fatal("IsTemporaryError(nil) = true, want false")
	}
	if !IsTemporaryError(ravendns.ErrDNSServFail) {
		t.Fatal("IsTemporaryError(ErrDNSServFail) = false, want true")
	}
	if !IsTemporaryError(fmt.Errorf("wrapped: %w: %w", ErrDNS, ravendns.ErrDNSServFail)) {
		t.Fatal("expected wrapped ErrDNS temporary error")
	}
	if !IsTemporaryError(fmt.Errorf("wrapped: %w", ErrMultipleRecords)) {
		t.Fatal("expected multiple-records temporary error")
	}
	if IsTemporaryError(errors.New("permanent")) {
		t.Fatal("unexpected temporary classification for generic error")
	}
}

func TestVerifyLengthLimitedSignature(t *testing.T) {
	ed25519Key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	message := testMessageBytes()
	signer := &Signer{
		Domain:                 "example.com",
		Selector:               "sel",
		PrivateKey:             ed25519Key,
		Headers:                []string{"From", "To", "Subject", "Date", "Message-ID"},
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
	}

	_, bodyOffset, err := parseMessageHeaders(message)
	if err != nil {
		t.Fatalf("parseMessageHeaders() error = %v", err)
	}
	canonicalBody, err := canonicalizeBody(CanonRelaxed, bytes.NewReader(message[bodyOffset:]))
	if err != nil {
		t.Fatalf("canonicalizeBody() error = %v", err)
	}

	signedMessage := signMessageWithLength(t, signer, message, int64(len(canonicalBody)))
	mutatedMessage := append(append([]byte(nil), signedMessage...), []byte("Appended footer.\r\n")...)

	resolver := ravendns.MockResolver{
		TXT: map[string][]string{
			"sel._domainkey.example.com.": {makeRecord(t, "ed25519", ed25519Key.Public())},
		},
	}

	results, err := Verify(context.Background(), resolver, mutatedMessage)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(results) != 1 || results[0].Status != StatusPass {
		t.Fatalf("Verify() = %+v, want pass", results)
	}
}

func TestSignatureBranchCoverage(t *testing.T) {
	bodyHash := bytes.Repeat([]byte{1}, 32)
	if (&Signature{ExpireTime: -1}).IsExpired() {
		t.Fatal("expected negative expiration to be treated as non-expired")
	}

	header, err := (&Signature{
		Version:       1,
		Algorithm:     "rsa-sha256",
		Domain:        "example.com",
		Selector:      "sel",
		BodyHash:      bodyHash,
		Signature:     []byte("sig"),
		CopiedHeaders: []string{"bare copied header"},
	}).Header(true)
	if err != nil {
		t.Fatalf("Header() error = %v", err)
	}
	if !strings.Contains(header, "z=") {
		t.Fatalf("Header() = %q, want z= tag", header)
	}

	withEmptyParts := "DKIM-Signature: v=1;; a=rsa-sha256; b=dGVzdA==; x=20; d=example.com; s=sel; h=from; bh=" + base64.StdEncoding.EncodeToString(bodyHash)
	parsed, verifySig, err := ParseSignature(withEmptyParts)
	if err != nil {
		t.Fatalf("ParseSignature() error = %v", err)
	}
	if parsed.ExpireTime != 20 || strings.Contains(string(verifySig), "b=dGVzdA==") {
		t.Fatalf("unexpected parsed signature = %+v verifySig=%q", parsed, string(verifySig))
	}

	if _, _, err := ParseSignature("DKIM-Signature: v=1; a=rsa-sha1; d=example.com; s=sel; h=from; bh=" + base64.StdEncoding.EncodeToString(bodyHash) + "; b=dGVzdA=="); err == nil || !strings.Contains(err.Error(), "expected 20 for sha1") {
		t.Fatalf("ParseSignature() error = %v, want sha1 body-hash length failure", err)
	}

	if got := hexVal('a'); got != 10 {
		t.Fatalf("hexVal('a') = %d, want 10", got)
	}
	if got := hexVal('G'); got != -1 {
		t.Fatalf("hexVal('G') = %d, want -1", got)
	}
}

func TestVerifierBranchCoverage(t *testing.T) {
	ed25519Key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	message := testMessageBytes()
	signer := &Signer{
		Domain:                 "example.com",
		Selector:               "sel",
		PrivateKey:             ed25519Key,
		Headers:                []string{"From", "To", "Subject", "Date", "Message-ID"},
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
	}

	signedMessage, headers, bodyOffset, sig, verifySig := signAndParseMessage(t, signer, message)
	resolver := ravendns.MockResolver{TXT: map[string][]string{"sel._domainkey.example.com.": {makeRecord(t, "ed25519", ed25519Key.Public())}}}

	policyVerifier := &Verifier{Resolver: resolver, Policy: func(*Signature) error { return errors.New("rejected") }}
	results, err := policyVerifier.Verify(context.Background(), signedMessage)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(results) != 1 || results[0].Status != StatusPolicy || !errors.Is(results[0].Err, ErrPolicy) {
		t.Fatalf("Verify() = %+v, want policy rejection", results)
	}

	verifier := &Verifier{Resolver: resolver}
	if _, _, _, err := verifier.checkSignatureParams(&Signature{Algorithm: "rsa-sha256", Domain: "example.com", SignedHeaders: []string{"from"}, Canonicalization: "simple/bogus", ExpireTime: -1}); !errors.Is(err, ErrCanonicalizationUnknown) {
		t.Fatalf("checkSignatureParams() error = %v, want %v", err, ErrCanonicalizationUnknown)
	}

	record := &Record{Version: "DKIM1", Key: "ed25519", PublicKey: ed25519Key.Public(), Services: []string{"email"}}
	canonicalBody, err := canonicalizeBody(CanonRelaxed, bytes.NewReader(signedMessage[bodyOffset:]))
	if err != nil {
		t.Fatalf("canonicalizeBody() error = %v", err)
	}
	tooLongSig := *sig
	tooLongSig.Length = int64(len(canonicalBody) + 1)
	status, err := verifier.verifyWithRecord(record, &tooLongSig, crypto.SHA256, CanonRelaxed, CanonRelaxed, headers, verifySig, bytes.NewReader(signedMessage), bodyOffset)
	if status != StatusPermerror || !errors.Is(err, ErrBodyHashLength) {
		t.Fatalf("verifyWithRecord() = (%q, %v), want permerror %v", status, err, ErrBodyHashLength)
	}

	if !IsTemporaryError(ErrDNS) {
		t.Fatal("expected ErrDNS to be treated as temporary")
	}
}

func TestMailConvenienceCoverage(t *testing.T) {
	ed25519Key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	mail := testMail()
	signer := &Signer{
		Domain:                 "example.com",
		Selector:               "sel",
		PrivateKey:             ed25519Key,
		Headers:                []string{"From", "To", "Subject", "Date", "Message-ID"},
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
	}

	if err := SignMail(mail, signer); err != nil {
		t.Fatalf("SignMail() error = %v", err)
	}
	if got := mail.Content.Headers[0].Name; got != "DKIM-Signature" {
		t.Fatalf("first header = %q, want DKIM-Signature", got)
	}

	resolver := ravendns.MockResolver{TXT: map[string][]string{"sel._domainkey.example.com.": {makeRecord(t, "ed25519", ed25519Key.Public())}}}
	results, err := VerifyMailContext(context.Background(), mail, resolver)
	if err != nil || len(results) != 1 || results[0].Status != StatusPass {
		t.Fatalf("VerifyMailContext() = (%v, %v), want pass", results, err)
	}

	multiMail := testMail()
	if err := SignMailMultiple(multiMail, []Signer{*signer, *signer}); err != nil {
		t.Fatalf("SignMailMultiple() error = %v", err)
	}
	count := 0
	for _, h := range multiMail.Content.Headers {
		if h.Name == "DKIM-Signature" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("DKIM-Signature count = %d, want 2", count)
	}

	quickMail := testMail()
	if err := QuickSign(quickMail, "example.com", "sel", ed25519Key); err != nil {
		t.Fatalf("QuickSign() error = %v", err)
	}
	parsed, _, err := ParseSignature("DKIM-Signature: " + quickMail.Content.Headers[0].Value)
	if err != nil {
		t.Fatalf("ParseSignature() error = %v", err)
	}
	if parsed.Canonicalization != "relaxed/relaxed" {
		t.Fatalf("QuickSign canonicalization = %q, want relaxed/relaxed", parsed.Canonicalization)
	}

	invalidMail := &ravenmail.Mail{Content: ravenmail.Content{Headers: ravenmail.Headers{{Name: "To", Value: "recipient@example.org"}}, Body: []byte("body")}}
	if err := SignMail(invalidMail, signer); !errors.Is(err, ErrFromRequired) {
		t.Fatalf("SignMail() error = %v, want %v", err, ErrFromRequired)
	}
	if err := SignMailMultiple(invalidMail, []Signer{*signer}); !errors.Is(err, ErrFromRequired) {
		t.Fatalf("SignMailMultiple() error = %v, want %v", err, ErrFromRequired)
	}
	if err := QuickSign(invalidMail, "example.com", "sel", ed25519Key); !errors.Is(err, ErrFromRequired) {
		t.Fatalf("QuickSign() error = %v, want %v", err, ErrFromRequired)
	}

	badVerifyMail := &ravenmail.Mail{Content: ravenmail.Content{Headers: ravenmail.Headers{{Name: " Bad", Value: "value"}}, Body: []byte("body")}}
	if _, err := VerifyMailContext(context.Background(), badVerifyMail, resolver); !errors.Is(err, ErrHeaderMalformed) {
		t.Fatalf("VerifyMailContext() error = %v, want %v", err, ErrHeaderMalformed)
	}
}
