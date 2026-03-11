package arc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	ravenmail "github.com/synqronlabs/raven/mail"
)

const (
	benchARCAuthenticationResults = "i=2; mx.example.com; dkim=pass header.d=example.com; spf=pass smtp.mailfrom=sender@example.com"
	benchARCMessageSignature      = "i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; h=From:To:Subject:Date:Message-ID; bh=YWJj; b=c2ln"
	benchARCSeal                  = "i=1; a=rsa-sha256; cv=none; d=example.com; s=selector; b=c2ln"
)

func benchmarkARCKeyAndRecord(b *testing.B) (*rsa.PrivateKey, string) {
	b.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey: %v", err)
	}
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		b.Fatalf("x509.MarshalPKIXPublicKey: %v", err)
	}
	record := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pubkeyBytes)
	return key, record
}

func benchmarkARCMail(b *testing.B) *ravenmail.Mail {
	b.Helper()
	mail, err := ravenmail.NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.org").
		Subject("ARC Benchmark Message").
		Date(time.Unix(1734607200, 0)).
		MessageID("arc-bench@example.com").
		TextBody("This is the body of the ARC benchmark message.").
		Build()
	if err != nil {
		b.Fatalf("Build: %v", err)
	}
	return mail
}

func cloneBenchmarkARCMail(src *ravenmail.Mail) *ravenmail.Mail {
	cloned := *src
	cloned.Envelope = src.Envelope
	cloned.Envelope.To = append([]ravenmail.Recipient(nil), src.Envelope.To...)
	if src.Envelope.ExtensionParams != nil {
		cloned.Envelope.ExtensionParams = make(map[string]string, len(src.Envelope.ExtensionParams))
		for key, value := range src.Envelope.ExtensionParams {
			cloned.Envelope.ExtensionParams[key] = value
		}
	}
	cloned.Content = src.Content
	cloned.Content.Headers = append(ravenmail.Headers(nil), src.Content.Headers...)
	cloned.Content.Body = append([]byte(nil), src.Content.Body...)
	cloned.Trace = append([]ravenmail.TraceField(nil), src.Trace...)
	return &cloned
}

func benchmarkARCSealedMessage(b *testing.B) ([]byte, *Verifier) {
	b.Helper()
	privateKey, dkimRecord := benchmarkARCKeyAndRecord(b)
	resolver := &mockResolver{
		txtRecords: map[string][]string{
			"arc._domainkey.example.com": {dkimRecord},
		},
	}
	sealer := &Sealer{
		Domain:                 "example.com",
		Selector:               "arc",
		PrivateKey:             privateKey,
		Headers:                []string{"From", "To", "Subject", "Date", "Message-ID"},
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
		Clock:                  func() time.Time { return time.Unix(1734607200, 0) },
	}
	message := testRawMessage()
	result, err := sealer.Seal(message, "example.com", "spf=pass; dkim=pass", ChainValidationNone)
	if err != nil {
		b.Fatalf("Seal: %v", err)
	}
	sealedMessage := []byte(result.Seal + "\r\n" + result.MessageSignature + "\r\n" + result.AuthenticationResults + "\r\n" + string(message))
	verifier := &Verifier{
		Resolver:      resolver,
		MinRSAKeyBits: 1024,
		Clock:         func() time.Time { return time.Unix(1734607200, 0) },
	}
	return sealedMessage, verifier
}

func BenchmarkParseAuthenticationResults(b *testing.B) {
	for b.Loop() {
		aar, err := ParseAuthenticationResults(benchARCAuthenticationResults)
		if err != nil {
			b.Fatalf("ParseAuthenticationResults: %v", err)
		}
		if aar.Instance != 2 {
			b.Fatalf("Instance = %d, want 2", aar.Instance)
		}
	}
}

func BenchmarkParseMessageSignature(b *testing.B) {
	for b.Loop() {
		ms, _, err := ParseMessageSignature(benchARCMessageSignature)
		if err != nil {
			b.Fatalf("ParseMessageSignature: %v", err)
		}
		if ms.Instance != 1 {
			b.Fatalf("Instance = %d, want 1", ms.Instance)
		}
	}
}

func BenchmarkParseSeal(b *testing.B) {
	for b.Loop() {
		seal, _, err := ParseSeal(benchARCSeal)
		if err != nil {
			b.Fatalf("ParseSeal: %v", err)
		}
		if seal.Instance != 1 {
			b.Fatalf("Instance = %d, want 1", seal.Instance)
		}
	}
}

func BenchmarkExtractARCSets(b *testing.B) {
	sealedMessage, _ := benchmarkARCSealedMessage(b)
	headers, _, err := parseHeaders(bufio.NewReader(bytes.NewReader(sealedMessage)))
	if err != nil {
		b.Fatalf("parseHeaders: %v", err)
	}

	b.ResetTimer()
	for b.Loop() {
		sets, err := extractARCSets(headers)
		if err != nil {
			b.Fatalf("extractARCSets: %v", err)
		}
		if len(sets) != 1 {
			b.Fatalf("len(sets) = %d, want 1", len(sets))
		}
	}
}

func BenchmarkSignMail(b *testing.B) {
	privateKey, _ := benchmarkARCKeyAndRecord(b)
	baseMail := benchmarkARCMail(b)
	sealer := &Sealer{
		Domain:                 "example.com",
		Selector:               "arc",
		PrivateKey:             privateKey,
		Headers:                DefaultSignedHeaders,
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
		Clock:                  func() time.Time { return time.Unix(1734607200, 0) },
	}

	b.ResetTimer()
	for b.Loop() {
		mail := cloneBenchmarkARCMail(baseMail)
		if err := SignMail(mail, sealer, "example.com", "spf=pass; dkim=pass", ChainValidationNone); err != nil {
			b.Fatalf("SignMail: %v", err)
		}
		if mail.Content.Headers.Get("ARC-Seal") == "" {
			b.Fatal("ARC-Seal header missing")
		}
	}
}

func BenchmarkVerifyMailContext(b *testing.B) {
	privateKey, dkimRecord := benchmarkARCKeyAndRecord(b)
	resolver := &mockResolver{
		txtRecords: map[string][]string{
			"arc._domainkey.example.com": {dkimRecord},
		},
	}
	mail := benchmarkARCMail(b)
	sealer := &Sealer{
		Domain:                 "example.com",
		Selector:               "arc",
		PrivateKey:             privateKey,
		Headers:                DefaultSignedHeaders,
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
		Clock:                  func() time.Time { return time.Unix(1734607200, 0) },
	}
	if err := SignMail(mail, sealer, "example.com", "spf=pass; dkim=pass", ChainValidationNone); err != nil {
		b.Fatalf("SignMail setup: %v", err)
	}
	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		result, err := VerifyMailContext(ctx, mail, resolver)
		if err != nil {
			b.Fatalf("VerifyMailContext: %v", err)
		}
		if result.Status != StatusPass {
			b.Fatalf("Status = %s, want %s", result.Status, StatusPass)
		}
	}
}
