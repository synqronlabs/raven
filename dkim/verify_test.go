package dkim

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	ravendns "github.com/synqronlabs/raven/dns"
)

func parseRSAKey(t *testing.T, rsaText string) *rsa.PrivateKey {
	rsab, _ := pem.Decode([]byte(rsaText))
	if rsab == nil {
		t.Fatalf("no pem in privKey")
	}

	key, err := x509.ParsePKCS8PrivateKey(rsab.Bytes)
	if err != nil {
		t.Fatalf("parsing private key: %s", err)
	}
	return key.(*rsa.PrivateKey)
}

func getRSAKey(t *testing.T) *rsa.PrivateKey {
	// Generated with:
	// openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt
	const rsaText = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDs8y3nEOKF/ara
guC48NMcWa7a0rzSl5dwuKNkGxRgd5fdcc9b+RgccSjBYCjKg36TE9pLggfNQH2E
60KU8sbhHOv2dHRW8gOP3dWdzT5thP7C3qiWa5TTolQ6sUqnQE9YANmvxJjTo3qs
s9novP9OJrZVceHpB1MJPXu7S257znLm5LksqPan+lwCAG4uMRrZVZ70XHn1/60S
59KYdbDL0FxB3CHiQ+t8nf/VGb7FF17tDxdPxHlRjiHyBQQmBmLLG38W6S7XAKc4
TrO4Bs3c3WScujlW5KeU2qn3Ua3v8xuT2H5YeXBlq8UOT8D//7oGC2yyrS/RfMGL
cFXgYmgbAgMBAAECggEAAbgb96a4Ngeqoy466iyZI4YFDkJkK1T9PMyiJtpJcg+8
Ete+DOlIQwCRLqH/ecSteOy2c0DMxLD4mCvKzmDaj4yRq7aZl33nB7aw05XHI61I
2eoaqAi8yjJN0SUzKPZ+/OD4s11GTJbNj444gQdKBOuj/Ae4/2NVt2XyTWAVO6G2
wcR0ZZhPpjoJ/ho8LLzPmcs+2LC9Ye3TlvqkbsY1JijFdIetCEbMhuzj/OtJQFXf
dYq3ijqn/VlODgSngfTmrqtLjEeNszeMapIVL3YeTsm+m+ZLjSGnXHnCJhzjrJUN
wFTmY/7L9XBcwueBtFA5JUPzvymOFpr+m38aIRkl1QKBgQD3U6nsA/JIlPB8HE7L
/knxNeT8HHXSTeHGggNzjbTWQhdjLwl5LhoXqOyDgGaUfwxB+wiXzL6pHujgU9YQ
3YY3kEeu75blNNshJ1X4uIVzYaQ9kRiAHajmfSzIaoLGzgBpSENSGy7csPDxqu2g
LKD8njnUgEBjmohiZfjRP68D7wKBgQD1QlvSyQn/WXcMPMn7CODKBPg7gkCGdJbB
yqSe4pGEd/+1WDQShWpFCQmOvP+GAIaDSJwftYZeU93Wk02fxkL85CkHkQ8ARJqM
u16doe7E3KRYf7RS+IRwiPGmZcFJ8NUs1qw0GjIa+1qd8ejvH1IcKqjwsu99QWiM
Gx/2qBbClQKBgQCIw6ri6AvCNxoEh2LLSwJ4b+T/xH0ing6LRrnB3EpzcHieUBRc
/jFPhAnFbetLkjWlBrvptT55Jq5/3dwx102wzAfXpIU8mc3St33C28Zv1z6LDQEP
V1denTl2We+XH7L6hQs1C/MN9opGGM7uE7+x8YzpBUKV0Y45W0oL67tL4QKBgQDQ
hWLci+DcIYx98xEnRh0YpbEHp26E4otqqIfeLnPaVMwruppLRPNdTpm5qib2H2w+
InXa39MmT9fEn+jXdxFtQe9AZ6yBZdKg5I1FKHCBH7b7J1iBUpoHs+cAunLkEsas
ILi4c602E46vywVoiRCesgaA3yGPNRVWSZmbdL4lIQKBgDQMizClITHX3VHZU5PW
rr3TRrdSLchWEUKz8Hzq1WmW89/kRfjp8mcB82/+7jJWD1XkrS2Kg5fNKFrITkGT
cU5sVDko+/cjEyjY1GpgSHfao09HzWvfYjQcMmbSoPuoxXkq4IxXGqI1YrD8ioGw
RbGU0RxrarX5hPy2/HX5P5VQ
-----END PRIVATE KEY-----`
	return parseRSAKey(t, rsaText)
}

func getWeakRSAKey(t *testing.T) *rsa.PrivateKey {
	// Generated with: openssl genrsa 512 | openssl pkcs8 -topk8 -nocrypt
	const rsaText = `-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAvuFh9FF5ZsNJXz28
7vLfEIzSpy3N0VEgOYQyiB9ODpqq5QjMw6ZgSbP5blpHSwHKC/5YnhZS4m/sDJwN
zt/xWQIDAQABAkEAnetBayxs0AQJE+6z/Myal8qqDP3sJZyEmJEybUPZBGKqavWH
vvnE74+blcz5oDAb+jxEjopkqqG2drdVIbQ6AQIhAPI4wnbKy48DgjdvYx2IgLqJ
tWXMEPfFDoFpPruS6ecxAiEAybz9NxwlRD76Mvv/a0UXwFi3NfdADrJ0nlPAYQ4K
8qkCIGWESmRVLCk9NDcdlPHMwv7rNj5632WojiLIxEUDFssRAiB1ig9elJ+B68+K
9RgUP+VexFG6t5wy8/bOaK2l3rCyQQIhALBolahjUQc1BdiNYzmXKD8oXlw2a49s
5pUY52bn0IYB
-----END PRIVATE KEY-----`
	return parseRSAKey(t, rsaText)
}

// makeRecord creates a DKIM DNS TXT record for testing.
func makeRecord(t *testing.T, keyType string, publicKey any) string {
	tr := &Record{
		Version:   "DKIM1",
		Key:       keyType,
		PublicKey: publicKey,
		Flags:     []string{"s"},
	}
	txt, err := tr.ToTXT()
	if err != nil {
		t.Fatalf("making dns txt record: %s", err)
	}
	return txt
}

// TestVerifyRSA tests verification of an RSA-signed real-world message.
func TestVerifyRSA(t *testing.T) {
	message := strings.ReplaceAll(`Return-Path: <mechiel@ueber.net>
X-Original-To: mechiel@ueber.net
Delivered-To: mechiel@ueber.net
Received: from [IPV6:2a02:a210:4a3:b80:ca31:30ee:74a7:56e0] (unknown [IPv6:2a02:a210:4a3:b80:ca31:30ee:74a7:56e0])
	by koriander.ueber.net (Postfix) with ESMTPSA id E119EDEB0B
	for <mechiel@ueber.net>; Fri, 10 Dec 2021 20:09:08 +0100 (CET)
DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=ueber.net;
	s=koriander; t=1639163348;
	bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;
	h=Date:To:From:Subject:From;
	b=rpWruWprs2TB7/MnulA2n2WtfUIfrrnAvRoSrip1ruX5ORN4AOYPPMmk/gGBDdc6O
	 grRpSsNzR9BrWcooYfbNfSbl04nPKMp0acsZGfpvkj0+mqk5b8lqZs3vncG1fHlQc7
	 0KXfnAHyEs7bjyKGbrw2XG1p/EDoBjIjUsdpdCAtamMGv3A3irof81oSqvwvi2KQks
	 17aB1YAL9Xzkq9ipo1aWvDf2W6h6qH94YyNocyZSVJ+SlVm3InNaF8APkV85wOm19U
	 9OW81eeuQbvSPcQZJVOmrWzp7XKHaXH0MYE3+hdH/2VtpCnPbh5Zj9SaIgVbaN6NPG
	 Ua0E07rwC86sg==
Message-ID: <427999f6-114f-e59c-631e-ab2a5f6bfe4c@ueber.net>
Date: Fri, 10 Dec 2021 20:09:08 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.4.0
Content-Language: nl
To: mechiel@ueber.net
From: Mechiel Lukkien <mechiel@ueber.net>
Subject: test
Content-Type: text/plain; charset=UTF-8; format=flowed
Content-Transfer-Encoding: 7bit

test
`, "\n", "\r\n")

	resolver := ravendns.MockResolver{
		TXT: map[string][]string{
			"koriander._domainkey.ueber.net.": {"v=DKIM1; k=rsa; s=email; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy3Z9ffZe8gUTJrdGuKj6IwEembmKYpp0jMa8uhudErcI4gFVUaFiiRWxc4jP/XR9NAEv3XwHm+CVcHu+L/n6VWt6g59U7vHXQicMfKGmEp2VplsgojNy/Y5X9HdVYM0azsI47NcJCDW9UVfeOHdOSgFME4F8dNtUKC4KTB2d1pqj/yixz+V8Sv8xkEyPfSRHcNXIw0LvelqJ1MRfN3hO/3uQSVrPYYk4SyV0b6wfnkQs28fpiIpGQvzlGI5WkrdOQT5k4YHaEvZDLNdwiMeVZOEL7dDoFs2mQsovm+tH0StUAZTnr61NLVFfD5V6Ip1V9zVtspPHvYSuOWwyArFZ9QIDAQAB"},
		},
	}

	verifier := &Verifier{Resolver: resolver}
	results, err := verifier.Verify(context.Background(), []byte(message))
	if err != nil {
		t.Fatalf("dkim verify: %v", err)
	}
	if len(results) != 1 || results[0].Status != StatusPass {
		for _, r := range results {
			t.Logf("result: status=%s, err=%v", r.Status, r.Err)
		}
		t.Fatalf("verify: unexpected results")
	}
}

// TestVerifyEd25519 tests verification of Ed25519 signatures (RFC 8463 example).
func TestVerifyEd25519(t *testing.T) {
	// From RFC 8463 Section 4
	message := strings.ReplaceAll(`DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;
 d=football.example.com; i=@football.example.com;
 q=dns/txt; s=brisbane; t=1528637909; h=from : to :
 subject : date : message-id : from : subject : date;
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus
 Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
 d=football.example.com; i=@football.example.com;
 q=dns/txt; s=test; t=1528637909; h=from : to : subject :
 date : message-id : from : subject : date;
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3
 DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz
 dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=
From: Joe SixPack <joe@football.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@football.example.com>

Hi.

We lost the game.  Are you hungry yet?

Joe.

`, "\n", "\r\n")

	resolver := ravendns.MockResolver{
		TXT: map[string][]string{
			"brisbane._domainkey.football.example.com.": {"v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="},
			"test._domainkey.football.example.com.":     {"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB"},
		},
	}

	verifier := &Verifier{Resolver: resolver}
	results, err := verifier.Verify(context.Background(), []byte(message))
	if err != nil {
		t.Fatalf("dkim verify: %v", err)
	}
	if len(results) != 2 || results[0].Status != StatusPass || results[1].Status != StatusPass {
		for _, r := range results {
			t.Logf("result: status=%s, err=%v", r.Status, r.Err)
		}
		t.Fatalf("verify: unexpected results")
	}
}

// TestVerifyComprehensive runs comprehensive verification tests with various error conditions.
func TestVerifyComprehensive(t *testing.T) {
	const message = `From: <mjl@mox.example>
To: <other@mox.example>
Subject: test
Date: Fri, 10 Dec 2021 20:09:08 +0100
Message-ID: <test@mox.example>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8; format=flowed
Content-Transfer-Encoding: 7bit

test
`

	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	var resolver ravendns.MockResolver
	var record *Record
	var recordTxt string
	var msg string
	var signer *Signer
	var signed bool
	var signDomain string

	prepare := func() {
		t.Helper()

		signDomain = "mox.example"

		record = &Record{
			Version:   "DKIM1",
			Key:       "ed25519",
			PublicKey: key.Public(),
			Flags:     []string{"s"},
		}

		txt, err := record.ToTXT()
		if err != nil {
			t.Fatalf("making dns txt record: %s", err)
		}
		recordTxt = txt

		resolver = ravendns.MockResolver{
			TXT: map[string][]string{
				"test._domainkey.mox.example.": {txt},
			},
		}

		signer = &Signer{
			Domain:                 signDomain,
			Selector:               "test",
			PrivateKey:             key,
			Headers:                []string{"From", "To", "Cc", "Bcc", "Reply-To", "References", "In-Reply-To", "Subject", "Date", "Message-ID", "Content-Type"},
			HeaderCanonicalization: CanonSimple,
			BodyCanonicalization:   CanonSimple,
		}

		msg = message
		signed = false
	}

	sign := func() {
		t.Helper()

		msg = strings.ReplaceAll(msg, "\n", "\r\n")

		headers, err := signer.Sign([]byte(msg))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		msg = headers + msg
		signed = true
	}

	test := func(name string, expStatus Status, expResultErr error, mod func()) {
		t.Run(name, func(t *testing.T) {
			prepare()
			mod()
			if !signed {
				sign()
			}

			verifier := &Verifier{Resolver: resolver}
			results, err := verifier.Verify(context.Background(), []byte(msg))
			if err != nil {
				if expResultErr == nil {
					t.Fatalf("got verify error %v, expected nil", err)
				}
				if !errors.Is(err, expResultErr) {
					t.Fatalf("got verify error %v, expected %v", err, expResultErr)
				}
				return
			}

			if expStatus != "" && (len(results) == 0 || results[0].Status != expStatus) {
				var status Status
				if len(results) > 0 {
					status = results[0].Status
				}
				t.Fatalf("got status %q, expected %q", status, expStatus)
			}
			var resultErr error
			if len(results) > 0 {
				resultErr = results[0].Err
			}
			if expResultErr != nil && !errors.Is(resultErr, expResultErr) {
				t.Fatalf("got result error %v, expected %v", resultErr, expResultErr)
			}
		})
	}

	// Basic pass test
	test("basic pass", StatusPass, nil, func() {})

	// No DKIM record in DNS
	test("no record", StatusPermerror, ErrNoRecord, func() {
		resolver.TXT = nil
	})

	// DNS request fails temporarily
	test("dns failure", StatusTemperror, ErrDNS, func() {
		resolver.Fail = []string{"txt test._domainkey.mox.example."}
	})

	// Claims to be DKIM through v=, but cannot be parsed
	test("invalid dkim record syntax", StatusPermerror, ErrSyntax, func() {
		resolver.TXT = map[string][]string{
			"test._domainkey.mox.example.": {"v=DKIM1; bogus"},
		}
	})

	// Not a DKIM record (no v=DKIM1)
	test("not dkim record", StatusPermerror, ErrNoRecord, func() {
		resolver.TXT = map[string][]string{
			"test._domainkey.mox.example.": {"bogus"},
		}
	})

	// Multiple DKIM records
	test("multiple records", StatusTemperror, ErrMultipleRecords, func() {
		resolver.TXT["test._domainkey.mox.example."] = []string{recordTxt, recordTxt}
	})

	// Invalid DKIM-Signature header (missing required tags)
	test("invalid signature header", StatusPermerror, nil, func() {
		msg = strings.ReplaceAll("DKIM-Signature: v=1\r\n"+msg, "\n", "\r\n")
		signed = true
	})

	// "From" not signed
	test("from not signed", StatusPermerror, ErrFromRequired, func() {
		sign()
		// Remove "from" from signed headers (h=)
		msg = strings.ReplaceAll(msg, ":From:", ":")
		msg = strings.ReplaceAll(msg, "=From:", "=")
	})

	// Domain in signature is TLD
	test("tld domain", StatusPermerror, ErrTLD, func() {
		// Sign as .com (a TLD)
		msg = strings.ReplaceAll(msg, "From: <mjl@mox.example>\n", "From: <mjl@com>\n")
		signer.Domain = "com"
		resolver.TXT = map[string][]string{
			"test._domainkey.com.": {recordTxt},
		}
	})

	// Unknown hash algorithm in signature
	test("unknown hash algorithm", StatusPermerror, ErrHashAlgorithmUnknown, func() {
		sign()
		msg = strings.ReplaceAll(msg, "sha256", "sha257")
	})

	// Unknown canonicalization
	test("unknown canonicalization", StatusPermerror, ErrCanonicalizationUnknown, func() {
		signer.HeaderCanonicalization = CanonRelaxed
		signer.BodyCanonicalization = CanonRelaxed
		sign()
		msg = strings.ReplaceAll(msg, "relaxed/relaxed", "bogus/bogus")
	})

	// Query methods without dns/txt
	test("query method", StatusPermerror, ErrQueryMethod, func() {
		sign()
		msg = strings.ReplaceAll(msg, "DKIM-Signature: ", "DKIM-Signature: q=other;")
	})

	// Hash algorithm not allowed by DNS record
	test("hash not allowed", StatusPermerror, ErrHashAlgNotAllowed, func() {
		recordTxt += ";h=sha1"
		resolver.TXT = map[string][]string{
			"test._domainkey.mox.example.": {recordTxt},
		}
	})

	// Signature algorithm mismatch (DNS record has different key type)
	test("algorithm mismatch", StatusPermerror, ErrSigAlgMismatch, func() {
		record.PublicKey = getRSAKey(t).Public()
		record.Key = "rsa"
		txt, err := record.ToTXT()
		if err != nil {
			t.Fatalf("making dns txt record: %s", err)
		}
		resolver.TXT = map[string][]string{
			"test._domainkey.mox.example.": {txt},
		}
	})

	// Empty public key means revoked key
	test("revoked key", StatusPermerror, ErrKeyRevoked, func() {
		record.PublicKey = nil
		record.Pubkey = nil
		txt, err := record.ToTXT()
		if err != nil {
			t.Fatalf("making dns txt record: %s", err)
		}
		resolver.TXT = map[string][]string{
			"test._domainkey.mox.example.": {txt},
		}
	})

	// Weak RSA key (< 1024 bits)
	// Go 1.24+ won't sign with 512-bit keys without GODEBUG=rsa1024min=0
	test("weak_rsa_key", StatusPermerror, ErrWeakKey, func() {
		t.Setenv("GODEBUG", "rsa1024min=0")
		weakKey := getWeakRSAKey(t)
		record.Key = "rsa"
		record.PublicKey = weakKey.Public()
		txt, err := record.ToTXT()
		if err != nil {
			t.Fatalf("making dns txt record: %s", err)
		}
		resolver.TXT = map[string][]string{
			"test._domainkey.mox.example.": {txt},
		}
		signer.PrivateKey = weakKey
	})

	// Key not allowed for email
	test("key not for email", StatusPermerror, ErrKeyNotForEmail, func() {
		recordTxt += ";s=other"
		resolver.TXT = map[string][]string{
			"test._domainkey.mox.example.": {recordTxt},
		}
	})

	// Wrong signature (modified header after signing)
	test("signature verify fail", StatusFail, ErrSigVerify, func() {
		sign()
		msg = strings.ReplaceAll(msg, "Subject: test\r\n", "Subject: modified header\r\n")
	})

	// Body hash mismatch (modified body after signing)
	test("body hash mismatch", StatusFail, ErrBodyHashMismatch, func() {
		sign()
		msg = strings.ReplaceAll(msg, "\r\ntest\r\n", "\r\nmodified body\r\n")
	})
}

// TestSignAndVerifyIntegration tests the full sign-then-verify flow.
func TestSignAndVerifyIntegration(t *testing.T) {
	message := strings.ReplaceAll(`From: mjl@mox.example
To: other@mox.example
Subject: test
Date: Fri, 10 Dec 2021 20:09:08 +0100
Message-ID: <test@mox.example>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8; format=flowed
Content-Transfer-Encoding: 7bit

test
`, "\n", "\r\n")

	rsaKey := getRSAKey(t)
	ed25519Key := ed25519.NewKeyFromSeed(make([]byte, 32))

	testCases := []struct {
		name       string
		signer     *Signer
		recordType string
		publicKey  any
	}{
		{
			name: "RSA-SHA256",
			signer: &Signer{
				Domain:                 "mox.example",
				Selector:               "testrsa",
				PrivateKey:             rsaKey,
				Headers:                []string{"From", "To", "Subject", "Date", "Message-ID"},
				HeaderCanonicalization: CanonSimple,
				BodyCanonicalization:   CanonSimple,
			},
			recordType: "rsa",
			publicKey:  rsaKey.Public(),
		},
		{
			name: "RSA-SHA256-relaxed",
			signer: &Signer{
				Domain:                 "mox.example",
				Selector:               "testrsa2",
				PrivateKey:             rsaKey,
				Headers:                []string{"From", "To", "Subject", "Date", "Message-ID"},
				HeaderCanonicalization: CanonRelaxed,
				BodyCanonicalization:   CanonRelaxed,
			},
			recordType: "rsa",
			publicKey:  rsaKey.Public(),
		},
		{
			name: "Ed25519-SHA256",
			signer: &Signer{
				Domain:                 "mox.example",
				Selector:               "tested25519",
				PrivateKey:             ed25519Key,
				Headers:                []string{"From", "To", "Subject", "Date", "Message-ID"},
				HeaderCanonicalization: CanonSimple,
				BodyCanonicalization:   CanonSimple,
			},
			recordType: "ed25519",
			publicKey:  ed25519Key.Public(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Sign the message
			sigHeader, err := tc.signer.Sign([]byte(message))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}

			// Create mock resolver with the public key
			resolver := ravendns.MockResolver{
				TXT: map[string][]string{
					tc.signer.Selector + "._domainkey.mox.example.": {makeRecord(t, tc.recordType, tc.publicKey)},
				},
			}

			// Verify the signed message
			signedMsg := sigHeader + message
			verifier := &Verifier{Resolver: resolver}
			results, err := verifier.Verify(context.Background(), []byte(signedMsg))
			if err != nil {
				t.Fatalf("verify: %v", err)
			}

			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			if results[0].Status != StatusPass {
				t.Fatalf("expected pass, got %s: %v", results[0].Status, results[0].Err)
			}
		})
	}
}

// TestBodyHashCanonical tests body hash calculation for different canonicalizations.
func TestBodyHashCanonical(t *testing.T) {
	// Test empty body with simple canonicalization
	simpleGot, err := computeBodyHash(crypto.SHA256.New(), CanonSimple, []byte(""))
	if err != nil {
		t.Fatalf("body hash, simple, empty string: %s", err)
	}
	simpleWant := base64Decode("frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=")
	if !bytes.Equal(simpleGot, simpleWant) {
		t.Fatalf("simple body hash for empty string, got %s, expected %s", base64Encode(simpleGot), base64Encode(simpleWant))
	}

	// Test empty body with relaxed canonicalization
	relaxedGot, err := computeBodyHash(crypto.SHA256.New(), CanonRelaxed, []byte(""))
	if err != nil {
		t.Fatalf("body hash, relaxed, empty string: %s", err)
	}
	relaxedWant := base64Decode("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
	if !bytes.Equal(relaxedGot, relaxedWant) {
		t.Fatalf("relaxed body hash for empty string, got %s, expected %s", base64Encode(relaxedGot), base64Encode(relaxedWant))
	}

	// Test RFC 6376 example
	// NOTE: the trailing space in the strings below are part of the test for canonicalization.
	exampleIn := strings.ReplaceAll(` c
d 	 e


`, "\n", "\r\n")

	// Relaxed output
	relaxedOut := strings.ReplaceAll(` c
d e
`, "\n", "\r\n")
	relaxedBh, err := computeBodyHash(crypto.SHA256.New(), CanonRelaxed, []byte(exampleIn))
	if err != nil {
		t.Fatalf("bodyhash: %s", err)
	}
	relaxedOutHash := sha256.Sum256([]byte(relaxedOut))
	if !bytes.Equal(relaxedBh, relaxedOutHash[:]) {
		t.Fatalf("relaxed body hash mismatch")
	}

	// Simple output
	simpleOut := strings.ReplaceAll(` c
d 	 e
`, "\n", "\r\n")
	simpleBh, err := computeBodyHash(crypto.SHA256.New(), CanonSimple, []byte(exampleIn))
	if err != nil {
		t.Fatalf("bodyhash: %s", err)
	}
	simpleOutHash := sha256.Sum256([]byte(simpleOut))
	if !bytes.Equal(simpleBh, simpleOutHash[:]) {
		t.Fatalf("simple body hash mismatch")
	}

	// RFC 8463 relaxed body example
	relaxedBody := strings.ReplaceAll(`Hi.

We lost the game.  Are you hungry yet?

Joe.

`, "\n", "\r\n")
	relaxedGot, err = computeBodyHash(crypto.SHA256.New(), CanonRelaxed, []byte(relaxedBody))
	if err != nil {
		t.Fatalf("body hash, relaxed, ed25519 example: %s", err)
	}
	relaxedWant = base64Decode("2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=")
	if !bytes.Equal(relaxedGot, relaxedWant) {
		t.Fatalf("relaxed body hash for ed25519 example, got %s, expected %s", base64Encode(relaxedGot), base64Encode(relaxedWant))
	}
}

// TestVerifyDNSSECAuthentic tests that DNSSEC authentication is properly reported.
func TestVerifyDNSSECAuthentic(t *testing.T) {
	message := strings.ReplaceAll(`From: <mjl@mox.example>
To: <other@mox.example>
Subject: test
Date: Fri, 10 Dec 2021 20:09:08 +0100
Message-ID: <test@mox.example>

test
`, "\n", "\r\n")

	key := ed25519.NewKeyFromSeed(make([]byte, 32))

	signer := &Signer{
		Domain:     "mox.example",
		Selector:   "test",
		PrivateKey: key,
		Headers:    []string{"From", "To", "Subject", "Date"},
	}

	sigHeader, err := signer.Sign([]byte(message))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	record := &Record{
		Version:   "DKIM1",
		Key:       "ed25519",
		PublicKey: key.Public(),
	}
	recordTxt, err := record.ToTXT()
	if err != nil {
		t.Fatalf("making record: %v", err)
	}

	// Test with AllAuthentic = true
	resolver := ravendns.MockResolver{
		TXT: map[string][]string{
			"test._domainkey.mox.example.": {recordTxt},
		},
		AllAuthentic: true,
	}

	verifier := &Verifier{Resolver: resolver}
	results, err := verifier.Verify(context.Background(), []byte(sigHeader+message))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].RecordAuthentic {
		t.Error("expected RecordAuthentic to be true")
	}

	// Test with AllAuthentic = false
	resolver2 := ravendns.MockResolver{
		TXT: map[string][]string{
			"test._domainkey.mox.example.": {recordTxt},
		},
		AllAuthentic: false,
	}
	verifier2 := &Verifier{Resolver: resolver2}
	results, err = verifier2.Verify(context.Background(), []byte(sigHeader+message))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].RecordAuthentic {
		t.Error("expected RecordAuthentic to be false")
	}
}

// TestSealedHeaders tests that sealed headers prevent header addition attacks.
func TestSealedHeaders(t *testing.T) {
	message := strings.ReplaceAll(`From: <mjl@mox.example>
To: <other@mox.example>
Subject: test
Date: Fri, 10 Dec 2021 20:09:08 +0100
Message-ID: <test@mox.example>

test
`, "\n", "\r\n")

	key := ed25519.NewKeyFromSeed(make([]byte, 32))

	// Sign without oversigning (sealing)
	signerUnseal := &Signer{
		Domain:          "mox.example",
		Selector:        "test",
		PrivateKey:      key,
		Headers:         []string{"From", "To", "Subject", "Date"},
		OversignHeaders: false,
	}

	sigHeader, err := signerUnseal.Sign([]byte(message))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	record := &Record{
		Version:   "DKIM1",
		Key:       "ed25519",
		PublicKey: key.Public(),
	}
	recordTxt, err := record.ToTXT()
	if err != nil {
		t.Fatalf("making record: %v", err)
	}

	resolver := ravendns.MockResolver{
		TXT: map[string][]string{
			"test._domainkey.mox.example.": {recordTxt},
		},
	}

	verifier := &Verifier{Resolver: resolver}

	// Adding a header at the end should fail (Subject header added after headers)
	msgWithAddedSubject := strings.ReplaceAll(sigHeader+message, "\r\n\r\n", "\r\nsubject: another\r\n\r\n")
	results, err := verifier.Verify(context.Background(), []byte(msgWithAddedSubject))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(results) != 1 || results[0].Status != StatusFail {
		t.Fatalf("expected signature to fail with added header, got %v", results)
	}

	// Adding a header at the beginning should pass (the original Subject is used)
	msgWithPrependedSubject := "subject: another\r\n" + sigHeader + message
	results, err = verifier.Verify(context.Background(), []byte(msgWithPrependedSubject))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(results) != 1 || results[0].Status != StatusPass {
		if len(results) > 0 {
			t.Fatalf("expected signature to pass, got %v: %v", results[0].Status, results[0].Err)
		}
		t.Fatalf("expected signature to pass, got no results")
	}
}

// TestLastOccurringHeader tests that DKIM verification uses the last-occurring header
// when the same header appears multiple times. This is per RFC 6376 Section 5.4.2.
func TestLastOccurringHeader(t *testing.T) {
	message := strings.ReplaceAll(`From: <mjl@mox.example>
To: <other@mox.example>
Subject: original
Date: Fri, 10 Dec 2021 20:09:08 +0100
Message-ID: <test@mox.example>

test
`, "\n", "\r\n")

	key := ed25519.NewKeyFromSeed(make([]byte, 32))

	// Sign without oversigning
	signer := &Signer{
		Domain:          "mox.example",
		Selector:        "test",
		PrivateKey:      key,
		Headers:         []string{"From", "To", "Subject", "Date"},
		OversignHeaders: false,
	}

	sigHeader, err := signer.Sign([]byte(message))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	record := &Record{
		Version:   "DKIM1",
		Key:       "ed25519",
		PublicKey: key.Public(),
	}
	recordTxt, err := record.ToTXT()
	if err != nil {
		t.Fatalf("making record: %v", err)
	}

	resolver := ravendns.MockResolver{
		TXT: map[string][]string{
			"test._domainkey.mox.example.": {recordTxt},
		},
	}

	verifier := &Verifier{Resolver: resolver}

	// Prepending a "subject: another" header should NOT affect verification
	// because DKIM should use the last-occurring Subject header (the original one)
	// RFC 6376: "The order of the header fields determines which header field is
	// signed, based on which one is encountered first in the message."
	msgWithPrepended := "subject: another\r\n" + sigHeader + message
	results, err := verifier.Verify(context.Background(), []byte(msgWithPrepended))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(results) != 1 || results[0].Status != StatusPass {
		if len(results) > 0 {
			t.Fatalf("prepended header: expected pass, got %v: %v", results[0].Status, results[0].Err)
		}
		t.Fatalf("prepended header: expected pass, got no results")
	}

	// Appending a "subject: another" header (before the body) SHOULD fail verification
	// because now the "another" subject is the last-occurring one
	msgWithAppended := strings.ReplaceAll(sigHeader+message, "\r\n\r\n", "\r\nsubject: another\r\n\r\n")
	results, err = verifier.Verify(context.Background(), []byte(msgWithAppended))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(results) != 1 || results[0].Status != StatusFail {
		t.Fatalf("appended header: expected fail, got %v", results)
	}
}

func base64Decode(s string) []byte {
	buf, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return buf
}

func base64Encode(buf []byte) string {
	return base64.StdEncoding.EncodeToString(buf)
}

// TestVerifyMultipleSignatures tests verification of messages with multiple DKIM signatures.
func TestVerifyMultipleSignatures(t *testing.T) {
	message := strings.ReplaceAll(`From: sender@mox.example
To: recipient@other.example
Subject: Test Multiple DKIM Signatures
Date: Thu, 18 Dec 2025 12:00:00 +0000
Message-ID: <test@mox.example>

This is a test message with multiple DKIM signatures.
`, "\n", "\r\n")

	// Generate keys
	rsaKey := getRSAKey(t)
	ed25519Key := ed25519.NewKeyFromSeed(make([]byte, 32))

	// Create signers with different key types and canonicalizations
	signers := []Signer{
		{
			Domain:                 "mox.example",
			Selector:               "rsa1",
			PrivateKey:             rsaKey,
			Headers:                []string{"From", "To", "Subject", "Date"},
			HeaderCanonicalization: CanonRelaxed,
			BodyCanonicalization:   CanonRelaxed,
		},
		{
			Domain:                 "mox.example",
			Selector:               "rsa2",
			PrivateKey:             rsaKey,
			Headers:                []string{"From", "To", "Subject", "Date", "Message-ID"},
			HeaderCanonicalization: CanonRelaxed,
			BodyCanonicalization:   CanonSimple,
		},
		{
			Domain:                 "mox.example",
			Selector:               "ed25519",
			PrivateKey:             ed25519Key,
			Headers:                []string{"From", "To", "Subject", "Date"},
			HeaderCanonicalization: CanonRelaxed,
			BodyCanonicalization:   CanonRelaxed,
		},
	}

	// Sign the message with all signers
	sigHeaders, err := SignMultiple([]byte(message), signers)
	if err != nil {
		t.Fatalf("SignMultiple: %v", err)
	}

	// Set up DNS records for all selectors
	resolver := ravendns.MockResolver{
		TXT: map[string][]string{
			"rsa1._domainkey.mox.example.":    {makeRecord(t, "rsa", &rsaKey.PublicKey)},
			"rsa2._domainkey.mox.example.":    {makeRecord(t, "rsa", &rsaKey.PublicKey)},
			"ed25519._domainkey.mox.example.": {makeRecord(t, "ed25519", ed25519Key.Public())},
		},
	}

	verifier := &Verifier{Resolver: resolver}

	// Verify the signed message
	signedMessage := sigHeaders + message
	results, err := verifier.Verify(context.Background(), []byte(signedMessage))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Should have 3 results
	if len(results) != 3 {
		t.Fatalf("expected 3 verification results, got %d", len(results))
	}

	// All signatures should pass
	for i, r := range results {
		if r.Status != StatusPass {
			t.Errorf("signature %d (%s): expected StatusPass, got %s: %v", i, r.Signature.Selector, r.Status, r.Err)
		}
		if r.Signature.Domain != "mox.example" {
			t.Errorf("signature %d: domain = %s, want mox.example", i, r.Signature.Domain)
		}
	}

	// Verify selectors are correct
	selectors := make(map[string]bool)
	for _, r := range results {
		selectors[r.Signature.Selector] = true
	}
	if !selectors["rsa1"] || !selectors["rsa2"] || !selectors["ed25519"] {
		t.Errorf("unexpected selectors: %v", selectors)
	}
}

// TestVerifyMultipleSignaturesPartialFailure tests verification when some signatures fail.
func TestVerifyMultipleSignaturesPartialFailure(t *testing.T) {
	message := strings.ReplaceAll(`From: sender@mox.example
To: recipient@other.example
Subject: Test Partial Failure
Date: Thu, 18 Dec 2025 12:00:00 +0000

Test message.
`, "\n", "\r\n")

	rsaKey := getRSAKey(t)
	ed25519Key := ed25519.NewKeyFromSeed(make([]byte, 32))

	signers := []Signer{
		{
			Domain:                 "mox.example",
			Selector:               "valid",
			PrivateKey:             rsaKey,
			Headers:                []string{"From", "To", "Subject"},
			HeaderCanonicalization: CanonRelaxed,
			BodyCanonicalization:   CanonRelaxed,
		},
		{
			Domain:                 "mox.example",
			Selector:               "norecord",
			PrivateKey:             ed25519Key,
			Headers:                []string{"From", "To", "Subject"},
			HeaderCanonicalization: CanonRelaxed,
			BodyCanonicalization:   CanonRelaxed,
		},
	}

	sigHeaders, err := SignMultiple([]byte(message), signers)
	if err != nil {
		t.Fatalf("SignMultiple: %v", err)
	}

	// Only set up DNS record for "valid" selector
	resolver := ravendns.MockResolver{
		TXT: map[string][]string{
			"valid._domainkey.mox.example.": {makeRecord(t, "rsa", &rsaKey.PublicKey)},
			// "norecord" has no DNS record
		},
	}

	verifier := &Verifier{Resolver: resolver}

	signedMessage := sigHeaders + message
	results, err := verifier.Verify(context.Background(), []byte(signedMessage))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 verification results, got %d", len(results))
	}

	// Check results - one should pass, one should fail
	var passCount, failCount int
	for _, r := range results {
		switch r.Status {
		case StatusPass:
			passCount++
			if r.Signature.Selector != "valid" {
				t.Errorf("expected 'valid' selector to pass, got %s", r.Signature.Selector)
			}
		case StatusTemperror, StatusPermerror:
			failCount++
			if r.Signature.Selector != "norecord" {
				t.Errorf("expected 'norecord' selector to fail, got %s", r.Signature.Selector)
			}
		default:
			t.Errorf("unexpected status %s for selector %s", r.Status, r.Signature.Selector)
		}
	}

	if passCount != 1 || failCount != 1 {
		t.Errorf("expected 1 pass and 1 fail, got %d pass and %d fail", passCount, failCount)
	}
}

// TestVerifyMultipleSignaturesMixedAlgorithms tests verification with different key algorithms.
func TestVerifyMultipleSignaturesMixedAlgorithms(t *testing.T) {
	message := strings.ReplaceAll(`From: sender@mox.example
To: recipient@other.example
Subject: Test Mixed Algorithms
Date: Thu, 18 Dec 2025 12:00:00 +0000

Test message with mixed algorithm signatures.
`, "\n", "\r\n")

	rsaKey := getRSAKey(t)
	ed25519Key := ed25519.NewKeyFromSeed(make([]byte, 32))

	// Sign with both RSA and Ed25519
	signers := []Signer{
		{
			Domain:                 "mox.example",
			Selector:               "rsa",
			PrivateKey:             rsaKey,
			Headers:                []string{"From", "To", "Subject", "Date"},
			HeaderCanonicalization: CanonRelaxed,
			BodyCanonicalization:   CanonRelaxed,
		},
		{
			Domain:                 "mox.example",
			Selector:               "ed",
			PrivateKey:             ed25519Key,
			Headers:                []string{"From", "To", "Subject", "Date"},
			HeaderCanonicalization: CanonRelaxed,
			BodyCanonicalization:   CanonRelaxed,
		},
	}

	sigHeaders, err := SignMultiple([]byte(message), signers)
	if err != nil {
		t.Fatalf("SignMultiple: %v", err)
	}

	resolver := ravendns.MockResolver{
		TXT: map[string][]string{
			"rsa._domainkey.mox.example.": {makeRecord(t, "rsa", &rsaKey.PublicKey)},
			"ed._domainkey.mox.example.":  {makeRecord(t, "ed25519", ed25519Key.Public())},
		},
	}

	verifier := &Verifier{Resolver: resolver}

	signedMessage := sigHeaders + message
	results, err := verifier.Verify(context.Background(), []byte(signedMessage))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 verification results, got %d", len(results))
	}

	// Both should pass
	for _, r := range results {
		if r.Status != StatusPass {
			t.Errorf("signature for selector %s: expected StatusPass, got %s: %v", r.Signature.Selector, r.Status, r.Err)
		}
	}

	// Verify we got both algorithm types
	algorithms := make(map[string]bool)
	for _, r := range results {
		algorithms[r.Signature.Algorithm] = true
	}
	if !algorithms["rsa-sha256"] || !algorithms["ed25519-sha256"] {
		t.Errorf("expected both rsa-sha256 and ed25519-sha256, got %v", algorithms)
	}
}
