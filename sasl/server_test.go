package sasl

import (
	"errors"
	"testing"
)

func TestPlainServer_WithInitialResponse(t *testing.T) {
	var verified *Credentials

	server := NewPlainServer(func(creds *Credentials) error {
		verified = creds
		return nil
	})

	response := []byte("admin\x00user@example.com\x00s3cret")
	challenge, done, err := server.Next(response)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(challenge) != 0 {
		t.Fatalf("expected no challenge, got %q", challenge)
	}
	if !done {
		t.Fatal("expected authentication to complete")
	}
	if verified == nil {
		t.Fatal("expected verifier to receive credentials")
	}
	if verified.AuthorizationID != "admin" {
		t.Fatalf("AuthorizationID = %q, want %q", verified.AuthorizationID, "admin")
	}
	if verified.AuthenticationID != "user@example.com" {
		t.Fatalf("AuthenticationID = %q, want %q", verified.AuthenticationID, "user@example.com")
	}
	if verified.Password != "s3cret" {
		t.Fatalf("Password = %q, want %q", verified.Password, "s3cret")
	}

	identityProvider, ok := server.(interface{ AuthIdentity() string })
	if !ok {
		t.Fatal("expected AuthIdentity provider")
	}
	if got := identityProvider.AuthIdentity(); got != "admin" {
		t.Fatalf("AuthIdentity = %q, want %q", got, "admin")
	}
}

func TestPlainServer_ChallengeThenResponse(t *testing.T) {
	server := NewPlainServer(func(creds *Credentials) error {
		if creds.AuthenticationID != "user" {
			t.Fatalf("AuthenticationID = %q, want %q", creds.AuthenticationID, "user")
		}
		return nil
	})

	challenge, done, err := server.Next(nil)
	if err != nil {
		t.Fatalf("initial Next: %v", err)
	}
	if len(challenge) != 0 {
		t.Fatalf("expected empty challenge, got %q", challenge)
	}
	if done {
		t.Fatal("expected authentication to continue")
	}

	challenge, done, err = server.Next([]byte("\x00user\x00pass"))
	if err != nil {
		t.Fatalf("final Next: %v", err)
	}
	if len(challenge) != 0 {
		t.Fatalf("expected no final challenge, got %q", challenge)
	}
	if !done {
		t.Fatal("expected authentication to complete")
	}
}

func TestLoginServer_FullExchange(t *testing.T) {
	var verified *Credentials

	server := NewLoginServer(func(creds *Credentials) error {
		verified = creds
		return nil
	})

	challenge, done, err := server.Next(nil)
	if err != nil {
		t.Fatalf("initial Next: %v", err)
	}
	if string(challenge) != "Username:" {
		t.Fatalf("challenge = %q, want %q", string(challenge), "Username:")
	}
	if done {
		t.Fatal("expected authentication to continue")
	}

	challenge, done, err = server.Next([]byte("user"))
	if err != nil {
		t.Fatalf("username Next: %v", err)
	}
	if string(challenge) != "Password:" {
		t.Fatalf("challenge = %q, want %q", string(challenge), "Password:")
	}
	if done {
		t.Fatal("expected authentication to continue")
	}

	challenge, done, err = server.Next([]byte("pass"))
	if err != nil {
		t.Fatalf("password Next: %v", err)
	}
	if len(challenge) != 0 {
		t.Fatalf("expected no final challenge, got %q", challenge)
	}
	if !done {
		t.Fatal("expected authentication to complete")
	}
	if verified == nil {
		t.Fatal("expected verifier to receive credentials")
	}
	if verified.AuthenticationID != "user" {
		t.Fatalf("AuthenticationID = %q, want %q", verified.AuthenticationID, "user")
	}
	if verified.Password != "pass" {
		t.Fatalf("Password = %q, want %q", verified.Password, "pass")
	}
}

func TestPlainServer_VerifyFailure(t *testing.T) {
	expected := errors.New("invalid credentials")
	server := NewPlainServer(func(*Credentials) error {
		return expected
	})

	_, done, err := server.Next([]byte("\x00user\x00wrong"))
	if !done {
		t.Fatal("expected authentication to complete")
	}
	if !errors.Is(err, expected) {
		t.Fatalf("error = %v, want %v", err, expected)
	}
}
