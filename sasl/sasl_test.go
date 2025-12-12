package sasl

import (
	"encoding/base64"
	"testing"
)

func TestPlain_Name(t *testing.T) {
	p := NewPlain()
	if p.Name() != "PLAIN" {
		t.Errorf("expected PLAIN, got %s", p.Name())
	}
}

func TestPlain_StartWithInitialResponse(t *testing.T) {
	// Format: authzid NUL authcid NUL passwd
	data := "\x00user@example.com\x00secret123"
	encoded := base64.StdEncoding.EncodeToString([]byte(data))

	p := NewPlain()
	challenge, done, err := p.Start(encoded)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !done {
		t.Error("expected done to be true")
	}
	if challenge != "" {
		t.Errorf("expected empty challenge, got %s", challenge)
	}

	creds := p.Credentials()
	if creds == nil {
		t.Fatal("expected credentials, got nil")
	}
	if creds.AuthorizationID != "" {
		t.Errorf("expected empty authzid, got %s", creds.AuthorizationID)
	}
	if creds.AuthenticationID != "user@example.com" {
		t.Errorf("expected user@example.com, got %s", creds.AuthenticationID)
	}
	if creds.Password != "secret123" {
		t.Errorf("expected secret123, got %s", creds.Password)
	}
	if creds.Identity() != "user@example.com" {
		t.Errorf("expected identity user@example.com, got %s", creds.Identity())
	}
}

func TestPlain_StartWithoutInitialResponse(t *testing.T) {
	p := NewPlain()
	challenge, done, err := p.Start("")

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if done {
		t.Error("expected done to be false")
	}
	if challenge != "" {
		t.Errorf("expected empty challenge, got %s", challenge)
	}

	// Now send the response
	data := "admin\x00user@example.com\x00secret123"
	encoded := base64.StdEncoding.EncodeToString([]byte(data))

	challenge, done, err = p.Next(encoded)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !done {
		t.Error("expected done to be true")
	}

	creds := p.Credentials()
	if creds == nil {
		t.Fatal("expected credentials, got nil")
	}
	if creds.AuthorizationID != "admin" {
		t.Errorf("expected admin authzid, got %s", creds.AuthorizationID)
	}
	if creds.AuthenticationID != "user@example.com" {
		t.Errorf("expected user@example.com, got %s", creds.AuthenticationID)
	}
	if creds.Identity() != "admin" {
		t.Errorf("expected identity admin (authzid), got %s", creds.Identity())
	}
}

func TestPlain_Cancelled(t *testing.T) {
	p := NewPlain()
	_, _, _ = p.Start("")

	_, done, err := p.Next("*")
	if err != ErrAuthenticationCancelled {
		t.Errorf("expected ErrAuthenticationCancelled, got %v", err)
	}
	if !done {
		t.Error("expected done to be true")
	}
}

func TestPlain_InvalidBase64(t *testing.T) {
	p := NewPlain()
	_, done, err := p.Start("not-valid-base64!!!")

	if err != ErrInvalidBase64 {
		t.Errorf("expected ErrInvalidBase64, got %v", err)
	}
	if !done {
		t.Error("expected done to be true")
	}
}

func TestPlain_InvalidFormat_WrongParts(t *testing.T) {
	// Only two parts instead of three
	data := "user@example.com\x00secret123"
	encoded := base64.StdEncoding.EncodeToString([]byte(data))

	p := NewPlain()
	_, done, err := p.Start(encoded)

	if err != ErrInvalidFormat {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}
	if !done {
		t.Error("expected done to be true")
	}
}

func TestPlain_InvalidFormat_EmptyAuthcid(t *testing.T) {
	// Empty authcid is not allowed
	data := "authzid\x00\x00secret123"
	encoded := base64.StdEncoding.EncodeToString([]byte(data))

	p := NewPlain()
	_, done, err := p.Start(encoded)

	if err != ErrInvalidFormat {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}
	if !done {
		t.Error("expected done to be true")
	}
}

func TestLogin_Name(t *testing.T) {
	l := NewLogin()
	if l.Name() != "LOGIN" {
		t.Errorf("expected LOGIN, got %s", l.Name())
	}
}

func TestLogin_FullExchange(t *testing.T) {
	l := NewLogin()

	// Start - should get username challenge
	challenge, done, err := l.Start("")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if done {
		t.Error("expected done to be false")
	}
	if challenge != LoginChallengeUsername {
		t.Errorf("expected username challenge, got %s", challenge)
	}

	// Send username
	username := base64.StdEncoding.EncodeToString([]byte("user@example.com"))
	challenge, done, err = l.Next(username)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if done {
		t.Error("expected done to be false")
	}
	if challenge != LoginChallengePassword {
		t.Errorf("expected password challenge, got %s", challenge)
	}

	// Send password
	password := base64.StdEncoding.EncodeToString([]byte("secret123"))
	challenge, done, err = l.Next(password)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !done {
		t.Error("expected done to be true")
	}
	if challenge != "" {
		t.Errorf("expected empty challenge, got %s", challenge)
	}

	creds := l.Credentials()
	if creds == nil {
		t.Fatal("expected credentials, got nil")
	}
	if creds.AuthenticationID != "user@example.com" {
		t.Errorf("expected user@example.com, got %s", creds.AuthenticationID)
	}
	if creds.Password != "secret123" {
		t.Errorf("expected secret123, got %s", creds.Password)
	}
	// LOGIN doesn't support authzid
	if creds.AuthorizationID != "" {
		t.Errorf("expected empty authzid, got %s", creds.AuthorizationID)
	}
}

func TestLogin_CancelledAtUsername(t *testing.T) {
	l := NewLogin()
	_, _, _ = l.Start("")

	_, done, err := l.Next("*")
	if err != ErrAuthenticationCancelled {
		t.Errorf("expected ErrAuthenticationCancelled, got %v", err)
	}
	if !done {
		t.Error("expected done to be true")
	}
}

func TestLogin_CancelledAtPassword(t *testing.T) {
	l := NewLogin()
	_, _, _ = l.Start("")

	username := base64.StdEncoding.EncodeToString([]byte("user@example.com"))
	_, _, _ = l.Next(username)

	_, done, err := l.Next("*")
	if err != ErrAuthenticationCancelled {
		t.Errorf("expected ErrAuthenticationCancelled, got %v", err)
	}
	if !done {
		t.Error("expected done to be true")
	}
}

func TestLogin_InvalidBase64Username(t *testing.T) {
	l := NewLogin()
	_, _, _ = l.Start("")

	_, done, err := l.Next("not-valid-base64!!!")
	if err != ErrInvalidBase64 {
		t.Errorf("expected ErrInvalidBase64, got %v", err)
	}
	if !done {
		t.Error("expected done to be true")
	}
}

func TestLogin_InvalidBase64Password(t *testing.T) {
	l := NewLogin()
	_, _, _ = l.Start("")

	username := base64.StdEncoding.EncodeToString([]byte("user@example.com"))
	_, _, _ = l.Next(username)

	_, done, err := l.Next("not-valid-base64!!!")
	if err != ErrInvalidBase64 {
		t.Errorf("expected ErrInvalidBase64, got %v", err)
	}
	if !done {
		t.Error("expected done to be true")
	}
}

func TestCredentials_Identity(t *testing.T) {
	// When authzid is set, it should be used
	c1 := &Credentials{
		AuthorizationID:  "admin",
		AuthenticationID: "user",
		Password:         "pass",
	}
	if c1.Identity() != "admin" {
		t.Errorf("expected admin, got %s", c1.Identity())
	}

	// When authzid is empty, authcid should be used
	c2 := &Credentials{
		AuthorizationID:  "",
		AuthenticationID: "user",
		Password:         "pass",
	}
	if c2.Identity() != "user" {
		t.Errorf("expected user, got %s", c2.Identity())
	}
}
