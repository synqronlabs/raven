package server_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/synqronlabs/raven/sasl"
	"github.com/synqronlabs/raven/server"
)

type verifierAuthSession struct {
	conn     *server.Conn
	identity string
	verified bool
}

func (s *verifierAuthSession) Mail(string, *server.MailOptions) error { return nil }
func (s *verifierAuthSession) Rcpt(string, *server.RcptOptions) error { return nil }
func (s *verifierAuthSession) Data(io.Reader) error                   { return nil }
func (s *verifierAuthSession) Reset()                                 {}
func (s *verifierAuthSession) Logout() error                          { return nil }

func (*verifierAuthSession) AuthMechanisms() []string { return []string{"PLAIN"} }

func (s *verifierAuthSession) Auth(mech string) (sasl.Server, error) {
	if mech != "PLAIN" {
		return nil, fmt.Errorf("unsupported mechanism: %s", mech)
	}

	return sasl.NewPlainServer(func(creds *sasl.Credentials) error {
		if creds.AuthenticationID != "user@example.com" || creds.Password != "s3cret" {
			return errors.New("invalid credentials")
		}
		s.identity = creds.Identity()
		s.verified = true
		return nil
	}), nil
}

type manualIdentitySession struct {
	conn *server.Conn
}

func (s *manualIdentitySession) Mail(string, *server.MailOptions) error { return nil }
func (s *manualIdentitySession) Rcpt(string, *server.RcptOptions) error { return nil }
func (s *manualIdentitySession) Data(io.Reader) error                   { return nil }
func (s *manualIdentitySession) Reset()                                 {}
func (s *manualIdentitySession) Logout() error                          { return nil }

func (*manualIdentitySession) AuthMechanisms() []string { return []string{"PLAIN"} }

func (s *manualIdentitySession) Auth(mech string) (sasl.Server, error) {
	if mech != "PLAIN" {
		return nil, fmt.Errorf("unsupported mechanism: %s", mech)
	}
	return &manualIdentityServer{conn: s.conn}, nil
}

type manualIdentityServer struct {
	conn *server.Conn
	done bool
}

func (s *manualIdentityServer) Next([]byte) ([]byte, bool, error) {
	if s.done {
		return nil, true, sasl.ErrInvalidFormat
	}
	s.conn.SetAuthIdentity("manual-user")
	s.done = true
	return nil, true, nil
}

type longAuthSession struct{}

func (*longAuthSession) Mail(string, *server.MailOptions) error { return nil }
func (*longAuthSession) Rcpt(string, *server.RcptOptions) error { return nil }
func (*longAuthSession) Data(io.Reader) error                   { return nil }
func (*longAuthSession) Reset()                                 {}
func (*longAuthSession) Logout() error                          { return nil }

func (*longAuthSession) AuthMechanisms() []string { return []string{"LONG"} }

func (*longAuthSession) Auth(mech string) (sasl.Server, error) {
	if mech != "LONG" {
		return nil, fmt.Errorf("unsupported mechanism: %s", mech)
	}
	return &longAuthServer{}, nil
}

type longAuthServer struct {
	challenged bool
}

func (s *longAuthServer) Next(response []byte) ([]byte, bool, error) {
	if !s.challenged {
		s.challenged = true
		return []byte("continue"), false, nil
	}
	if len(response) != 2000 {
		return nil, false, fmt.Errorf("unexpected response length: %d", len(response))
	}
	return nil, true, nil
}

func TestServer_AUTHPlainPropagatesIdentity(t *testing.T) {
	var sess *verifierAuthSession
	backend := &testBackend{
		sessionFactory: func(c *server.Conn) (server.Session, error) {
			sess = &verifierAuthSession{conn: c}
			return sess, nil
		},
	}

	ts := newTestServer(t, backend, server.ServerConfig{AllowInsecureAuth: true})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	lines := tc.expectMultilineCode(250)
	foundAuth := false
	for _, line := range lines {
		if line == "250-AUTH PLAIN" || line == "250 AUTH PLAIN" {
			foundAuth = true
			break
		}
	}
	if !foundAuth {
		t.Fatalf("expected AUTH PLAIN advertisement, got %v", lines)
	}

	encoded := base64.StdEncoding.EncodeToString([]byte("admin\x00user@example.com\x00s3cret"))
	tc.send("AUTH PLAIN %s", encoded)
	tc.expectCode(235)

	if sess == nil {
		t.Fatal("expected session to be created")
	}
	if !sess.verified {
		t.Fatal("expected credentials to be verified")
	}
	if got := sess.identity; got != "admin" {
		t.Fatalf("verified identity = %q, want %q", got, "admin")
	}
	if got := sess.conn.AuthIdentity(); got != "admin" {
		t.Fatalf("Conn.AuthIdentity = %q, want %q", got, "admin")
	}
	if !sess.conn.Authenticated() {
		t.Fatal("expected connection to be authenticated")
	}
}

func TestServer_AUTHCustomServerCanSetIdentity(t *testing.T) {
	var sess *manualIdentitySession
	backend := &testBackend{
		sessionFactory: func(c *server.Conn) (server.Session, error) {
			sess = &manualIdentitySession{conn: c}
			return sess, nil
		},
	}

	ts := newTestServer(t, backend, server.ServerConfig{AllowInsecureAuth: true})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	tc.expectMultilineCode(250)

	tc.send("AUTH PLAIN")
	tc.expectCode(235)

	if sess == nil {
		t.Fatal("expected session to be created")
	}
	if got := sess.conn.AuthIdentity(); got != "manual-user" {
		t.Fatalf("Conn.AuthIdentity = %q, want %q", got, "manual-user")
	}
	if !sess.conn.Authenticated() {
		t.Fatal("expected connection to be authenticated")
	}
}

func TestServer_AUTHResponseUsesSeparateLineLimit(t *testing.T) {
	backend := &testBackend{
		sessionFactory: func(*server.Conn) (server.Session, error) {
			return &longAuthSession{}, nil
		},
	}

	ts := newTestServer(t, backend, server.ServerConfig{
		AllowInsecureAuth: true,
		MaxLineLength:     512,
		MaxAuthLineLength: 4096,
	})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	tc.expectMultilineCode(250)

	tc.send("AUTH LONG")
	tc.expectCode(334)

	payload := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), 2000))
	if len(payload)+2 <= 512 {
		t.Fatalf("test payload too short: got %d bytes including CRLF", len(payload)+2)
	}
	if len(payload)+2 > 4096 {
		t.Fatalf("test payload too long for MaxAuthLineLength: got %d bytes including CRLF", len(payload)+2)
	}

	tc.send("%s", payload)
	tc.expectCode(235)
}
