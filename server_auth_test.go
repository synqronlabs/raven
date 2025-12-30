package raven

import (
	"bufio"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// Authentication Setup Tests
// =============================================================================

func TestServer_Auth_NotAdvertisedByDefault(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	lines := client.ExpectMultilineCode(250)

	for _, line := range lines {
		if strings.Contains(line, "AUTH") {
			t.Error("AUTH should not be advertised without configuration")
		}
	}
}

func TestServer_Auth_AdvertisedWhenConfigured(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			return nil // Accept all
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	lines := client.ExpectMultilineCode(250)

	authFound := false
	for _, line := range lines {
		if strings.Contains(line, "AUTH") && strings.Contains(line, "PLAIN") {
			authFound = true
			break
		}
	}
	if !authFound {
		t.Error("expected AUTH PLAIN to be advertised")
	}
}

func TestServer_Auth_MultipleMechanisms(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, nil).EnableLoginAuth()
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	lines := client.ExpectMultilineCode(250)

	var authLine string
	for _, line := range lines {
		if strings.Contains(line, "AUTH") {
			authLine = line
			break
		}
	}

	if !strings.Contains(authLine, "PLAIN") {
		t.Error("expected PLAIN in AUTH mechanisms")
	}
	if !strings.Contains(authLine, "LOGIN") {
		t.Error("expected LOGIN in AUTH mechanisms")
	}
}

// =============================================================================
// PLAIN Authentication Tests
// =============================================================================

func TestServer_Auth_PLAIN_Success(t *testing.T) {
	var authIdentity, authPassword string
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			mu.Lock()
			authIdentity = identity
			authPassword = password
			mu.Unlock()
			return nil // Accept
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	// AUTH PLAIN with initial response
	// Format: base64(authzid NUL authcid NUL passwd)
	plainAuth := base64.StdEncoding.EncodeToString([]byte("\x00user@example.com\x00password123"))
	client.Send("AUTH PLAIN %s", plainAuth)
	client.ExpectCode(235)

	mu.Lock()
	if authIdentity != "user@example.com" {
		t.Errorf("expected identity 'user@example.com', got %q", authIdentity)
	}
	if authPassword != "password123" {
		t.Errorf("expected password 'password123', got %q", authPassword)
	}
	mu.Unlock()
}

func TestServer_Auth_PLAIN_Challenge(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			return nil // Accept
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	// AUTH PLAIN without initial response
	client.Send("AUTH PLAIN")
	client.ExpectCode(334) // Server sends challenge

	// Send credentials
	plainAuth := base64.StdEncoding.EncodeToString([]byte("\x00user@example.com\x00password123"))
	client.Send("%s", plainAuth)
	client.ExpectCode(235)
}

func TestServer_Auth_PLAIN_Rejected(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			if password != "correctpassword" {
				return c.Error(CodeAuthCredentialsInvalid, "Invalid credentials")
			}
			return nil
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	plainAuth := base64.StdEncoding.EncodeToString([]byte("\x00user@example.com\x00wrongpassword"))
	client.Send("AUTH PLAIN %s", plainAuth)
	client.ExpectCode(535)
}

func TestServer_Auth_PLAIN_InvalidBase64(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			return nil
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	client.Send("AUTH PLAIN not-valid-base64!!!")
	client.ExpectCode(535)
}

func TestServer_Auth_PLAIN_InvalidFormat(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			return nil
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	// Invalid format (missing parts)
	invalidAuth := base64.StdEncoding.EncodeToString([]byte("just-one-part"))
	client.Send("AUTH PLAIN %s", invalidAuth)
	client.ExpectCode(535)
}

func TestServer_Auth_PLAIN_Cancel(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			return nil
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	client.Send("AUTH PLAIN")
	client.ExpectCode(334)

	// Cancel with "*"
	client.Send("*")
	client.ExpectCode(535)
}

// =============================================================================
// LOGIN Authentication Tests
// =============================================================================

func TestServer_Auth_LOGIN_Success(t *testing.T) {
	var authIdentity, authPassword string
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			mu.Lock()
			authIdentity = identity
			authPassword = password
			mu.Unlock()
			return nil
		}).EnableLoginAuth()
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	client.Send("AUTH LOGIN")
	line := client.ExpectCode(334)
	// Should prompt for username (base64 of "Username:")
	if !strings.Contains(line, base64.StdEncoding.EncodeToString([]byte("Username:"))) {
		t.Logf("Got challenge: %s", line)
	}

	// Send username
	client.Send("%s", base64.StdEncoding.EncodeToString([]byte("user@example.com")))
	line = client.ExpectCode(334)
	// Should prompt for password (base64 of "Password:")
	if !strings.Contains(line, base64.StdEncoding.EncodeToString([]byte("Password:"))) {
		t.Logf("Got challenge: %s", line)
	}

	// Send password
	client.Send("%s", base64.StdEncoding.EncodeToString([]byte("password123")))
	client.ExpectCode(235)

	mu.Lock()
	if authIdentity != "user@example.com" {
		t.Errorf("expected identity 'user@example.com', got %q", authIdentity)
	}
	if authPassword != "password123" {
		t.Errorf("expected password 'password123', got %q", authPassword)
	}
	mu.Unlock()
}

func TestServer_Auth_LOGIN_Rejected(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			if password != "correctpassword" {
				return c.Error(CodeAuthCredentialsInvalid, "Invalid credentials")
			}
			return nil
		}).EnableLoginAuth()
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	client.Send("AUTH LOGIN")
	client.ExpectCode(334)

	client.Send("%s", base64.StdEncoding.EncodeToString([]byte("user@example.com")))
	client.ExpectCode(334)

	client.Send("%s", base64.StdEncoding.EncodeToString([]byte("wrongpassword")))
	client.ExpectCode(535)
}

// =============================================================================
// Authentication State Tests
// =============================================================================

func TestServer_Auth_BeforeEhlo(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			return nil
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	// Try AUTH before EHLO
	plainAuth := base64.StdEncoding.EncodeToString([]byte("\x00user\x00pass"))
	client.Send("AUTH PLAIN %s", plainAuth)
	client.ExpectCode(503)
}

func TestServer_Auth_AlreadyAuthenticated(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			return nil
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	// First auth succeeds
	plainAuth := base64.StdEncoding.EncodeToString([]byte("\x00user\x00pass"))
	client.Send("AUTH PLAIN %s", plainAuth)
	client.ExpectCode(235)

	// Second auth should fail
	client.Send("AUTH PLAIN %s", plainAuth)
	client.ExpectCode(503)
}

func TestServer_Auth_UnsupportedMechanism(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			return nil
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	// Try unsupported mechanism
	client.Send("AUTH CRAM-MD5")
	client.ExpectCode(504)
}

// =============================================================================
// Require Auth Tests
// =============================================================================

func TestServer_RequireAuth_MailFromRejected(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			return nil
		}).RequireAuth()
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	// Try MAIL FROM without auth
	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(554) // Transaction failed (auth required)
}

func TestServer_RequireAuth_MailFromAccepted(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			return nil
		}).RequireAuth()
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	// Authenticate first
	plainAuth := base64.StdEncoding.EncodeToString([]byte("\x00user\x00pass"))
	client.Send("AUTH PLAIN %s", plainAuth)
	client.ExpectCode(235)

	// Now MAIL FROM should work
	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(250)
}

// =============================================================================
// Auth Identity in Context Tests
// =============================================================================

func TestServer_Auth_IdentityAvailableInHandlers(t *testing.T) {
	var authIdentity string
	var isAuthenticated bool
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			return nil
		})
		s.OnMailFrom(func(c *Context) *Response {
			mu.Lock()
			isAuthenticated = c.Connection.IsAuthenticated()
			authIdentity = c.AuthIdentity()
			mu.Unlock()
			return c.Next()
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	plainAuth := base64.StdEncoding.EncodeToString([]byte("\x00testuser@example.com\x00password"))
	client.Send("AUTH PLAIN %s", plainAuth)
	client.ExpectCode(235)

	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(250)

	mu.Lock()
	if !isAuthenticated {
		t.Error("expected IsAuthenticated to be true")
	}
	if authIdentity != "testuser@example.com" {
		t.Errorf("expected auth identity 'testuser@example.com', got %q", authIdentity)
	}
	mu.Unlock()
}

func TestServer_Auth_NotAuthenticatedIdentity(t *testing.T) {
	var authIdentity string
	var isAuthenticated bool
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.OnMailFrom(func(c *Context) *Response {
			mu.Lock()
			isAuthenticated = c.Connection.IsAuthenticated()
			authIdentity = c.AuthIdentity()
			mu.Unlock()
			return c.Next()
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(250)

	mu.Lock()
	if isAuthenticated {
		t.Error("expected IsAuthenticated to be false")
	}
	if authIdentity != "" {
		t.Errorf("expected empty auth identity, got %q", authIdentity)
	}
	mu.Unlock()
}

// =============================================================================
// Auth with Authorization ID Tests
// =============================================================================

func TestServer_Auth_PLAIN_WithAuthzID(t *testing.T) {
	var authIdentity, authPassword string
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			mu.Lock()
			authIdentity = identity
			authPassword = password
			mu.Unlock()
			return nil
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	// With authzid: base64(authzid NUL authcid NUL passwd)
	plainAuth := base64.StdEncoding.EncodeToString([]byte("admin@example.com\x00user@example.com\x00password"))
	client.Send("AUTH PLAIN %s", plainAuth)
	client.ExpectCode(235)

	mu.Lock()
	// When authzid is provided, identity should be authzid
	if authIdentity != "admin@example.com" {
		t.Errorf("expected identity 'admin@example.com' (authzid), got %q", authIdentity)
	}
	if authPassword != "password" {
		t.Errorf("expected password 'password', got %q", authPassword)
	}
	mu.Unlock()
}

// =============================================================================
// Auth Envelope Tests
// =============================================================================

func TestServer_Auth_EnvelopeAuth(t *testing.T) {
	var envelopeAuth string
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			return nil
		})
		s.OnMessage(func(c *Context) *Response {
			mu.Lock()
			envelopeAuth = c.Mail.Envelope.Auth
			mu.Unlock()
			return c.Next()
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	plainAuth := base64.StdEncoding.EncodeToString([]byte("\x00authuser@example.com\x00password"))
	client.Send("AUTH PLAIN %s", plainAuth)
	client.ExpectCode(235)

	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(250)

	client.Send("RCPT TO:<recipient@example.com>")
	client.ExpectCode(250)

	client.Send("DATA")
	client.ExpectCode(354)

	client.Send("Subject: Test")
	client.Send("")
	client.Send("Body")
	client.Send(".")

	client.ExpectCode(250)

	mu.Lock()
	if envelopeAuth != "authuser@example.com" {
		t.Errorf("expected envelope auth 'authuser@example.com', got %q", envelopeAuth)
	}
	mu.Unlock()
}

func TestServer_Auth_ReadTimeout(t *testing.T) {
	// Test that AUTH exchange respects ReadTimeout
	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"LOGIN"}, func(c *Context, mechanism, identity, password string) *Response {
			return nil // Accept all
		})
		s.ReadTimeout(100 * time.Millisecond)
	})
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	reader.ReadString('\n')

	// EHLO
	conn.Write([]byte("EHLO test.com\r\n"))
	for {
		line, _ := reader.ReadString('\n')
		if len(line) < 4 || line[3] == ' ' {
			break
		}
	}

	// Start AUTH LOGIN (requires multi-step exchange)
	conn.Write([]byte("AUTH LOGIN\r\n"))
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "334") {
		t.Fatalf("expected 334 challenge, got: %s", line)
	}

	// Don't respond - wait for timeout
	time.Sleep(200 * time.Millisecond)

	// Try to read - should get timeout or connection closed
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	line, err = reader.ReadString('\n')
	// Either connection closed (EOF) or we get a 4xx/5xx error
	if err == nil && !strings.HasPrefix(line, "4") && !strings.HasPrefix(line, "5") {
		t.Logf("expected timeout/error during AUTH, got: %s", line)
	}
}
