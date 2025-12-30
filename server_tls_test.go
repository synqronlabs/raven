package raven

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// TLS Test Certificate Generation
// =============================================================================

// generateTestCert creates a self-signed certificate for testing.
func generateTestCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// Create certificate template
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test"},
			CommonName:   "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	// Encode certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode private key
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Parse certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Create cert pool
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	return cert, certPool
}

// =============================================================================
// STARTTLS Tests
// =============================================================================

func TestServer_STARTTLS_Advertised(t *testing.T) {
	cert, _ := generateTestCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	ts := newTestServer(t, func(s *Server) {
		s.TLS(tlsConfig)
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	lines := client.ExpectMultilineCode(250)

	starttlsFound := false
	for _, line := range lines {
		if strings.Contains(line, "STARTTLS") {
			starttlsFound = true
			break
		}
	}
	if !starttlsFound {
		t.Error("expected STARTTLS to be advertised")
	}
}

func TestServer_STARTTLS_NotAdvertisedWithoutConfig(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	lines := client.ExpectMultilineCode(250)

	for _, line := range lines {
		if strings.Contains(line, "STARTTLS") {
			t.Error("STARTTLS should not be advertised without TLS config")
		}
	}
}

func TestServer_STARTTLS_Success(t *testing.T) {
	cert, certPool := generateTestCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	ts := newTestServer(t, func(s *Server) {
		s.TLS(tlsConfig)
	})
	defer ts.Close()

	// Use raw connection for STARTTLS upgrade
	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "220") {
		t.Fatalf("unexpected greeting: %s", line)
	}

	// Send EHLO
	conn.Write([]byte("EHLO client.test\r\n"))
	for {
		line, _ = reader.ReadString('\n')
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// Send STARTTLS
	conn.Write([]byte("STARTTLS\r\n"))
	line, _ = reader.ReadString('\n')
	if !strings.HasPrefix(line, "220") {
		t.Fatalf("expected 220 for STARTTLS, got: %s", line)
	}

	// Upgrade to TLS
	clientTLSConfig := &tls.Config{
		RootCAs:    certPool,
		ServerName: "test.example.com",
	}
	tlsConn := tls.Client(conn, clientTLSConfig)
	err = tlsConn.Handshake()
	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	// Re-create reader for TLS connection
	tlsReader := bufio.NewReader(tlsConn)

	// Send EHLO again after TLS
	tlsConn.Write([]byte("EHLO client.test\r\n"))
	line, _ = tlsReader.ReadString('\n')
	if !strings.HasPrefix(line, "250") {
		t.Fatalf("unexpected EHLO response after TLS: %s", line)
	}
}

func TestServer_STARTTLS_BeforeEHLO(t *testing.T) {
	cert, _ := generateTestCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	ts := newTestServer(t, func(s *Server) {
		s.TLS(tlsConfig)
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	// Try STARTTLS without EHLO
	client.Send("STARTTLS")
	client.ExpectCode(503) // Bad sequence
}

func TestServer_STARTTLS_NotAdvertisedAfterUpgrade(t *testing.T) {
	cert, certPool := generateTestCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	ts := newTestServer(t, func(s *Server) {
		s.TLS(tlsConfig)
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
	conn.Write([]byte("EHLO client.test\r\n"))
	for {
		line, _ := reader.ReadString('\n')
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// STARTTLS
	conn.Write([]byte("STARTTLS\r\n"))
	reader.ReadString('\n')

	// Upgrade
	clientTLSConfig := &tls.Config{
		RootCAs:    certPool,
		ServerName: "test.example.com",
	}
	tlsConn := tls.Client(conn, clientTLSConfig)
	tlsConn.Handshake()
	tlsReader := bufio.NewReader(tlsConn)

	// EHLO after TLS
	tlsConn.Write([]byte("EHLO client.test\r\n"))
	var lines []string
	for {
		line, _ := tlsReader.ReadString('\n')
		lines = append(lines, line)
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// STARTTLS should NOT be advertised after upgrade
	for _, line := range lines {
		if strings.Contains(line, "STARTTLS") {
			t.Error("STARTTLS should not be advertised after TLS upgrade")
		}
	}
}

// =============================================================================
// RequireTLS Tests
// =============================================================================

func TestServer_RequireTLS_AuthNotAdvertisedWithoutTLS(t *testing.T) {
	cert, _ := generateTestCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	ts := newTestServer(t, func(s *Server) {
		s.TLS(tlsConfig).
			RequireTLS().
			Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
				return nil
			})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	lines := client.ExpectMultilineCode(250)

	// AUTH should NOT be advertised before TLS when RequireTLS is set
	for _, line := range lines {
		if strings.Contains(line, "AUTH") {
			t.Error("AUTH should not be advertised before TLS with RequireTLS")
		}
	}
}

func TestServer_RequireTLS_AuthRejectedWithoutTLS(t *testing.T) {
	cert, _ := generateTestCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	ts := newTestServer(t, func(s *Server) {
		s.TLS(tlsConfig).
			RequireTLS().
			Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
				return nil
			})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	// Try AUTH without TLS
	plainAuth := base64.StdEncoding.EncodeToString([]byte("\x00user\x00pass"))
	client.Send("AUTH PLAIN %s", plainAuth)
	client.ExpectCode(530) // Must use TLS first
}

func TestServer_RequireTLS_MailFromRejectedWithoutTLS(t *testing.T) {
	cert, _ := generateTestCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	ts := newTestServer(t, func(s *Server) {
		s.TLS(tlsConfig).RequireTLS()
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	// Try MAIL FROM without TLS
	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(554) // TLS required
}

// =============================================================================
// Implicit TLS Tests
// =============================================================================

func TestServer_ImplicitTLS(t *testing.T) {
	cert, certPool := generateTestCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	server := New("test.example.com").
		GracefulShutdown(false).
		TLS(tlsConfig)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to create TLS listener: %v", err)
	}

	go server.Serve(listener)
	defer server.Close()

	// Wait for server to start
	time.Sleep(10 * time.Millisecond)

	// Connect with TLS
	clientConfig := &tls.Config{
		RootCAs:    certPool,
		ServerName: "test.example.com",
	}
	conn, err := tls.Dial("tcp", listener.Addr().String(), clientConfig)
	if err != nil {
		t.Fatalf("failed to dial TLS: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "220") {
		t.Fatalf("unexpected greeting: %s", line)
	}

	// Send EHLO
	conn.Write([]byte("EHLO client.test\r\n"))
	var lines []string
	for {
		line, _ = reader.ReadString('\n')
		lines = append(lines, line)
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// STARTTLS should NOT be advertised (already using TLS)
	for _, line := range lines {
		if strings.Contains(line, "STARTTLS") {
			t.Error("STARTTLS should not be advertised with implicit TLS")
		}
	}
}

// =============================================================================
// TLS Connection State Tests
// =============================================================================

func TestServer_TLS_IsTLSContext(t *testing.T) {
	cert, certPool := generateTestCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	var isTLS bool
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.TLS(tlsConfig)
		s.OnMailFrom(func(c *Context) *Response {
			mu.Lock()
			isTLS = c.Connection.IsTLS()
			mu.Unlock()
			return c.Next()
		})
	})
	defer ts.Close()

	// Connect and upgrade to TLS
	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	reader.ReadString('\n') // greeting

	conn.Write([]byte("EHLO client.test\r\n"))
	for {
		line, _ := reader.ReadString('\n')
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	conn.Write([]byte("STARTTLS\r\n"))
	reader.ReadString('\n')

	clientTLSConfig := &tls.Config{
		RootCAs:    certPool,
		ServerName: "test.example.com",
	}
	tlsConn := tls.Client(conn, clientTLSConfig)
	tlsConn.Handshake()
	tlsReader := bufio.NewReader(tlsConn)

	tlsConn.Write([]byte("EHLO client.test\r\n"))
	for {
		line, _ := tlsReader.ReadString('\n')
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	tlsConn.Write([]byte("MAIL FROM:<sender@example.com>\r\n"))
	tlsReader.ReadString('\n')

	mu.Lock()
	if !isTLS {
		t.Error("expected IsTLS to be true after STARTTLS")
	}
	mu.Unlock()
}

func TestServer_TLS_IsTLSContext_WithoutTLS(t *testing.T) {
	var isTLS bool
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.OnMailFrom(func(c *Context) *Response {
			mu.Lock()
			isTLS = c.Connection.IsTLS()
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
	if isTLS {
		t.Error("expected IsTLS to be false without TLS")
	}
	mu.Unlock()
}

// =============================================================================
// REQUIRETLS Extension Tests
// =============================================================================

func TestServer_REQUIRETLS_Advertised(t *testing.T) {
	cert, certPool := generateTestCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	ts := newTestServer(t, func(s *Server) {
		s.TLS(tlsConfig)
	})
	defer ts.Close()

	// Connect and upgrade to TLS
	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	reader.ReadString('\n') // greeting

	conn.Write([]byte("EHLO client.test\r\n"))
	for {
		line, _ := reader.ReadString('\n')
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	conn.Write([]byte("STARTTLS\r\n"))
	reader.ReadString('\n')

	clientTLSConfig := &tls.Config{
		RootCAs:    certPool,
		ServerName: "test.example.com",
	}
	tlsConn := tls.Client(conn, clientTLSConfig)
	tlsConn.Handshake()
	tlsReader := bufio.NewReader(tlsConn)

	tlsConn.Write([]byte("EHLO client.test\r\n"))
	var lines []string
	for {
		line, _ := tlsReader.ReadString('\n')
		lines = append(lines, line)
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// REQUIRETLS should be advertised after TLS upgrade
	requireTLSFound := false
	for _, line := range lines {
		if strings.Contains(line, "REQUIRETLS") {
			requireTLSFound = true
			break
		}
	}
	if !requireTLSFound {
		t.Error("REQUIRETLS should be advertised after TLS upgrade")
	}
}

func TestServer_REQUIRETLS_Parameter(t *testing.T) {
	cert, certPool := generateTestCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	var requireTLSFlag bool
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.TLS(tlsConfig)
		s.OnMessage(func(c *Context) *Response {
			mu.Lock()
			requireTLSFlag = c.Mail.Envelope.RequireTLS
			mu.Unlock()
			return c.Next()
		})
	})
	defer ts.Close()

	// Connect and upgrade to TLS
	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	reader.ReadString('\n') // greeting

	conn.Write([]byte("EHLO client.test\r\n"))
	for {
		line, _ := reader.ReadString('\n')
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	conn.Write([]byte("STARTTLS\r\n"))
	reader.ReadString('\n')

	clientTLSConfig := &tls.Config{
		RootCAs:    certPool,
		ServerName: "test.example.com",
	}
	tlsConn := tls.Client(conn, clientTLSConfig)
	tlsConn.Handshake()
	tlsReader := bufio.NewReader(tlsConn)

	tlsConn.Write([]byte("EHLO client.test\r\n"))
	for {
		line, _ := tlsReader.ReadString('\n')
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// Use REQUIRETLS parameter
	tlsConn.Write([]byte("MAIL FROM:<sender@example.com> REQUIRETLS\r\n"))
	line, _ := tlsReader.ReadString('\n')
	if !strings.HasPrefix(line, "250") {
		t.Fatalf("MAIL FROM with REQUIRETLS failed: %s", line)
	}

	tlsConn.Write([]byte("RCPT TO:<recipient@example.com>\r\n"))
	tlsReader.ReadString('\n')

	tlsConn.Write([]byte("DATA\r\n"))
	tlsReader.ReadString('\n')

	tlsConn.Write([]byte("Subject: Test\r\n\r\nBody\r\n.\r\n"))
	tlsReader.ReadString('\n')

	mu.Lock()
	if !requireTLSFlag {
		t.Error("expected RequireTLS envelope flag to be set")
	}
	mu.Unlock()
}

func TestServer_REQUIRETLS_RejectedWithoutTLS(t *testing.T) {
	cert, _ := generateTestCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	ts := newTestServer(t, func(s *Server) {
		s.TLS(tlsConfig)
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	// Try REQUIRETLS without TLS connection
	client.Send("MAIL FROM:<sender@example.com> REQUIRETLS")
	client.ExpectCode(554) // REQUIRETLS requires TLS
}
