// Command msa demonstrates a Mail Submission Agent that accepts messages from
// authenticated users on port 587 with STARTTLS, DKIM-signs them, and relays
// to the recipient's MX server.
//
// This shows how to combine the server, dkim, and client packages into a
// realistic submission pipeline.
//
// Usage:
//
//	go run . -domain example.com -addr :587 -selector sel1 -key dkim-private.pem
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"

	"github.com/synqronlabs/raven/client"
	"github.com/synqronlabs/raven/dkim"
	ravenmail "github.com/synqronlabs/raven/mail"
	"github.com/synqronlabs/raven/sasl"
	"github.com/synqronlabs/raven/server"
)

func main() {
	domain := flag.String("domain", "example.com", "Server domain")
	addr := flag.String("addr", ":587", "Listen address")
	selector := flag.String("selector", "sel1", "DKIM selector")
	keyPath := flag.String("key", "", "Path to DKIM private key (PEM)")
	relayHost := flag.String("relay", "", "Downstream MX host (if empty, logs only)")
	relayPort := flag.Int("relay-port", 25, "Downstream MX port")
	flag.Parse()

	var privKey crypto.Signer
	if *keyPath != "" {
		var err error
		privKey, err = loadPrivateKey(*keyPath)
		if err != nil {
			log.Fatalf("loading DKIM key: %v", err)
		}
	}

	backend := &MSABackend{
		domain:    *domain,
		selector:  *selector,
		privKey:   privKey,
		relayHost: *relayHost,
		relayPort: *relayPort,
	}

	srv := server.NewServer(backend, server.ServerConfig{
		Domain:            *domain,
		Addr:              *addr,
		AllowInsecureAuth: true, // For demo only; use TLSConfig in production
		MaxMessageBytes:   25 * 1024 * 1024,
		MaxRecipients:     100,
	})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	log.Printf("MSA listening on %s for domain %s", *addr, *domain)
	if err := srv.ListenAndServe(ctx); err != nil && err != server.ErrServerClosed {
		log.Fatal(err)
	}
}

// MSABackend creates sessions for authenticated submission.
type MSABackend struct {
	domain    string
	selector  string
	privKey   crypto.Signer
	relayHost string
	relayPort int
}

func (b *MSABackend) NewSession(c *server.Conn) (server.Session, error) {
	log.Printf("New connection from %s", c.RemoteAddr())
	return &MSASession{backend: b, conn: c}, nil
}

// MSASession handles a single submission transaction.
// It implements both server.Session and server.AuthSession.
type MSASession struct {
	backend *MSABackend
	conn    *server.Conn
	from    string
	to      []string
}

// AuthMechanisms advertises supported SASL mechanisms.
func (s *MSASession) AuthMechanisms() []string {
	return []string{"PLAIN", "LOGIN"}
}

// Auth returns a sasl.Server for the requested mechanism.
// In production, replace the credential check with a real backend.
func (s *MSASession) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case "PLAIN":
		return &plainAuthServer{}, nil
	case "LOGIN":
		return &loginAuthServer{}, nil
	default:
		return nil, fmt.Errorf("unsupported mechanism: %s", mech)
	}
}

// plainAuthServer implements sasl.Server for PLAIN authentication.
type plainAuthServer struct {
	done bool
}

func (s *plainAuthServer) Next(response []byte) (challenge []byte, done bool, err error) {
	if s.done {
		return nil, true, fmt.Errorf("unexpected data after auth")
	}
	if len(response) == 0 {
		// Request initial response
		return nil, false, nil
	}
	// PLAIN format: authzid\0authcid\0password
	parts := bytes.SplitN(response, []byte{0}, 3)
	if len(parts) != 3 {
		s.done = true
		return nil, true, fmt.Errorf("invalid PLAIN format")
	}
	user := string(parts[1])
	// TODO: replace with real credential verification
	log.Printf("AUTH PLAIN: user=%q", user)
	s.done = true
	return nil, true, nil
}

// loginAuthServer implements sasl.Server for LOGIN authentication.
// LOGIN is a challenge-response mechanism: server sends "Username:" then "Password:".
type loginAuthServer struct {
	step     int
	username string
}

func (s *loginAuthServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch s.step {
	case 0:
		// Send "Username:" challenge
		s.step = 1
		return []byte("Username:"), false, nil
	case 1:
		// Received username, send "Password:" challenge
		s.username = string(response)
		s.step = 2
		return []byte("Password:"), false, nil
	case 2:
		// Received password — authentication complete
		// TODO: replace with real credential verification
		log.Printf("AUTH LOGIN: user=%q", s.username)
		return nil, true, nil
	default:
		return nil, true, fmt.Errorf("unexpected LOGIN state")
	}
}

func (s *MSASession) Mail(from string, opts *server.MailOptions) error {
	if !s.conn.Authenticated() {
		return &server.SMTPError{
			Code:         530,
			EnhancedCode: server.EnhancedCode{5, 7, 0},
			Message:      "Authentication required",
		}
	}
	s.from = from
	log.Printf("MAIL FROM: %s", from)
	return nil
}

func (s *MSASession) Rcpt(to string, opts *server.RcptOptions) error {
	s.to = append(s.to, to)
	log.Printf("RCPT TO: %s", to)
	return nil
}

// Data receives the message, DKIM-signs it, and optionally relays downstream.
func (s *MSASession) Data(r io.Reader) error {
	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	log.Printf("Received %d bytes from %s for %v", len(body), s.from, s.to)

	// Build a Mail object for signing / relaying.
	msg := ravenmail.NewMail()
	fromAddr, err := ravenmail.ParseAddress(s.from)
	if err != nil {
		return err
	}
	msg.SetFrom(fromAddr)
	for _, rcpt := range s.to {
		addr, err := ravenmail.ParseAddress(rcpt)
		if err != nil {
			return err
		}
		msg.AddRecipient(addr)
	}
	msg.Content.Body = body

	// DKIM-sign if a key was provided.
	if s.backend.privKey != nil {
		if err := dkim.QuickSign(msg, s.backend.domain, s.backend.selector, s.backend.privKey); err != nil {
			log.Printf("DKIM sign error: %v", err)
			// Non-fatal for this demo; production should decide per policy.
		} else {
			log.Printf("DKIM signed (d=%s s=%s)", s.backend.domain, s.backend.selector)
		}
	}

	// Relay downstream or just log.
	if s.backend.relayHost != "" {
		return s.relay(msg)
	}
	log.Println("No relay host configured - message accepted and discarded")
	return nil
}

func (s *MSASession) relay(msg *ravenmail.Mail) error {
	dialer := client.NewDialer(s.backend.relayHost, s.backend.relayPort)
	dialer.StartTLS = true
	result, err := dialer.DialAndSend(msg)
	if err != nil {
		return fmt.Errorf("relay failed: %w", err)
	}
	log.Printf("Relayed: success=%v messageID=%s", result.Success, result.MessageID)
	return nil
}

func (s *MSASession) Reset() {
	s.from = ""
	s.to = nil
}

func (s *MSASession) Logout() error {
	log.Printf("Client disconnected: %s", s.conn.RemoteAddr())
	return nil
}

func loadPrivateKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported key type in %s", path)
}
