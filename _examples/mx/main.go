// Command mx demonstrates a Mail Exchanger (MX) / Mail Delivery Agent (MDA)
// that receives messages on port 25, runs the full SPF, DKIM, DMARC, and ARC
// authentication pipeline, and logs the results.
//
// This is the pattern for an inbound mail gateway or mailbox delivery agent.
//
// Usage:
//
//	go run . -domain mx.example.com -addr :2525
package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"

	"github.com/synqronlabs/raven/arc"
	"github.com/synqronlabs/raven/dkim"
	"github.com/synqronlabs/raven/dmarc"
	"github.com/synqronlabs/raven/dns"
	ravenmail "github.com/synqronlabs/raven/mail"
	"github.com/synqronlabs/raven/server"
	"github.com/synqronlabs/raven/spf"
)

func main() {
	domain := flag.String("domain", "mx.example.com", "Server domain (for greeting)")
	addr := flag.String("addr", ":2525", "Listen address")
	flag.Parse()

	resolver := dns.NewResolver(dns.ResolverConfig{DNSSEC: true})
	spfResolver := spf.NewResolverWithDefaults()

	backend := &MXBackend{
		domain:      *domain,
		resolver:    resolver,
		spfResolver: spfResolver,
	}

	srv := server.NewServer(backend, server.ServerConfig{
		Domain:          *domain,
		Addr:            *addr,
		MaxMessageBytes: 50 * 1024 * 1024,
		MaxRecipients:   1000,
		EnableSMTPUTF8:  true,
	})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	log.Printf("MX server listening on %s for domain %s", *addr, *domain)
	if err := srv.ListenAndServe(ctx); err != nil && err != server.ErrServerClosed {
		log.Fatal(err)
	}
}

// MXBackend creates sessions that perform authentication checks on inbound mail.
type MXBackend struct {
	domain      string
	resolver    dns.Resolver
	spfResolver spf.Resolver
}

func (b *MXBackend) NewSession(c *server.Conn) (server.Session, error) {
	remoteIP := extractIP(c.RemoteAddr())
	log.Printf("Inbound connection from %s", c.RemoteAddr())
	return &MXSession{
		backend:  b,
		conn:     c,
		remoteIP: remoteIP,
	}, nil
}

// MXSession performs SPF, DKIM, DMARC, and ARC checks on each inbound message.
type MXSession struct {
	backend  *MXBackend
	conn     *server.Conn
	remoteIP net.IP
	from     string
	to       []string
}

func (s *MXSession) Mail(from string, opts *server.MailOptions) error {
	s.from = from
	log.Printf("MAIL FROM: %s (remote=%s)", from, s.remoteIP)
	return nil
}

func (s *MXSession) Rcpt(to string, opts *server.RcptOptions) error {
	s.to = append(s.to, to)
	log.Printf("RCPT TO: %s", to)
	return nil
}

// Data runs the full authentication pipeline and decides whether to accept.
func (s *MXSession) Data(r io.Reader) error {
	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	log.Printf("Received %d bytes from %s for %v", len(body), s.from, s.to)

	ctx := s.conn.Context()

	// Reconstruct a Mail object for convenience wrappers.
	msg := ravenmail.NewMail()
	fromAddr, _ := ravenmail.ParseAddress(s.from)
	msg.SetFrom(fromAddr)
	for _, rcpt := range s.to {
		addr, parseErr := ravenmail.ParseAddress(rcpt)
		if parseErr != nil {
			continue
		}
		msg.AddRecipient(addr)
	}
	msg.Content.Body = body

	// --- SPF ---
	mailFromDomain := domainOf(s.from)
	spfReceived, spfDomain, spfExplanation, spfAuthentic, spfErr := spf.Verify(
		ctx, s.backend.spfResolver, spf.Args{
			RemoteIP:       s.remoteIP,
			MailFromDomain: mailFromDomain,
			HelloDomain:    s.conn.Hostname,
			LocalHostname:  s.backend.domain,
		})
	if spfErr != nil {
		log.Printf("SPF error: %v", spfErr)
	}
	log.Printf("SPF: %s domain=%s authentic=%v explanation=%q",
		spfReceived.Result, spfDomain, spfAuthentic, spfExplanation)

	// --- DKIM ---
	dkimResults, dkimErr := dkim.VerifyMailContext(ctx, msg, s.backend.resolver)
	if dkimErr != nil {
		log.Printf("DKIM error: %v", dkimErr)
	}
	for _, dr := range dkimResults {
		sig := dr.Signature
		if sig != nil {
			log.Printf("DKIM: %s (d=%s s=%s)", dr.Status, sig.Domain, sig.Selector)
		} else {
			log.Printf("DKIM: %s", dr.Status)
		}
	}

	// --- DMARC ---
	dmarcResult, useResult, dmarcErr := dmarc.VerifyMailObject(
		ctx, s.backend.resolver, msg, dmarc.MailVerifyArgs{
			SPFResult:             spfReceived.Result,
			SPFDomain:             spfDomain,
			DKIMResults:           dkimResults,
			ApplyRandomPercentage: true,
		})
	if dmarcErr != nil {
		log.Printf("DMARC error: %v", dmarcErr)
	}
	log.Printf("DMARC: status=%s reject=%v use=%v aligned_spf=%v aligned_dkim=%v",
		dmarcResult.Status, dmarcResult.Reject, useResult,
		dmarcResult.AlignedSPFPass, dmarcResult.AlignedDKIMPass)

	// --- ARC ---
	arcResult, arcErr := arc.VerifyMailContext(ctx, msg, s.backend.resolver)
	if arcErr != nil {
		log.Printf("ARC error: %v", arcErr)
	}
	if arcResult != nil {
		log.Printf("ARC: status=%s oldest_pass=%d", arcResult.Status, arcResult.OldestPass)
	}

	// --- Policy decision ---
	if useResult && dmarcResult.Reject {
		log.Printf("REJECTING message per DMARC policy")
		return &server.SMTPError{
			Code:         550,
			EnhancedCode: server.EnhancedCode{5, 7, 1},
			Message:      "Message rejected per DMARC policy",
		}
	}

	log.Println("Message accepted for delivery")
	// In a real MDA, queue to mailbox storage here.
	return nil
}

func (s *MXSession) Reset() {
	s.from = ""
	s.to = nil
}

func (s *MXSession) Logout() error {
	log.Printf("Client disconnected: %s", s.conn.RemoteAddr())
	return nil
}

// extractIP pulls the IP from a net.Addr (strips the port).
func extractIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return net.ParseIP(addr.String())
	}
	return net.ParseIP(host)
}

// domainOf returns the domain part of an email address.
func domainOf(address string) string {
	parts := strings.SplitN(address, "@", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return address
}
