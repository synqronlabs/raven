package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	ravenmail "github.com/synqronlabs/raven/mail"
)

// Dialer provides methods for establishing SMTP connections.
type Dialer struct {
	Host               string
	Port               int
	LocalAddr          string // Local address to bind to
	TLSConfig          *tls.Config
	Auth               *ClientAuth
	LocalName          string
	ConnectTimeout     time.Duration
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
	ValidateBeforeSend bool // Validate email content before sending
	SSL                bool // Implicit TLS (port 465)
	StartTLS           bool
	RequireTLS         bool
	Debug              bool
}

// NewDialer creates a new Dialer with sensible defaults.
func NewDialer(host string, port int) *Dialer {
	return &Dialer{
		Host:           host,
		Port:           port,
		ConnectTimeout: 30 * time.Second,
		ReadTimeout:    5 * time.Minute,
		WriteTimeout:   5 * time.Minute,
	}
}

// Dial establishes a new connection to the SMTP server.
func (d *Dialer) Dial() (*Client, error) {
	return d.DialContext(context.Background())
}

// DialContext establishes a new connection with context support.
func (d *Dialer) DialContext(ctx context.Context) (*Client, error) {
	config := &ClientConfig{
		LocalName:          d.LocalName,
		LocalAddr:          d.LocalAddr,
		TLSConfig:          d.TLSConfig,
		Auth:               d.Auth,
		ConnectTimeout:     d.ConnectTimeout,
		ReadTimeout:        d.ReadTimeout,
		WriteTimeout:       d.WriteTimeout,
		ValidateBeforeSend: d.ValidateBeforeSend,
		Debug:              d.Debug,
	}

	if config.LocalName == "" {
		config.LocalName = "localhost"
	}

	client := NewClient(config)
	address := net.JoinHostPort(d.Host, fmt.Sprintf("%d", d.Port))

	// Connect
	var err error
	if d.SSL {
		err = client.DialTLSContext(ctx, address)
	} else {
		err = client.DialContext(ctx, address)
	}
	if err != nil {
		return nil, fmt.Errorf("dialing SMTP server %s: %w", address, err)
	}

	// EHLO
	if err := client.Hello(); err != nil {
		client.Close()
		return nil, fmt.Errorf("initializing SMTP session with EHLO/HELO: %w", err)
	}

	// STARTTLS if requested
	if d.StartTLS && !d.SSL {
		if client.HasExtension(ravenmail.ExtSTARTTLS) {
			if err := client.StartTLS(); err != nil {
				client.Close()
				return nil, fmt.Errorf("upgrading SMTP session with STARTTLS: %w", err)
			}
			// EHLO again after STARTTLS
			if err := client.Hello(); err != nil {
				client.Close()
				return nil, fmt.Errorf("re-initializing SMTP session after STARTTLS: %w", err)
			}
		} else if d.RequireTLS {
			client.Close()
			return nil, ErrTLSNotSupported
		}
	}

	// Authenticate if credentials provided
	if d.Auth != nil {
		if err := client.Auth(); err != nil {
			client.Close()
			return nil, fmt.Errorf("authenticating SMTP session: %w", err)
		}
	}

	return client, nil
}

// DialAndSend is a convenience method that connects, sends a message, and disconnects.
func (d *Dialer) DialAndSend(mail *ravenmail.Mail) (*SendResult, error) {
	client, err := d.Dial()
	if err != nil {
		return nil, fmt.Errorf("dialing before send: %w", err)
	}

	result, err := client.Send(mail)
	quitErr := client.Quit()
	if err != nil {
		if quitErr != nil {
			return result, fmt.Errorf("sending mail in dial-and-send flow: %w", errors.Join(err, fmt.Errorf("closing SMTP session: %w", quitErr)))
		}
		return result, fmt.Errorf("sending mail in dial-and-send flow: %w", err)
	}
	if quitErr != nil {
		return result, fmt.Errorf("closing SMTP session after send: %w", quitErr)
	}
	return result, nil
}

// DialAndSendMultiple sends multiple messages in a single connection.
func (d *Dialer) DialAndSendMultiple(mails []*ravenmail.Mail) ([]*SendResult, error) {
	client, err := d.Dial()
	if err != nil {
		return nil, fmt.Errorf("dialing before multi-send: %w", err)
	}

	results, err := client.SendMultiple(mails)
	quitErr := client.Quit()
	if err != nil {
		if quitErr != nil {
			return results, fmt.Errorf("sending multiple mails in one session: %w", errors.Join(err, fmt.Errorf("closing SMTP session: %w", quitErr)))
		}
		return results, fmt.Errorf("sending multiple mails in one session: %w", err)
	}
	if quitErr != nil {
		return results, fmt.Errorf("closing SMTP session after multi-send: %w", quitErr)
	}
	return results, nil
}

// Pool manages a pool of SMTP connections for efficient sending.
type Pool struct {
	dialer *Dialer
	mu     sync.Mutex
	conns  chan *Client
	size   int
	closed bool
}

// NewPool creates a new connection pool.
func NewPool(dialer *Dialer, size int) *Pool {
	if size <= 0 {
		size = 5
	}
	return &Pool{
		dialer: dialer,
		conns:  make(chan *Client, size),
		size:   size,
	}
}

// Get retrieves a connection from the pool, creating one if necessary.
func (p *Pool) Get() (*Client, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrClientClosed
	}
	p.mu.Unlock()

	// Try to get an existing connection
	select {
	case client := <-p.conns:
		// Verify connection is still valid
		if err := client.Noop(); err == nil {
			return client, nil
		}
		// Connection is dead, close it and create new one
		client.Close()
	default:
		// No available connections
	}

	// Create new connection
	return p.dialer.Dial()
}

// Put returns a connection to the pool.
func (p *Pool) Put(client *Client) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		client.Close()
		return
	}
	p.mu.Unlock()

	// Try to return to pool
	select {
	case p.conns <- client:
		// Returned to pool
	default:
		// Pool full, close connection
		if err := client.Quit(); err != nil {
			if closeErr := client.Close(); closeErr != nil {
				_ = closeErr
			}
		}
	}
}

// Send sends a message using a pooled connection.
func (p *Pool) Send(mail *ravenmail.Mail) (*SendResult, error) {
	client, err := p.Get()
	if err != nil {
		return nil, fmt.Errorf("getting SMTP client from pool: %w", err)
	}

	result, err := client.Send(mail)
	if err != nil {
		// Error occurred, close this connection
		client.Close()
		return result, fmt.Errorf("sending mail with pooled client: %w", err)
	}

	// Return connection to pool
	p.Put(client)
	return result, nil
}

// Close closes the pool and all connections.
func (p *Pool) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()

	close(p.conns)

	for client := range p.conns {
		if err := client.Quit(); err != nil {
			if closeErr := client.Close(); closeErr != nil {
				_ = closeErr
			}
		}
	}

	return nil
}

// QuickSend is a convenience function for sending a single email.
// It handles all connection setup and teardown automatically.
//
// Example:
//
//	err := client.QuickSend(
//	    "smtp.example.com:587",
//	    &client.ClientAuth{Username: "user", Password: "pass"},
//	    "sender@example.com",
//	    []string{"recipient@example.com"},
//	    "Subject",
//	    "Body text",
//	)
func QuickSend(address string, auth *ClientAuth, from string, to []string, subject, body string) error {
	builder := ravenmail.NewMailBuilder().
		From(from).
		Subject(subject).
		TextBody(body)

	for _, addr := range to {
		builder.To(addr)
	}

	mail, err := builder.Build()
	if err != nil {
		return fmt.Errorf("building mail message: %w", err)
	}

	config := DefaultClientConfig()
	config.Auth = auth

	client := NewClient(config)

	if err := client.Dial(address); err != nil {
		return fmt.Errorf("dialing SMTP server %s: %w", address, err)
	}
	defer client.Close()

	if err := client.Hello(); err != nil {
		return fmt.Errorf("initializing SMTP session with EHLO/HELO: %w", err)
	}

	// Try STARTTLS if available
	if client.HasExtension(ravenmail.ExtSTARTTLS) {
		if err := client.StartTLS(); err != nil {
			return fmt.Errorf("upgrading SMTP session with STARTTLS: %w", err)
		}
		if err := client.Hello(); err != nil {
			return fmt.Errorf("re-initializing SMTP session after STARTTLS: %w", err)
		}
	}

	if auth != nil {
		if err := client.Auth(); err != nil {
			return fmt.Errorf("authenticating SMTP session: %w", err)
		}
	}

	_, err = client.Send(mail)
	if err != nil {
		return fmt.Errorf("sending mail message: %w", err)
	}

	if err := client.Quit(); err != nil {
		return fmt.Errorf("closing SMTP session with QUIT: %w", err)
	}
	return nil
}

// QuickSendTLS is like QuickSend but uses implicit TLS (port 465).
func QuickSendTLS(address string, auth *ClientAuth, from string, to []string, subject, body string) error {
	builder := ravenmail.NewMailBuilder().
		From(from).
		Subject(subject).
		TextBody(body)

	for _, addr := range to {
		builder.To(addr)
	}

	mail, err := builder.Build()
	if err != nil {
		return fmt.Errorf("building mail message: %w", err)
	}

	config := DefaultClientConfig()
	config.Auth = auth

	client := NewClient(config)

	if err := client.DialTLS(address); err != nil {
		return fmt.Errorf("dialing SMTP server %s with implicit TLS: %w", address, err)
	}
	defer client.Close()

	if err := client.Hello(); err != nil {
		return fmt.Errorf("initializing SMTP session with EHLO/HELO: %w", err)
	}

	if auth != nil {
		if err := client.Auth(); err != nil {
			return fmt.Errorf("authenticating SMTP session: %w", err)
		}
	}

	_, err = client.Send(mail)
	if err != nil {
		return fmt.Errorf("sending mail message: %w", err)
	}

	if err := client.Quit(); err != nil {
		return fmt.Errorf("closing SMTP session with QUIT: %w", err)
	}
	return nil
}

// QuickSendMail is a convenience function for sending a pre-built Mail object.
func QuickSendMail(address string, auth *ClientAuth, mail *ravenmail.Mail) error {
	config := DefaultClientConfig()
	config.Auth = auth

	client := NewClient(config)

	if err := client.Dial(address); err != nil {
		return fmt.Errorf("dialing SMTP server %s: %w", address, err)
	}
	defer client.Close()

	if err := client.Hello(); err != nil {
		return fmt.Errorf("initializing SMTP session with EHLO/HELO: %w", err)
	}

	if client.HasExtension(ravenmail.ExtSTARTTLS) {
		if err := client.StartTLS(); err != nil {
			return fmt.Errorf("upgrading SMTP session with STARTTLS: %w", err)
		}
		if err := client.Hello(); err != nil {
			return fmt.Errorf("re-initializing SMTP session after STARTTLS: %w", err)
		}
	}

	if auth != nil {
		if err := client.Auth(); err != nil {
			return fmt.Errorf("authenticating SMTP session: %w", err)
		}
	}

	_, err := client.Send(mail)
	if err != nil {
		return fmt.Errorf("sending mail message: %w", err)
	}

	if err := client.Quit(); err != nil {
		return fmt.Errorf("closing SMTP session with QUIT: %w", err)
	}
	return nil
}
