package raven

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"
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
	address := fmt.Sprintf("%s:%d", d.Host, d.Port)

	// Connect
	var err error
	if d.SSL {
		err = client.DialTLSContext(ctx, address)
	} else {
		err = client.DialContext(ctx, address)
	}
	if err != nil {
		return nil, err
	}

	// EHLO
	if err := client.Hello(); err != nil {
		client.Close()
		return nil, err
	}

	// STARTTLS if requested
	if d.StartTLS && !d.SSL {
		if client.HasExtension(ExtSTARTTLS) {
			if err := client.StartTLS(); err != nil {
				client.Close()
				return nil, err
			}
			// EHLO again after STARTTLS
			if err := client.Hello(); err != nil {
				client.Close()
				return nil, err
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
			return nil, err
		}
	}

	return client, nil
}

// DialAndSend is a convenience method that connects, sends a message, and disconnects.
func (d *Dialer) DialAndSend(mail *Mail) (*SendResult, error) {
	client, err := d.Dial()
	if err != nil {
		return nil, err
	}
	defer client.Quit()

	return client.Send(mail)
}

// DialAndSendMultiple sends multiple messages in a single connection.
func (d *Dialer) DialAndSendMultiple(mails []*Mail) ([]*SendResult, error) {
	client, err := d.Dial()
	if err != nil {
		return nil, err
	}
	defer client.Quit()

	return client.SendMultiple(mails)
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
		client.Quit()
	}
}

// Send sends a message using a pooled connection.
func (p *Pool) Send(mail *Mail) (*SendResult, error) {
	client, err := p.Get()
	if err != nil {
		return nil, err
	}

	result, err := client.Send(mail)
	if err != nil {
		// Error occurred, close this connection
		client.Close()
		return result, err
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
		client.Quit()
	}

	return nil
}

// QuickSend is a convenience function for sending a single email.
// It handles all connection setup and teardown automatically.
//
// Example:
//
//	err := raven.QuickSend(
//	    "smtp.example.com:587",
//	    &raven.ClientAuth{Username: "user", Password: "pass"},
//	    "sender@example.com",
//	    []string{"recipient@example.com"},
//	    "Subject",
//	    "Body text",
//	)
func QuickSend(address string, auth *ClientAuth, from string, to []string, subject, body string) error {
	builder := NewMailBuilder().
		From(from).
		Subject(subject).
		TextBody(body)

	for _, addr := range to {
		builder.To(addr)
	}

	mail, err := builder.Build()
	if err != nil {
		return err
	}

	config := DefaultClientConfig()
	config.Auth = auth

	client := NewClient(config)

	if err := client.Dial(address); err != nil {
		return err
	}
	defer client.Close()

	if err := client.Hello(); err != nil {
		return err
	}

	// Try STARTTLS if available
	if client.HasExtension(ExtSTARTTLS) {
		if err := client.StartTLS(); err != nil {
			return err
		}
		if err := client.Hello(); err != nil {
			return err
		}
	}

	if auth != nil {
		if err := client.Auth(); err != nil {
			return err
		}
	}

	_, err = client.Send(mail)
	if err != nil {
		return err
	}

	return client.Quit()
}

// QuickSendTLS is like QuickSend but uses implicit TLS (port 465).
func QuickSendTLS(address string, auth *ClientAuth, from string, to []string, subject, body string) error {
	builder := NewMailBuilder().
		From(from).
		Subject(subject).
		TextBody(body)

	for _, addr := range to {
		builder.To(addr)
	}

	mail, err := builder.Build()
	if err != nil {
		return err
	}

	config := DefaultClientConfig()
	config.Auth = auth

	client := NewClient(config)

	if err := client.DialTLS(address); err != nil {
		return err
	}
	defer client.Close()

	if err := client.Hello(); err != nil {
		return err
	}

	if auth != nil {
		if err := client.Auth(); err != nil {
			return err
		}
	}

	_, err = client.Send(mail)
	if err != nil {
		return err
	}

	return client.Quit()
}

// QuickSendMail is a convenience function for sending a pre-built Mail object.
func QuickSendMail(address string, auth *ClientAuth, mail *Mail) error {
	config := DefaultClientConfig()
	config.Auth = auth

	client := NewClient(config)

	if err := client.Dial(address); err != nil {
		return err
	}
	defer client.Close()

	if err := client.Hello(); err != nil {
		return err
	}

	if client.HasExtension(ExtSTARTTLS) {
		if err := client.StartTLS(); err != nil {
			return err
		}
		if err := client.Hello(); err != nil {
			return err
		}
	}

	if auth != nil {
		if err := client.Auth(); err != nil {
			return err
		}
	}

	_, err := client.Send(mail)
	if err != nil {
		return err
	}

	return client.Quit()
}
