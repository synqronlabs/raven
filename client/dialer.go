package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
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
		_ = client.Close()
		return nil, fmt.Errorf("initializing SMTP session with EHLO/HELO: %w", err)
	}

	// STARTTLS if requested
	if d.StartTLS && !d.SSL {
		if client.HasExtension(ravenmail.ExtSTARTTLS) {
			if err := client.StartTLS(); err != nil {
				_ = client.Close()
				return nil, fmt.Errorf("upgrading SMTP session with STARTTLS: %w", err)
			}
			// EHLO again after STARTTLS
			if err := client.Hello(); err != nil {
				_ = client.Close()
				return nil, fmt.Errorf("re-initializing SMTP session after STARTTLS: %w", err)
			}
		} else if d.RequireTLS {
			_ = client.Close()
			return nil, ErrTLSNotSupported
		}
	}

	// Authenticate if credentials provided
	if d.Auth != nil {
		if err := client.Auth(); err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("authenticating SMTP session: %w", err)
		}
	}

	return client, nil
}

// DialAndSend is a convenience method that connects, sends a message, and disconnects.
//
// Deprecated: Use Dial and reuse the returned Client, or use Pool. Opening one
// SMTP connection per message is inefficient for server workloads.
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

// DialAndSendRaw connects, streams a raw RFC 5322 message, and disconnects.
//
// Deprecated: Use Dial and reuse Client.SendRaw, or use Pool.SendRaw. Opening
// one SMTP connection per message is inefficient for server workloads.
func (d *Dialer) DialAndSendRaw(envelope ravenmail.Envelope, data io.Reader) (*SendResult, error) {
	client, err := d.Dial()
	if err != nil {
		return nil, fmt.Errorf("dialing before raw send: %w", err)
	}

	result, err := client.SendRaw(envelope, data)
	quitErr := client.Quit()
	if err != nil {
		if quitErr != nil {
			return result, fmt.Errorf("sending raw mail in dial-and-send flow: %w", errors.Join(err, fmt.Errorf("closing SMTP session: %w", quitErr)))
		}
		return result, fmt.Errorf("sending raw mail in dial-and-send flow: %w", err)
	}
	if quitErr != nil {
		return result, fmt.Errorf("closing SMTP session after raw send: %w", quitErr)
	}
	return result, nil
}

// DialAndSendMultiple sends multiple messages in a single connection.
//
// Deprecated: Dial once and call Send or SendRaw for each queued message. This
// avoids retaining the entire batch and its result slice in memory.
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

// DialAndSendRawMultiple streams multiple raw messages in a single connection.
//
// Deprecated: Dial once and call SendRaw for each queued message so messages
// and results can be released incrementally.
func (d *Dialer) DialAndSendRawMultiple(messages []RawMessage) ([]*SendResult, error) {
	client, err := d.Dial()
	if err != nil {
		return nil, fmt.Errorf("dialing before raw multi-send: %w", err)
	}

	results, err := client.SendRawMultiple(messages)
	quitErr := client.Quit()
	if err != nil {
		if quitErr != nil {
			return results, fmt.Errorf("sending multiple raw mails in one session: %w", errors.Join(err, fmt.Errorf("closing SMTP session: %w", quitErr)))
		}
		return results, fmt.Errorf("sending multiple raw mails in one session: %w", err)
	}
	if quitErr != nil {
		return results, fmt.Errorf("closing SMTP session after raw multi-send: %w", quitErr)
	}
	return results, nil
}

type poolClientState uint8

const (
	poolClientCheckedOut poolClientState = iota
	poolClientIdle
)

// Pool manages a bounded pool of SMTP connections for efficient sending.
// Its size limits all live connections, including checked-out connections.
type Pool struct {
	dialer *Dialer
	mu     sync.Mutex
	conns  chan *Client
	slots  chan struct{}
	done   chan struct{}
	owned  map[*Client]poolClientState
	size   int
	closed bool
}

// NewPool creates a connection pool with at most size live connections.
func NewPool(dialer *Dialer, size int) *Pool {
	if size <= 0 {
		size = 5
	}
	p := &Pool{
		dialer: dialer,
		conns:  make(chan *Client, size),
		slots:  make(chan struct{}, size),
		done:   make(chan struct{}),
		owned:  make(map[*Client]poolClientState, size),
		size:   size,
	}
	for range size {
		p.slots <- struct{}{}
	}
	return p
}

// Get retrieves a connection from the pool, waiting when all connections are
// checked out. Close wakes blocked callers with ErrClientClosed.
func (p *Pool) Get() (*Client, error) {
	return p.GetContext(context.Background())
}

// GetContext retrieves a connection from the pool, waiting for capacity when
// necessary. Cancellation affects capacity waiting and dialing. Health checks
// on reused connections and subsequent SMTP operations use the Client's
// configured timeouts.
func (p *Pool) GetContext(ctx context.Context) (*Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// Prefer an already established idle connection over consuming capacity
		// for a new dial.
		select {
		case client := <-p.conns:
			if reused, err := p.reuse(client); err != nil || reused != nil {
				return reused, err
			}
			continue
		default:
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.done:
			return nil, ErrClientClosed
		case client := <-p.conns:
			if reused, err := p.reuse(client); err != nil || reused != nil {
				return reused, err
			}
		case <-p.slots:
			// An idle connection may have been returned at the same time as the
			// capacity token became selectable. Prefer reuse if so.
			select {
			case client := <-p.conns:
				p.releaseSlot()
				if reused, err := p.reuse(client); err != nil || reused != nil {
					return reused, err
				}
				continue
			default:
			}

			p.mu.Lock()
			closed := p.closed
			p.mu.Unlock()
			if closed {
				p.releaseSlot()
				return nil, ErrClientClosed
			}

			client, err := p.dialer.DialContext(ctx)
			if err != nil {
				p.releaseSlot()
				return nil, err
			}

			p.mu.Lock()
			closed = p.closed
			if !closed {
				p.owned[client] = poolClientCheckedOut
			}
			p.mu.Unlock()
			if closed {
				_ = client.Close()
				p.releaseSlot()
				return nil, ErrClientClosed
			}
			return client, nil
		}
	}
}

func (p *Pool) reuse(client *Client) (*Client, error) {
	p.mu.Lock()
	state, owned := p.owned[client]
	if p.closed {
		if owned {
			delete(p.owned, client)
		}
		p.mu.Unlock()
		_ = client.Close()
		if owned {
			p.releaseSlot()
		}
		return nil, ErrClientClosed
	}
	if !owned || state != poolClientIdle {
		p.mu.Unlock()
		_ = client.Close()
		return nil, nil
	}
	p.owned[client] = poolClientCheckedOut
	p.mu.Unlock()

	if err := client.Noop(); err != nil {
		p.discard(client)
		return nil, nil
	}
	return client, nil
}

func (p *Pool) discard(client *Client) {
	p.mu.Lock()
	_, owned := p.owned[client]
	if owned {
		delete(p.owned, client)
	}
	p.mu.Unlock()

	_ = client.Close()
	if owned {
		p.releaseSlot()
	}
}

func (p *Pool) releaseSlot() {
	p.slots <- struct{}{}
}

// Put returns a connection obtained from Get or GetContext to the pool. Clients
// not owned by this pool are closed and are never admitted.
func (p *Pool) Put(client *Client) {
	if client == nil {
		return
	}

	p.mu.Lock()
	state, owned := p.owned[client]
	if !owned {
		p.mu.Unlock()
		_ = client.Close()
		return
	}
	if state == poolClientIdle {
		p.mu.Unlock()
		return
	}
	if p.closed {
		delete(p.owned, client)
		p.mu.Unlock()
		_ = client.Close()
		p.releaseSlot()
		return
	}

	// Keep the lifecycle lock held while publishing the connection so Close
	// cannot mark the pool closed between the check and the channel send.
	p.owned[client] = poolClientIdle
	select {
	case p.conns <- client:
		p.mu.Unlock()
		return
	default:
		delete(p.owned, client)
		p.mu.Unlock()
	}

	// The idle queue should only be full after misuse such as duplicate returns.
	if err := client.Quit(); err != nil {
		_ = client.Close()
	}
	p.releaseSlot()
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
		p.discard(client)
		return result, fmt.Errorf("sending mail with pooled client: %w", err)
	}

	// Return connection to pool
	p.Put(client)
	return result, nil
}

// SendRaw streams a raw RFC 5322 message using a pooled connection.
func (p *Pool) SendRaw(envelope ravenmail.Envelope, data io.Reader) (*SendResult, error) {
	client, err := p.Get()
	if err != nil {
		return nil, fmt.Errorf("getting SMTP client from pool: %w", err)
	}

	result, err := client.SendRaw(envelope, data)
	if err != nil {
		p.discard(client)
		return result, fmt.Errorf("sending raw mail with pooled client: %w", err)
	}

	p.Put(client)
	return result, nil
}

// Close closes the pool and all connections.
func (p *Pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	close(p.done)

	// The channel intentionally remains open. Closing it would race with Put
	// callers that observed the pool as open. Drain all idle connections while
	// holding the lifecycle lock, then close them without blocking other calls.
	clients := make([]*Client, 0, len(p.conns))
	for range len(p.conns) {
		client := <-p.conns
		if state, ok := p.owned[client]; ok && state == poolClientIdle {
			delete(p.owned, client)
			clients = append(clients, client)
		}
	}
	p.mu.Unlock()

	for _, client := range clients {
		if err := client.Quit(); err != nil {
			_ = client.Close()
		}
		p.releaseSlot()
	}

	return nil
}

// QuickSend is a convenience function for sending a single email.
// It handles all connection setup and teardown automatically.
//
// Deprecated: Use Dialer or Pool and reuse SMTP connections. Prefer SendRaw for
// an already serialized message stream.
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
	defer func() { _ = client.Close() }()

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
//
// Deprecated: Configure Dialer.TLS and reuse the resulting Client or Pool.
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
	defer func() { _ = client.Close() }()

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
//
// Deprecated: Use Dialer or Pool and reuse SMTP connections. Prefer SendRaw for
// an already serialized message stream.
func QuickSendMail(address string, auth *ClientAuth, mail *ravenmail.Mail) error {
	config := DefaultClientConfig()
	config.Auth = auth

	client := NewClient(config)

	if err := client.Dial(address); err != nil {
		return fmt.Errorf("dialing SMTP server %s: %w", address, err)
	}
	defer func() { _ = client.Close() }()

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
