package raven

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrClientClosed           = errors.New("smtp: client closed")
	ErrNoConnection           = errors.New("smtp: no connection established")
	ErrExtensionNotSupported  = errors.New("smtp: extension not supported by server")
	ErrAuthFailed             = errors.New("smtp: authentication failed")
	ErrTLSAlreadyActive       = errors.New("smtp: TLS already active")
	ErrTLSNotSupported        = errors.New("smtp: STARTTLS not supported by server")
	ErrUnexpectedResponse     = errors.New("smtp: unexpected server response")
	ErrRequireTLSNotSupported = errors.New("smtp: REQUIRETLS not supported by server")
)

// ClientConfig holds configuration for the SMTP client.
type ClientConfig struct {
	LocalName      string // Hostname for EHLO/HELO (default: "localhost")
	LocalAddr      string // Local address to bind to (e.g., "ip:port")
	TLSConfig      *tls.Config
	Auth           *ClientAuth
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	RetryConfig    *RetryConfig
	Debug          bool
	DebugWriter    io.Writer
}

// ClientAuth holds authentication credentials.
type ClientAuth struct {
	Username   string
	Password   string
	Mechanisms []string // Preferred SASL mechanisms (auto-select if empty)
}

// RetryConfig controls retry behavior.
type RetryConfig struct {
	MaxRetries   int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
}

// DefaultClientConfig returns a ClientConfig with sensible defaults.
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		LocalName:      "localhost",
		ConnectTimeout: 30 * time.Second,
		ReadTimeout:    5 * time.Minute,
		WriteTimeout:   5 * time.Minute,
	}
}

// Client is an SMTP client.
type Client struct {
	config        *ClientConfig
	conn          net.Conn
	reader        *bufio.Reader
	writer        *bufio.Writer
	mu            sync.Mutex
	serverName    string
	extensions    map[Extension]string
	greeting      string
	isTLS         bool
	isESMTP       bool
	authenticated bool
	closed        bool
	lastResponse  *ClientResponse
	ctx           context.Context
	cancel        context.CancelFunc
}

// ClientResponse represents a parsed SMTP server response.
type ClientResponse struct {
	Code         int
	Message      string
	Lines        []string
	EnhancedCode string
}

// IsSuccess returns true if the response indicates success (2xx).
func (r *ClientResponse) IsSuccess() bool {
	return r.Code >= 200 && r.Code < 300
}

// IsIntermediate returns true if the response is intermediate (3xx).
func (r *ClientResponse) IsIntermediate() bool {
	return r.Code >= 300 && r.Code < 400
}

// IsTransientError returns true if the response indicates a transient error (4xx).
func (r *ClientResponse) IsTransientError() bool {
	return r.Code >= 400 && r.Code < 500
}

// IsPermanentError returns true if the response indicates a permanent error (5xx).
func (r *ClientResponse) IsPermanentError() bool {
	return r.Code >= 500 && r.Code < 600
}

// Error returns the response as an error if it indicates failure.
func (r *ClientResponse) Error() error {
	if r.IsSuccess() || r.IsIntermediate() {
		return nil
	}
	return &SMTPError{
		Code:         r.Code,
		EnhancedCode: r.EnhancedCode,
		Message:      r.Message,
	}
}

// SMTPError represents an SMTP protocol error.
type SMTPError struct {
	Code         int
	EnhancedCode string
	Message      string
}

func (e *SMTPError) Error() string {
	if e.EnhancedCode != "" {
		return fmt.Sprintf("SMTP %d %s: %s", e.Code, e.EnhancedCode, e.Message)
	}
	return fmt.Sprintf("SMTP %d: %s", e.Code, e.Message)
}

// IsPermanent returns true if this is a permanent failure (5xx).
func (e *SMTPError) IsPermanent() bool {
	return e.Code >= 500 && e.Code < 600
}

// IsTransient returns true if this is a transient failure (4xx).
func (e *SMTPError) IsTransient() bool {
	return e.Code >= 400 && e.Code < 500
}

// NewClient creates a new SMTP client.
func NewClient(config *ClientConfig) *Client {
	if config == nil {
		config = DefaultClientConfig()
	}
	if config.LocalName == "" {
		config.LocalName = "localhost"
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		config:     config,
		extensions: make(map[Extension]string),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Dial connects to the SMTP server (e.g., "smtp.example.com:25").
func (c *Client) Dial(address string) error {
	return c.DialContext(context.Background(), address)
}

// DialContext connects to the SMTP server with a context.
func (c *Client) DialContext(ctx context.Context, address string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrClientClosed
	}

	// Parse host for TLS server name
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	c.serverName = host

	connectTimeout := c.config.ConnectTimeout
	if connectTimeout == 0 {
		connectTimeout = 30 * time.Second
	}

	dialer := &net.Dialer{
		Timeout: connectTimeout,
	}

	if c.config.LocalAddr != "" {
		laddr, err := resolveLocalAddr(c.config.LocalAddr)
		if err != nil {
			return fmt.Errorf("invalid local address: %w", err)
		}
		dialer.LocalAddr = laddr
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}

	c.conn = conn
	c.reader = bufio.NewReader(conn)
	c.writer = bufio.NewWriter(conn)

	// Read server greeting
	resp, err := c.readResponse()
	if err != nil {
		c.conn.Close()
		c.conn = nil
		return fmt.Errorf("failed to read greeting: %w", err)
	}

	if !resp.IsSuccess() {
		c.conn.Close()
		c.conn = nil
		return resp.Error()
	}

	c.greeting = resp.Message

	return nil
}

// DialTLS connects using implicit TLS (typically port 465).
func (c *Client) DialTLS(address string) error {
	return c.DialTLSContext(context.Background(), address)
}

// DialTLSContext connects to the SMTP server using implicit TLS with a context.
func (c *Client) DialTLSContext(ctx context.Context, address string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrClientClosed
	}

	// Parse host for TLS server name
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	c.serverName = host

	// Prepare TLS config
	tlsConfig := c.config.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	if tlsConfig.ServerName == "" {
		tlsConfig = tlsConfig.Clone()
		tlsConfig.ServerName = host
	}

	// Connect with timeout
	connectTimeout := c.config.ConnectTimeout
	if connectTimeout == 0 {
		connectTimeout = 30 * time.Second
	}

	netDialer := &net.Dialer{
		Timeout: connectTimeout,
	}

	// Set local address if specified
	if c.config.LocalAddr != "" {
		laddr, err := resolveLocalAddr(c.config.LocalAddr)
		if err != nil {
			return fmt.Errorf("invalid local address: %w", err)
		}
		netDialer.LocalAddr = laddr
	}

	dialer := &tls.Dialer{
		NetDialer: netDialer,
		Config:    tlsConfig,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("dial TLS failed: %w", err)
	}

	c.conn = conn
	c.reader = bufio.NewReader(conn)
	c.writer = bufio.NewWriter(conn)
	c.isTLS = true

	// Read server greeting
	resp, err := c.readResponse()
	if err != nil {
		c.conn.Close()
		c.conn = nil
		return fmt.Errorf("failed to read greeting: %w", err)
	}

	if !resp.IsSuccess() {
		c.conn.Close()
		c.conn = nil
		return resp.Error()
	}

	c.greeting = resp.Message

	return nil
}

// Hello sends EHLO/HELO to the server.
func (c *Client) Hello() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return ErrNoConnection
	}

	// Try EHLO first
	if err := c.writeCommand("EHLO %s", c.config.LocalName); err != nil {
		return err
	}

	resp, err := c.readResponse()
	if err != nil {
		return err
	}

	if resp.IsSuccess() {
		c.isESMTP = true
		c.parseExtensions(resp.Lines)
		return nil
	}

	// Fall back to HELO for non-ESMTP servers
	if err := c.writeCommand("HELO %s", c.config.LocalName); err != nil {
		return err
	}

	resp, err = c.readResponse()
	if err != nil {
		return err
	}

	if !resp.IsSuccess() {
		return resp.Error()
	}

	c.isESMTP = false
	return nil
}

// StartTLS upgrades the connection to TLS.
func (c *Client) StartTLS() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return ErrNoConnection
	}

	if c.isTLS {
		return ErrTLSAlreadyActive
	}

	if _, ok := c.extensions[ExtSTARTTLS]; !ok {
		return ErrTLSNotSupported
	}

	if err := c.writeCommand("STARTTLS"); err != nil {
		return err
	}

	resp, err := c.readResponse()
	if err != nil {
		return err
	}

	if !resp.IsSuccess() {
		return resp.Error()
	}

	// Upgrade to TLS
	tlsConfig := c.config.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	if tlsConfig.ServerName == "" {
		tlsConfig = tlsConfig.Clone()
		tlsConfig.ServerName = c.serverName
	}

	tlsConn := tls.Client(c.conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}

	c.conn = tlsConn
	c.reader = bufio.NewReader(tlsConn)
	c.writer = bufio.NewWriter(tlsConn)
	c.isTLS = true

	// Clear extensions - must re-send EHLO after STARTTLS
	c.extensions = make(map[Extension]string)
	c.isESMTP = false

	return nil
}

// Auth authenticates with the server.
func (c *Client) Auth() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return ErrNoConnection
	}

	if c.config.Auth == nil {
		return errors.New("no authentication credentials configured")
	}

	authExt, ok := c.extensions[ExtAuth]
	if !ok {
		return fmt.Errorf("%w: AUTH", ErrExtensionNotSupported)
	}

	// Parse supported mechanisms
	serverMechanisms := strings.Fields(authExt)

	// Select mechanism
	mechanism := c.selectAuthMechanism(serverMechanisms)
	if mechanism == "" {
		return fmt.Errorf("no supported authentication mechanism available")
	}

	switch mechanism {
	case "PLAIN":
		return c.authPLAIN()
	case "LOGIN":
		return c.authLOGIN()
	default:
		return fmt.Errorf("unsupported authentication mechanism: %s", mechanism)
	}
}

// AuthWithMechanism authenticates using a specific SASL mechanism.
func (c *Client) AuthWithMechanism(mechanism string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return ErrNoConnection
	}

	if c.config.Auth == nil {
		return errors.New("no authentication credentials configured")
	}

	switch strings.ToUpper(mechanism) {
	case "PLAIN":
		return c.authPLAIN()
	case "LOGIN":
		return c.authLOGIN()
	default:
		return fmt.Errorf("unsupported authentication mechanism: %s", mechanism)
	}
}

func (c *Client) selectAuthMechanism(serverMechanisms []string) string {
	// Check if client has preferred mechanisms
	if len(c.config.Auth.Mechanisms) > 0 {
		for _, pref := range c.config.Auth.Mechanisms {
			for _, srv := range serverMechanisms {
				if strings.EqualFold(pref, srv) {
					return strings.ToUpper(pref)
				}
			}
		}
		return ""
	}

	// Default preference order
	preference := []string{"PLAIN", "LOGIN"}
	for _, mech := range preference {
		for _, srv := range serverMechanisms {
			if strings.EqualFold(mech, srv) {
				return mech
			}
		}
	}
	return ""
}

func (c *Client) authPLAIN() error {
	// Build PLAIN credentials: \0username\0password
	creds := fmt.Sprintf("\x00%s\x00%s", c.config.Auth.Username, c.config.Auth.Password)
	encoded := base64Encode([]byte(creds))

	if err := c.writeCommand("AUTH PLAIN %s", encoded); err != nil {
		return err
	}

	resp, err := c.readResponse()
	if err != nil {
		return err
	}

	if !resp.IsSuccess() {
		return fmt.Errorf("%w: %s", ErrAuthFailed, resp.Message)
	}

	c.authenticated = true
	return nil
}

func (c *Client) authLOGIN() error {
	if err := c.writeCommand("AUTH LOGIN"); err != nil {
		return err
	}

	resp, err := c.readResponse()
	if err != nil {
		return err
	}

	// Expect 334 challenge
	if resp.Code != 334 {
		return fmt.Errorf("%w: unexpected response %d", ErrAuthFailed, resp.Code)
	}

	// Send username
	if err := c.writeCommand("%s", base64Encode([]byte(c.config.Auth.Username))); err != nil {
		return err
	}

	resp, err = c.readResponse()
	if err != nil {
		return err
	}

	if resp.Code != 334 {
		return fmt.Errorf("%w: unexpected response %d", ErrAuthFailed, resp.Code)
	}

	// Send password
	if err := c.writeCommand("%s", base64Encode([]byte(c.config.Auth.Password))); err != nil {
		return err
	}

	resp, err = c.readResponse()
	if err != nil {
		return err
	}

	if !resp.IsSuccess() {
		return fmt.Errorf("%w: %s", ErrAuthFailed, resp.Message)
	}

	c.authenticated = true
	return nil
}

// Reset sends the RSET command.
func (c *Client) Reset() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return ErrNoConnection
	}

	if err := c.writeCommand("RSET"); err != nil {
		return err
	}

	resp, err := c.readResponse()
	if err != nil {
		return err
	}

	if !resp.IsSuccess() {
		return resp.Error()
	}

	return nil
}

// Noop sends the NOOP command.
func (c *Client) Noop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return ErrNoConnection
	}

	if err := c.writeCommand("NOOP"); err != nil {
		return err
	}

	resp, err := c.readResponse()
	if err != nil {
		return err
	}

	if !resp.IsSuccess() {
		return resp.Error()
	}

	return nil
}

// Quit sends the QUIT command.
func (c *Client) Quit() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return ErrNoConnection
	}

	if err := c.writeCommand("QUIT"); err != nil {
		// Still close the connection
		c.close()
		return err
	}

	// Try to read response, but don't fail if it doesn't come
	c.readResponse()

	return c.close()
}

// Close closes the connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.close()
}

func (c *Client) close() error {
	if c.conn == nil {
		return nil
	}

	c.closed = true
	c.cancel()

	err := c.conn.Close()
	c.conn = nil
	c.reader = nil
	c.writer = nil

	return err
}

// parseExtensions parses the EHLO response lines for extensions.
func (c *Client) parseExtensions(lines []string) {
	c.extensions = make(map[Extension]string)

	for _, line := range lines[1:] { // Skip first line (greeting)
		// Extension lines are space-separated: "EXT params"
		parts := strings.SplitN(line, " ", 2)
		ext := Extension(strings.ToUpper(parts[0]))
		params := ""
		if len(parts) > 1 {
			params = parts[1]
		}
		c.extensions[ext] = params
	}
}

// writeCommand sends a command to the server.
func (c *Client) writeCommand(format string, args ...any) error {
	cmd := fmt.Sprintf(format, args...)

	if c.config.Debug && c.config.DebugWriter != nil {
		fmt.Fprintf(c.config.DebugWriter, "C: %s\n", cmd)
	}

	if c.config.WriteTimeout > 0 {
		c.conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout))
	}

	_, err := c.writer.WriteString(cmd + "\r\n")
	if err != nil {
		return err
	}

	return c.writer.Flush()
}

// readResponse reads and parses a server response.
func (c *Client) readResponse() (*ClientResponse, error) {
	if c.config.ReadTimeout > 0 {
		c.conn.SetReadDeadline(time.Now().Add(c.config.ReadTimeout))
	}

	var lines []string
	var code int

	for {
		line, err := c.reader.ReadString('\n')
		if err != nil {
			return nil, err
		}

		line = strings.TrimRight(line, "\r\n")

		if c.config.Debug && c.config.DebugWriter != nil {
			fmt.Fprintf(c.config.DebugWriter, "S: %s\n", line)
		}

		if len(line) < 4 {
			return nil, fmt.Errorf("%w: line too short: %q", ErrUnexpectedResponse, line)
		}

		lineCode, err := strconv.Atoi(line[:3])
		if err != nil {
			return nil, fmt.Errorf("%w: invalid code: %q", ErrUnexpectedResponse, line)
		}

		if code == 0 {
			code = lineCode
		} else if lineCode != code {
			return nil, fmt.Errorf("%w: inconsistent codes", ErrUnexpectedResponse)
		}

		// Extract message part (skip code and separator)
		message := ""
		if len(line) > 4 {
			message = line[4:]
		}
		lines = append(lines, message)

		// Check if this is the last line (space after code vs dash for continuation)
		if line[3] == ' ' {
			break
		}
	}

	// Build response
	resp := &ClientResponse{
		Code:    code,
		Message: strings.Join(lines, "\n"),
		Lines:   lines,
	}

	// Parse enhanced status code from first line
	if len(lines) > 0 {
		resp.EnhancedCode = parseEnhancedCode(lines[0])
	}

	c.lastResponse = resp
	return resp, nil
}

// parseEnhancedCode extracts an enhanced status code from a response message.
func parseEnhancedCode(msg string) string {
	if len(msg) < 5 {
		return ""
	}

	// Check pattern X.Y.Z
	parts := strings.SplitN(msg, " ", 2)
	if len(parts) == 0 {
		return ""
	}

	code := parts[0]
	subparts := strings.Split(code, ".")
	if len(subparts) != 3 {
		return ""
	}

	// Validate each part is a number
	for _, p := range subparts {
		if _, err := strconv.Atoi(p); err != nil {
			return ""
		}
	}

	return code
}

// base64Encode encodes data to base64.
func base64Encode(data []byte) string {
	return base64StdEncoding.EncodeToString(data)
}

var base64StdEncoding = newBase64Encoding()

func newBase64Encoding() *base64Encoding {
	return &base64Encoding{}
}

type base64Encoding struct{}

func (e *base64Encoding) EncodeToString(src []byte) string {
	const encodeStd = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	if len(src) == 0 {
		return ""
	}

	dst := make([]byte, (len(src)+2)/3*4)
	n := len(src)
	di, si := 0, 0

	for si < n-2 {
		val := uint(src[si+0])<<16 | uint(src[si+1])<<8 | uint(src[si+2])
		dst[di+0] = encodeStd[val>>18&0x3F]
		dst[di+1] = encodeStd[val>>12&0x3F]
		dst[di+2] = encodeStd[val>>6&0x3F]
		dst[di+3] = encodeStd[val&0x3F]
		si += 3
		di += 4
	}

	remain := n - si
	if remain > 0 {
		val := uint(src[si+0]) << 16
		if remain == 2 {
			val |= uint(src[si+1]) << 8
		}

		dst[di+0] = encodeStd[val>>18&0x3F]
		dst[di+1] = encodeStd[val>>12&0x3F]
		if remain == 2 {
			dst[di+2] = encodeStd[val>>6&0x3F]
			dst[di+3] = '='
		} else {
			dst[di+2] = '='
			dst[di+3] = '='
		}
	}

	return string(dst)
}

// resolveLocalAddr parses a local address string into a *net.TCPAddr.
// Accepts formats: "ip:port", "[ipv6]:port", ":port", "ip", or "" (returns nil).
func resolveLocalAddr(addr string) (*net.TCPAddr, error) {
	if addr == "" {
		return nil, nil
	}

	// Try to parse as IP first (handles both IPv4 and IPv6)
	ip := net.ParseIP(addr)
	if ip != nil {
		return &net.TCPAddr{IP: ip, Port: 0}, nil
	}

	// Try to parse as host:port
	return net.ResolveTCPAddr("tcp", addr)
}
