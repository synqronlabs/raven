package server

import (
	"bufio"
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/synqronlabs/raven/internal/transferbuf"
	ravenio "github.com/synqronlabs/raven/io"
	"github.com/synqronlabs/raven/sasl"
)

// ConnectionState represents the current state of an SMTP connection.
type ConnectionState int

const (
	StateNew     ConnectionState = iota
	StateGreeted                 // After HELO/EHLO
	StateMail                    // After MAIL FROM
	StateRcpt                    // After first RCPT TO
	StateData                    // During DATA
	StateQuit                    // After QUIT
)

// Conn represents an SMTP connection.
type Conn struct {
	// Server is the parent server.
	server *Server

	// Hostname is the client's self-identified hostname (from HELO/EHLO).
	Hostname string

	// Session is the backend session for this connection.
	session Session

	// ctx is the connection context.
	ctx    context.Context
	cancel context.CancelFunc

	// conn is the underlying network connection.
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer

	// mu protects mutable state.
	mu sync.RWMutex

	// state is the current connection state.
	state ConnectionState

	// TLS state (nil if not using TLS).
	tlsState *tls.ConnectionState

	// isESMTP indicates if the client used EHLO (vs HELO).
	isESMTP bool

	// authenticated is true if AUTH succeeded.
	authenticated bool

	// authIdentity is the authenticated user identity.
	authIdentity string

	// recipientCount tracks recipients in current transaction.
	recipientCount int

	// Transaction-level state (reset after each message)
	// bodyType is the BODY= parameter from MAIL FROM (for 7BIT enforcement).
	bodyType BodyType

	// smtputf8 indicates if SMTPUTF8 was requested for this transaction.
	// When true, non-ASCII characters are allowed in envelope addresses.
	smtputf8 bool

	// bdatState tracks streaming state across BDAT chunks.
	bdatState *bdatStreamState
}

// TLS returns the TLS connection state, or nil if not using TLS.
func (c *Conn) TLS() *tls.ConnectionState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tlsState
}

// Authenticated returns true if the client has authenticated.
func (c *Conn) Authenticated() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.authenticated
}

// AuthIdentity returns the authenticated user identity.
func (c *Conn) AuthIdentity() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.authIdentity
}

// SetAuthIdentity records the authenticated user identity for the connection.
//
// Custom AUTH implementations can call this during a successful SASL exchange
// so later session logic can inspect Conn.AuthIdentity(). This does not mark
// the connection as authenticated; AUTH completion still controls that state.
func (c *Conn) SetAuthIdentity(identity string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authIdentity = identity
}

// RemoteAddr returns the remote address of the connection.
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// LocalAddr returns the local address of the connection.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// Context returns the connection's context.
func (c *Conn) Context() context.Context {
	return c.ctx
}

// Close closes the connection.
func (c *Conn) Close() error {
	c.cancel()
	return c.conn.Close()
}

// newConn creates a new connection handler.
func newConn(ctx context.Context, netConn net.Conn, s *Server) *Conn {
	ctx, cancel := context.WithCancel(ctx)

	c := &Conn{
		server: s,
		ctx:    ctx,
		cancel: cancel,
		conn:   netConn,
		reader: bufio.NewReader(netConn),
		writer: bufio.NewWriter(netConn),
		state:  StateNew,
	}

	// Check if this is an implicit TLS connection
	if tlsConn, ok := netConn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		c.tlsState = &state
	}

	return c
}

// serve handles the SMTP session.
func (c *Conn) serve() {
	defer func() {
		if r := recover(); r != nil {
			c.server.logf("panic: %v", r)
		}
	}()

	// Send greeting
	c.writeResponse(220, c.server.config.Domain+" ESMTP ready")

	// Command loop
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		// Set read deadline
		if err := c.conn.SetReadDeadline(time.Now().Add(c.server.config.ReadTimeout)); err != nil {
			c.server.logf("setting read deadline: %v", err)
			return
		}

		line, err := c.readLine()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				c.writeError(errTimeout)
				return
			}
			if c.writeCommandReadError(err) {
				continue
			}
			c.server.logf("read error: %v", err)
			return
		}

		// Handle the command
		if c.state == StateQuit {
			return
		}

		if err := c.handleCommand(line); err != nil {
			c.server.logf("command error: %v", err)
			return
		}

		if c.state == StateQuit {
			return
		}
	}
}

// readLine reads a line from the connection using optimized SMTP line reading.
// It enforces CRLF line endings (RFC 5321) and checks line length limits.
func (c *Conn) readLine() (string, error) {
	line, err := ravenio.ReadLine(c.reader, c.server.config.MaxLineLength, false)
	if err != nil {
		return "", fmt.Errorf("reading SMTP command line: %w", err)
	}

	if c.server.config.Debug != nil {
		_, _ = fmt.Fprintf(c.server.config.Debug, "C: %s\n", line)
	}

	return line, nil
}

// readLineASCII reads an AUTH exchange line with ASCII enforcement.
func (c *Conn) readLineASCII() (string, error) {
	line, err := ravenio.ReadLine(c.reader, c.server.config.MaxAuthLineLength, true)
	if err != nil {
		return "", fmt.Errorf("reading SMTP AUTH response line: %w", err)
	}

	if c.server.config.Debug != nil {
		_, _ = fmt.Fprintf(c.server.config.Debug, "C: %s\n", line)
	}

	return line, nil
}

func (c *Conn) writeCommandReadError(err error) bool {
	switch {
	case errors.Is(err, ravenio.ErrLineTooLong):
		c.writeError(errCommandLineTooLong)
		return true
	case errors.Is(err, ravenio.ErrBadLineEnding):
		c.writeError(errBadCommandLineEnding)
		return true
	default:
		return false
	}
}

func (c *Conn) writeAuthReadError(err error) bool {
	switch {
	case errors.Is(err, ravenio.Err8BitIn7BitMode):
		c.writeError(errInvalidCharacters)
		return true
	case errors.Is(err, ravenio.ErrLineTooLong):
		c.writeError(errAuthExchangeLineTooLong)
		return true
	case errors.Is(err, ravenio.ErrBadLineEnding):
		c.writeError(errAuthBadLineEnding)
		return true
	default:
		return false
	}
}

// writeResponse writes an SMTP response.
func (c *Conn) writeResponse(code int, message string) {
	c.writeResponseMulti(code, []string{message})
}

// writeResponseMulti writes a multi-line SMTP response.
func (c *Conn) writeResponseMulti(code int, messages []string) {
	if err := c.conn.SetWriteDeadline(time.Now().Add(c.server.config.WriteTimeout)); err != nil {
		c.server.logf("setting write deadline: %v", err)
		return
	}

	for i, msg := range messages {
		var line string
		if i == len(messages)-1 {
			line = fmt.Sprintf("%d %s\r\n", code, msg)
		} else {
			line = fmt.Sprintf("%d-%s\r\n", code, msg)
		}
		if _, err := c.writer.WriteString(line); err != nil {
			c.server.logf("writing SMTP response line: %v", err)
			return
		}

		if c.server.config.Debug != nil {
			_, _ = fmt.Fprintf(c.server.config.Debug, "S: %s", line)
		}
	}

	if err := c.writer.Flush(); err != nil {
		c.server.logf("flushing SMTP response: %v", err)
	}
}

// handleCommand parses and dispatches an SMTP command.
func (c *Conn) handleCommand(line string) error {
	verb, args := parseCommand(line)
	verb = strings.ToUpper(verb)

	switch verb {
	case "HELO":
		return c.handleHELO(args, false)
	case "EHLO":
		return c.handleHELO(args, true)
	case "STARTTLS":
		return c.handleSTARTTLS()
	case "AUTH":
		return c.handleAUTH(args)
	case "MAIL":
		return c.handleMAIL(args)
	case "RCPT":
		return c.handleRCPT(args)
	case "DATA":
		return c.handleDATA()
	case "BDAT":
		return c.handleBDAT(args)
	case "RSET":
		return c.handleRSET()
	case "VRFY":
		return c.handleVRFY(args)
	case "EXPN":
		return c.handleEXPN(args)
	case "HELP":
		return c.handleHELP(args)
	case "NOOP":
		c.writeResponse(250, "OK")
		return nil
	case "QUIT":
		return c.handleQUIT()
	default:
		c.writeError(errUnrecognizedCommand)
		return nil
	}
}

// parseCommand splits an SMTP command into verb and arguments.
func parseCommand(line string) (verb, args string) {
	before, after, ok := strings.Cut(line, " ")
	if !ok {
		return line, ""
	}
	return before, after
}

// handleHELO handles HELO and EHLO commands.
func (c *Conn) handleHELO(hostname string, isEHLO bool) error {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		c.writeError(errHostnameRequired)
		return nil
	}

	c.mu.Lock()
	c.Hostname = hostname
	c.isESMTP = isEHLO
	c.state = StateGreeted
	c.mu.Unlock()

	// Create session from backend
	session, err := c.server.backend.NewSession(c)
	if err != nil {
		c.writeError(err)
		return nil
	}
	c.session = session

	if !isEHLO {
		// HELO - simple response
		c.writeResponse(250, c.server.config.Domain)
		return nil
	}

	// EHLO - advertise extensions
	extensions := c.buildExtensions()
	c.writeResponseMulti(250, extensions)
	return nil
}

// buildExtensions builds the EHLO extension list.
func (c *Conn) buildExtensions() []string {
	cfg := &c.server.config
	exts := []string{cfg.Domain}

	// Always advertise these
	exts = append(exts, "PIPELINING", "8BITMIME", "ENHANCEDSTATUSCODES")

	// SIZE
	if cfg.MaxMessageBytes > 0 {
		exts = append(exts, fmt.Sprintf("SIZE %d", cfg.MaxMessageBytes))
	} else if cfg.MaxMessageBytes == 0 {
		exts = append(exts, "SIZE 26214400") // 25MB default
	} else {
		exts = append(exts, "SIZE")
	}

	// SMTPUTF8
	if cfg.EnableSMTPUTF8 {
		exts = append(exts, "SMTPUTF8")
	}

	// STARTTLS
	if cfg.TLSConfig != nil && c.TLS() == nil {
		exts = append(exts, "STARTTLS")
	}

	// REQUIRETLS
	if cfg.EnableREQUIRETLS && c.TLS() != nil {
		exts = append(exts, "REQUIRETLS")
	}

	// DELIVERBY
	if cfg.EnableDELIVERBY {
		if cfg.DeliveryByMinSeconds > 0 {
			exts = append(exts, fmt.Sprintf("DELIVERBY %d", cfg.DeliveryByMinSeconds))
		} else {
			exts = append(exts, "DELIVERBY")
		}
	}

	// DSN
	if cfg.EnableDSN {
		exts = append(exts, "DSN")
	}

	// CHUNKING/BINARYMIME
	if cfg.EnableCHUNKING {
		exts = append(exts, "CHUNKING")
		if cfg.EnableBINARYMIME {
			exts = append(exts, "BINARYMIME")
		}
	}

	// AUTH
	if authSess, ok := c.session.(AuthSession); ok && c.session != nil {
		mechs := authSess.AuthMechanisms()
		if len(mechs) > 0 && (cfg.AllowInsecureAuth || c.TLS() != nil) {
			exts = append(exts, "AUTH "+strings.Join(mechs, " "))
		}
	}

	return exts
}

// handleSTARTTLS handles the STARTTLS command.
func (c *Conn) handleSTARTTLS() error {
	if c.server.config.TLSConfig == nil {
		c.writeError(errTLSNotAvailable)
		return nil
	}

	if c.TLS() != nil {
		c.writeError(errTLSAlreadyActive)
		return nil
	}

	c.writeResponse(220, "Ready to start TLS")

	// Upgrade connection to TLS
	tlsConn := tls.Server(c.conn, c.server.config.TLSConfig)
	if err := tlsConn.Handshake(); err != nil {
		c.server.logf("TLS handshake error: %v", err)
		return fmt.Errorf("performing STARTTLS handshake: %w", err)
	}

	c.mu.Lock()
	c.conn = tlsConn
	c.reader = bufio.NewReader(tlsConn)
	c.writer = bufio.NewWriter(tlsConn)
	state := tlsConn.ConnectionState()
	c.tlsState = &state
	// Reset state after STARTTLS - client must re-issue EHLO
	c.state = StateNew
	c.session = nil
	c.authenticated = false
	c.authIdentity = ""
	c.mu.Unlock()

	return nil
}

// handleAUTH handles the AUTH command.
func (c *Conn) handleAUTH(args string) error {
	if c.state != StateGreeted {
		c.writeError(errBadSequence)
		return nil
	}

	// Check if already authenticated
	if c.Authenticated() {
		c.writeError(errAlreadyAuthenticated)
		return nil
	}

	// Check if TLS is required
	if !c.server.config.AllowInsecureAuth && c.TLS() == nil {
		c.writeError(errEncryptionRequired)
		return nil
	}

	// Check if session supports auth
	authSess, ok := c.session.(AuthSession)
	if !ok {
		c.writeError(ErrAuthUnsupported)
		return nil
	}

	// Parse mechanism and initial response
	parts := strings.SplitN(args, " ", 2)
	mechanism := strings.ToUpper(parts[0])
	var initialResponse string
	if len(parts) > 1 && parts[1] != "=" {
		initialResponse = parts[1]
	}

	// Get SASL server for this mechanism
	saslServer, err := authSess.Auth(mechanism)
	if err != nil {
		c.writeResponse(504, fmt.Sprintf("Mechanism not supported: %s", mechanism))
		return nil
	}

	// Decode initial response if present
	var response []byte
	if initialResponse != "" {
		response, err = base64.StdEncoding.DecodeString(initialResponse)
		if err != nil {
			c.writeError(errInvalidBase64)
			return nil
		}
	}

	// Run SASL exchange
	for {
		challenge, done, err := saslServer.Next(response)
		if err != nil {
			if errors.Is(err, sasl.ErrAuthenticationCancelled) {
				c.writeError(errAuthCancelled)
			} else {
				c.writeError(ErrAuthFailed)
			}
			return nil
		}

		if done {
			// Authentication successful
			c.mu.Lock()
			c.authenticated = true
			if provider, ok := saslServer.(interface{ AuthIdentity() string }); ok {
				identity := provider.AuthIdentity()
				if identity != "" || c.authIdentity == "" {
					c.authIdentity = identity
				}
			}
			c.mu.Unlock()
			c.writeResponse(235, "2.7.0 Authentication successful")
			return nil
		}

		// Send challenge
		encodedChallenge := base64.StdEncoding.EncodeToString(challenge)
		c.writeResponse(334, encodedChallenge)

		// Read response (with ASCII enforcement for AUTH)
		line, err := c.readLineASCII()
		if err != nil {
			if c.writeAuthReadError(err) {
				return nil
			}
			return fmt.Errorf("reading AUTH client response: %w", err)
		}

		if line == "*" {
			c.writeError(errAuthCancelled)
			return nil
		}

		response, err = base64.StdEncoding.DecodeString(line)
		if err != nil {
			c.writeError(errInvalidBase64)
			return nil
		}
	}
}

// handleMAIL handles the MAIL FROM command.
func (c *Conn) handleMAIL(args string) error {
	if c.state != StateGreeted {
		c.writeError(errBadSequence)
		return nil
	}

	if c.session == nil {
		c.writeError(errHeloFirst)
		return nil
	}

	// Parse MAIL FROM:<address> [parameters]
	if !strings.HasPrefix(strings.ToUpper(args), "FROM:") {
		c.writeError(errMailSyntax)
		return nil
	}

	args = args[5:] // Remove "FROM:"

	// First do a quick path extraction to get params (we need to check SMTPUTF8 first)
	rawPath, params, err := extractPathAndParams(args)
	if err != nil {
		c.writeResponse(501, fmt.Sprintf("5.1.7 Invalid address syntax: %v", err))
		return nil
	}

	// Parse mail options to determine if SMTPUTF8 is requested
	opts, err := c.parseMailOptions(params)
	if err != nil {
		c.writeError(err)
		return nil
	}

	// Now validate the address with proper UTF8 context
	var from string
	if rawPath != "" {
		parsed, err := parseAddress(rawPath, opts.UTF8)
		if err != nil {
			c.writeResponse(501, fmt.Sprintf("5.1.7 Invalid sender address: %v", err))
			return nil
		}
		from = parsed.String()
	}

	// Check SIZE if specified
	if opts.Size > 0 && c.server.config.MaxMessageBytes > 0 {
		if opts.Size > c.server.config.MaxMessageBytes {
			c.writeError(ErrMessageTooLarge)
			return nil
		}
	}

	// Call session
	if err := c.session.Mail(from, opts); err != nil {
		c.writeError(err)
		return nil
	}

	c.mu.Lock()
	c.state = StateMail
	c.recipientCount = 0
	c.bodyType = opts.Body
	c.smtputf8 = opts.UTF8
	c.mu.Unlock()

	c.writeResponse(250, "2.1.0 OK")
	return nil
}

// handleRCPT handles the RCPT TO command.
func (c *Conn) handleRCPT(args string) error {
	if c.state != StateMail && c.state != StateRcpt {
		c.writeError(errBadSequence)
		return nil
	}

	// Check recipient limit
	if c.recipientCount >= c.server.config.MaxRecipients {
		c.writeError(ErrTooManyRecipients)
		return nil
	}

	// Parse RCPT TO:<address> [parameters]
	if !strings.HasPrefix(strings.ToUpper(args), "TO:") {
		c.writeError(errRcptSyntax)
		return nil
	}

	args = args[3:] // Remove "TO:"

	// Extract path and params
	rawPath, params, err := extractPathAndParams(args)
	if err != nil {
		c.writeResponse(501, fmt.Sprintf("5.1.7 Invalid address syntax: %v", err))
		return nil
	}

	// Validate address - RCPT TO must have a non-null path
	if rawPath == "" {
		c.writeError(errEmptyRecipient)
		return nil
	}

	// Validate address using transaction's SMTPUTF8 state
	c.mu.RLock()
	allowUTF8 := c.smtputf8
	c.mu.RUnlock()

	parsed, err := parseAddress(rawPath, allowUTF8)
	if err != nil {
		c.writeResponse(501, fmt.Sprintf("5.1.3 Invalid recipient address: %v", err))
		return nil
	}
	to := parsed.String()

	// Parse rcpt options
	opts, err := c.parseRcptOptions(params)
	if err != nil {
		c.writeError(err)
		return nil
	}

	// Call session
	if err := c.session.Rcpt(to, opts); err != nil {
		c.writeError(err)
		return nil
	}

	c.mu.Lock()
	c.state = StateRcpt
	c.recipientCount++
	c.mu.Unlock()

	c.writeResponse(250, "2.1.5 OK")
	return nil
}

// RFC 5321 line length limits for message content.
const (
	maxContentLineLength = 1000 // Including CRLF
)

// dataReader implements io.Reader for SMTP DATA content.
// It reads line-by-line, handles dot-stuffing, enforces line length limits,
// and optionally enforces 7-bit ASCII.
type dataReader struct {
	reader      *bufio.Reader
	enforce7Bit bool
	maxSize     int64
	bytesRead   int64
	done        bool
	err         error
	buf         []byte // Unconsumed bytes from the current line
	lineBuf     []byte // Reused only when a line spans the bufio buffer
}

func newDataReader(r *bufio.Reader, enforce7Bit bool, maxSize int64) *dataReader {
	return &dataReader{
		reader:      r,
		enforce7Bit: enforce7Bit,
		maxSize:     maxSize,
	}
}

func (d *dataReader) Read(p []byte) (int, error) {
	if d.err != nil {
		return 0, d.err
	}
	if d.done {
		return 0, io.EOF
	}

	// If we have buffered data, return it first
	if len(d.buf) > 0 {
		n := copy(p, d.buf)
		d.buf = d.buf[n:]
		return n, nil
	}

	// Read the next line as bytes. In the common case this is a zero-copy view
	// into the bufio.Reader and remains valid until the next read from it.
	line, err := d.readLine(d.enforce7Bit)
	if err != nil {
		d.err = err
		return 0, err
	}

	// Check for end of data
	if len(line) == 3 && line[0] == '.' && line[1] == '\r' && line[2] == '\n' {
		d.done = true
		return 0, io.EOF
	}

	// Handle dot-stuffing
	if line[0] == '.' {
		line = line[1:]
	}

	// Check size limit
	if d.maxSize > 0 && d.bytesRead+int64(len(line)) > d.maxSize {
		// Drain remaining data
		d.drainData()
		d.err = ErrMessageTooLarge
		return 0, d.err
	}
	d.bytesRead += int64(len(line))

	// Copy to output buffer
	n := copy(p, line)
	if n < len(line) {
		d.buf = line[n:]
	}

	return n, nil
}

// readLine returns one validated CRLF-terminated DATA line. Lines that fit in
// the bufio buffer require no allocation; lineBuf handles the uncommon case
// where a caller supplied an unusually small buffer.
func (d *dataReader) readLine(enforce7Bit bool) ([]byte, error) {
	line, err := d.reader.ReadSlice('\n')
	if err == nil {
		return d.validateLine(line, enforce7Bit)
	}
	if !errors.Is(err, bufio.ErrBufferFull) {
		return nil, fmt.Errorf("reading SMTP line: %w", err)
	}

	d.lineBuf = append(d.lineBuf[:0], line...)
	if len(d.lineBuf) > maxContentLineLength {
		d.drainLine()
		return nil, ravenio.ErrLineTooLong
	}
	for {
		line, err = d.reader.ReadSlice('\n')
		if len(d.lineBuf)+len(line) > maxContentLineLength {
			if errors.Is(err, bufio.ErrBufferFull) {
				d.drainLine()
			}
			return nil, ravenio.ErrLineTooLong
		}
		d.lineBuf = append(d.lineBuf, line...)
		if err == nil {
			return d.validateLine(d.lineBuf, enforce7Bit)
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, fmt.Errorf("reading continued SMTP line: %w", err)
		}
	}
}

func (d *dataReader) validateLine(line []byte, enforce7Bit bool) ([]byte, error) {
	if len(line) > maxContentLineLength {
		return nil, ravenio.ErrLineTooLong
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return nil, ravenio.ErrBadLineEnding
	}
	if enforce7Bit {
		for _, b := range line {
			if b > 127 {
				return nil, ravenio.Err8BitIn7BitMode
			}
		}
	}
	return line, nil
}

func (d *dataReader) drainLine() {
	for {
		_, err := d.reader.ReadSlice('\n')
		if !errors.Is(err, bufio.ErrBufferFull) {
			return
		}
	}
}

// drainData reads and discards through the DATA terminator. It deliberately
// ignores content validation errors so a rejected transaction cannot leave
// message bytes in the SMTP command stream.
func (d *dataReader) drainData() {
	if d.done {
		return
	}
	d.buf = nil
	d.lineBuf = d.lineBuf[:0]
	atLineStart := true
	for {
		line, err := d.reader.ReadSlice('\n')
		if atLineStart && err == nil && len(line) == 3 && line[0] == '.' && line[1] == '\r' && line[2] == '\n' {
			d.done = true
			return
		}
		switch {
		case err == nil:
			atLineStart = true
		case errors.Is(err, bufio.ErrBufferFull):
			atLineStart = false
		default:
			d.done = true
			return
		}
	}
}

const bdatReadBufferSize = transferbuf.ReadSize

var (
	receivedHeaderName        = []byte("Received:")
	messageHeaderSeparator    = []byte("\r\n\r\n")
	errMessageBodyNotConsumed = errors.New("session returned before consuming the message body")
	errTransactionAborted     = errors.New("message transaction aborted")
)

func readMessageHeaders(r io.Reader, prepended MessageHeaders, maxReceived int) (MessageHeaders, *bufio.Reader, error) {
	br := bufio.NewReader(r)
	headers := make(MessageHeaders, 0, len(prepended)+512)
	headers = append(headers, prepended...)

	receivedCount := 0
	if len(prepended) > 0 {
		receivedCount = 1
		if maxReceived > 0 && receivedCount >= maxReceived {
			return nil, br, errTooManyHops
		}
	}

	for {
		line, err := br.ReadSlice('\n')
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				if len(line) > 0 {
					headers = append(headers, line...)
					if isReceivedHeaderLine(line) {
						receivedCount++
						if maxReceived > 0 && receivedCount >= maxReceived {
							return nil, br, errTooManyHops
						}
					}
				}
				return headers, br, nil
			case errors.Is(err, bufio.ErrBufferFull):
				return nil, br, fmt.Errorf("reading message headers: %w", err)
			default:
				return nil, br, err
			}
		}

		if len(line) == 2 && line[0] == '\r' && line[1] == '\n' {
			return headers, br, nil
		}

		headers = append(headers, line...)
		if isReceivedHeaderLine(line) {
			receivedCount++
			if maxReceived > 0 && receivedCount >= maxReceived {
				return nil, br, errTooManyHops
			}
		}
	}
}

func isReceivedHeaderLine(line []byte) bool {
	if len(line) == 0 {
		return false
	}
	if line[0] == ' ' || line[0] == '\t' {
		return false
	}
	return len(line) >= len(receivedHeaderName) && bytes.EqualFold(line[:len(receivedHeaderName)], receivedHeaderName)
}

func countReceivedHeaders(headers MessageHeaders) int {
	count := 0
	remaining := headers
	for len(remaining) > 0 {
		idx := bytes.Index(remaining, []byte("\r\n"))
		if idx == -1 {
			if isReceivedHeaderLine(remaining) {
				count++
			}
			break
		}

		line := remaining[:idx+2]
		if isReceivedHeaderLine(line) {
			count++
		}
		remaining = remaining[idx+2:]
	}
	return count
}

// generateQueueID returns a random hex string for use as a queue/transaction ID.
func generateQueueID() string {
	b := make([]byte, 8)
	if _, err := crand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

type bdatStreamState struct {
	receivedHeader MessageHeaders
	clientHeaders  MessageHeaders
	bytesRead      int64
	headersDone    bool
	bodyReader     *io.PipeReader
	bodyWriter     *io.PipeWriter
	sessionDone    chan error
	sessionErr     error
	sessionReady   bool
}

func newBdatStreamState(receivedHeader MessageHeaders) *bdatStreamState {
	return &bdatStreamState{
		receivedHeader: append(MessageHeaders(nil), receivedHeader...),
		clientHeaders:  make(MessageHeaders, 0, 512),
	}
}

func (s *bdatStreamState) appendChunk(c *Conn, data []byte) error {
	if len(data) == 0 {
		return nil
	}

	s.bytesRead += int64(len(data))
	if c.server.config.MaxMessageBytes > 0 && s.bytesRead > c.server.config.MaxMessageBytes {
		return ErrMessageTooLarge
	}

	if s.headersDone {
		return s.writeBody(data)
	}

	s.clientHeaders = append(s.clientHeaders, data...)
	idx := bytes.Index(s.clientHeaders, messageHeaderSeparator)
	if idx == -1 {
		return nil
	}

	bodyStart := idx + len(messageHeaderSeparator)
	bodyPrefix := s.clientHeaders[bodyStart:]
	s.clientHeaders = s.clientHeaders[:idx+2]
	s.headersDone = true

	if err := s.startSession(c); err != nil {
		return err
	}
	return s.writeBody(bodyPrefix)
}

func (s *bdatStreamState) startSession(c *Conn) error {
	if s.bodyWriter != nil {
		return nil
	}

	headers := make(MessageHeaders, 0, len(s.receivedHeader)+len(s.clientHeaders))
	headers = append(headers, s.receivedHeader...)
	headers = append(headers, s.clientHeaders...)
	if c.server.config.MaxReceivedHeaders > 0 && countReceivedHeaders(headers) >= c.server.config.MaxReceivedHeaders {
		return errTooManyHops
	}

	bodyReader, bodyWriter := io.Pipe()
	done := make(chan error, 1)
	s.bodyReader = bodyReader
	s.bodyWriter = bodyWriter
	s.sessionDone = done

	go func(headers MessageHeaders, reader *io.PipeReader, done chan<- error) {
		err := c.session.Data(headers, reader)
		if err != nil {
			_ = reader.CloseWithError(err)
		} else {
			_ = reader.Close()
		}
		done <- err
	}(headers, bodyReader, done)

	return nil
}

func (s *bdatStreamState) writeBody(data []byte) error {
	if len(data) == 0 {
		return s.ensureSessionActive()
	}

	for len(data) > 0 {
		n, err := s.bodyWriter.Write(data)
		data = data[n:]
		if err != nil {
			if finished, sessionErr := s.pollSession(); finished {
				if sessionErr != nil {
					return sessionErr
				}
				return errMessageBodyNotConsumed
			}
			return fmt.Errorf("streaming BDAT body: %w", err)
		}
	}

	return s.ensureSessionActive()
}

func (s *bdatStreamState) ensureSessionActive() error {
	if finished, sessionErr := s.pollSession(); finished {
		if sessionErr != nil {
			return sessionErr
		}
		return errMessageBodyNotConsumed
	}
	return nil
}

func (s *bdatStreamState) pollSession() (bool, error) {
	if s.sessionReady {
		return true, s.sessionErr
	}
	if s.sessionDone == nil {
		return false, nil
	}

	select {
	case err := <-s.sessionDone:
		s.sessionErr = err
		s.sessionReady = true
		return true, err
	default:
		return false, nil
	}
}

func (s *bdatStreamState) finish(c *Conn) error {
	if !s.headersDone {
		s.headersDone = true
		if err := s.startSession(c); err != nil {
			return err
		}
	}

	if s.bodyWriter != nil {
		_ = s.bodyWriter.Close()
	}

	if s.sessionReady {
		return s.sessionErr
	}
	if s.sessionDone == nil {
		return nil
	}

	s.sessionErr = <-s.sessionDone
	s.sessionReady = true
	return s.sessionErr
}

func (s *bdatStreamState) abort(err error) {
	if s.bodyWriter != nil {
		_ = s.bodyWriter.CloseWithError(err)
	}
}

// buildReceivedHeader generates a Received header per RFC 5321 §4.4.
func (c *Conn) buildReceivedHeader() string {
	var b strings.Builder

	// Determine protocol string
	protocol := c.protocolString()

	// from <client-hostname> (<client-ip>)
	b.WriteString("Received: from ")
	if c.Hostname != "" {
		b.WriteString(c.Hostname)
	} else {
		b.WriteString("unknown")
	}
	b.WriteString(" (")
	remoteAddr := c.conn.RemoteAddr()
	if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
		b.WriteString(tcpAddr.IP.String())
	} else {
		b.WriteString(remoteAddr.String())
	}
	b.WriteString(")\r\n")

	// by <server-domain> with <protocol> id <queue-id>
	b.WriteString("\tby ")
	b.WriteString(c.server.config.Domain)
	b.WriteString(" with ")
	b.WriteString(protocol)
	b.WriteString(" id ")
	b.WriteString(generateQueueID())
	b.WriteString("\r\n")

	// ; <timestamp>
	b.WriteString("\t; ")
	b.WriteString(time.Now().UTC().Format(time.RFC1123Z))
	b.WriteString("\r\n")

	return b.String()
}

// protocolString returns the SMTP protocol variant string per RFC 3848.
func (c *Conn) protocolString() string {
	hasTLS := c.TLS() != nil
	hasAuth := c.Authenticated()
	hasUTF8 := c.smtputf8

	switch {
	case hasUTF8 && hasTLS && hasAuth:
		return "UTF8SMTPSA"
	case hasUTF8 && hasTLS:
		return "UTF8SMTPS"
	case hasUTF8 && hasAuth:
		return "UTF8SMTPA"
	case hasUTF8:
		return "UTF8SMTP"
	case hasTLS && hasAuth:
		return "ESMTPSA"
	case hasTLS:
		return "ESMTPS"
	case hasAuth:
		return "ESMTPA"
	case c.isESMTP:
		return "ESMTP"
	default:
		return "SMTP"
	}
}

// handleDATA handles the DATA command.
func (c *Conn) handleDATA() error {
	if c.state != StateRcpt {
		c.writeError(errBadSequence)
		return nil
	}

	if c.recipientCount == 0 {
		c.writeError(errNoRecipients)
		return nil
	}

	c.writeResponse(354, "Start mail input; end with <CRLF>.<CRLF>")

	// Set data timeout
	if err := c.conn.SetReadDeadline(time.Now().Add(c.server.config.DataTimeout)); err != nil {
		return fmt.Errorf("setting DATA read deadline: %w", err)
	}

	// Determine if we need to enforce 7-bit (BODY=7BIT or no BODY parameter with strict mode)
	enforce7Bit := c.bodyType == Body7Bit

	// Create data reader with line validation and dot-unstuffing
	dataRdr := newDataReader(c.reader, enforce7Bit, c.server.config.MaxMessageBytes)

	// Parse the header block up front so the session receives headers and a
	// streaming body reader, and reject loops before user code sees the message.
	headers, bodyRdr, err := readMessageHeaders(
		dataRdr,
		MessageHeaders(c.buildReceivedHeader()),
		c.server.config.MaxReceivedHeaders,
	)
	if err != nil {
		if !dataRdr.done {
			dataRdr.drainData()
		}
		c.writeError(err)
		c.resetTransaction()
		return nil
	}

	// Call session
	if err := c.session.Data(headers, bodyRdr); err != nil {
		// Drain remaining data if not already done
		if !dataRdr.done {
			dataRdr.drainData()
		}
		c.writeError(err)
		c.resetTransaction()
		return nil
	}

	// Check if data reader encountered an error
	if dataRdr.err != nil {
		c.writeError(dataRdr.err)
		c.resetTransaction()
		return nil
	}
	if !dataRdr.done {
		dataRdr.drainData()
		c.writeError(errMessageBodyNotConsumed)
		c.resetTransaction()
		return nil
	}

	c.writeResponse(250, "2.0.0 OK")
	c.resetTransaction()
	return nil
}

// handleBDAT handles the BDAT command (CHUNKING extension).
func (c *Conn) handleBDAT(args string) error {
	if c.state != StateRcpt && c.state != StateData {
		c.writeError(errBadSequence)
		return nil
	}
	if c.recipientCount == 0 {
		c.writeError(errNoRecipients)
		return nil
	}

	if !c.server.config.EnableCHUNKING {
		c.writeError(errChunkingNotSupported)
		return nil
	}

	// Parse BDAT <size> [LAST]
	parts := strings.Fields(args)
	if len(parts) < 1 || len(parts) > 2 {
		c.writeError(errBdatSyntax)
		return nil
	}
	if len(parts) == 2 && !strings.EqualFold(parts[1], "LAST") {
		c.writeError(errBdatSyntax)
		return nil
	}

	for _, ch := range parts[0] {
		if ch < '0' || ch > '9' {
			c.writeError(errInvalidChunkSize)
			return nil
		}
	}
	size, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		c.writeError(errInvalidChunkSize)
		return nil
	}

	isLast := len(parts) == 2

	// Set data timeout
	if err := c.conn.SetReadDeadline(time.Now().Add(c.server.config.DataTimeout)); err != nil {
		return fmt.Errorf("setting BDAT read deadline: %w", err)
	}

	if c.bdatState == nil {
		c.bdatState = newBdatStreamState(MessageHeaders(c.buildReceivedHeader()))
	}

	limited := &io.LimitedReader{R: c.reader, N: size}
	buffer := transferbuf.Get(bdatReadBufferSize)
	defer buffer.Release()
	buf := buffer.Bytes
	for limited.N > 0 {
		n, err := limited.Read(buf)
		if n > 0 {
			if appendErr := c.bdatState.appendChunk(c, buf[:n]); appendErr != nil {
				_, _ = io.Copy(io.Discard, limited)
				c.bdatState.abort(appendErr)
				c.writeError(appendErr)
				c.resetTransaction()
				return nil
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && limited.N == 0 {
				break
			}
			c.bdatState.abort(errChunkReadFailed)
			c.writeError(errChunkReadFailed)
			c.resetTransaction()
			return nil
		}
	}

	if !isLast {
		if err := c.bdatState.ensureSessionActive(); err != nil {
			c.bdatState.abort(err)
			c.writeError(err)
			c.resetTransaction()
			return nil
		}
		c.writeResponse(250, fmt.Sprintf("2.0.0 %d bytes received", size))
		c.mu.Lock()
		c.state = StateData
		c.mu.Unlock()
		return nil
	}

	if err := c.bdatState.finish(c); err != nil {
		c.bdatState.abort(err)
		c.writeError(err)
		c.resetTransaction()
		return nil
	}

	c.writeResponse(250, "2.0.0 OK")
	c.resetTransaction()
	return nil
}

// handleRSET handles the RSET command.
func (c *Conn) handleRSET() error {
	c.resetTransaction()
	c.writeResponse(250, "2.0.0 OK")
	return nil
}

// handleVRFY handles the VRFY command.
// If the session implements VRFYSession, the request is delegated.
// Otherwise, returns 502 per RFC 5321 §3.5.1.
func (c *Conn) handleVRFY(args string) error {
	if c.session == nil {
		c.writeError(errCommandNotImplemented)
		return nil
	}
	if vrfy, ok := c.session.(VRFYSession); ok {
		result, err := vrfy.Verify(args)
		if err != nil {
			c.writeError(err)
			return nil
		}
		c.writeResponse(250, result)
		return nil
	}
	c.writeError(errCommandNotImplemented)
	return nil
}

// handleEXPN handles the EXPN command.
// If the session implements EXPNSession, the request is delegated.
// Otherwise, returns 502 per RFC 5321 §3.5.1.
func (c *Conn) handleEXPN(args string) error {
	if c.session == nil {
		c.writeError(errCommandNotImplemented)
		return nil
	}
	if expn, ok := c.session.(EXPNSession); ok {
		results, err := expn.Expand(args)
		if err != nil {
			c.writeError(err)
			return nil
		}
		if len(results) == 0 {
			c.writeError(errMailingListNotFound)
			return nil
		}
		c.writeResponseMulti(250, results)
		return nil
	}
	c.writeError(errCommandNotImplemented)
	return nil
}

// handleHELP handles the HELP command.
func (c *Conn) handleHELP(_ string) error {
	c.writeResponse(214, "See RFC 5321")
	return nil
}

// handleQUIT handles the QUIT command.
func (c *Conn) handleQUIT() error {
	c.writeResponse(221, fmt.Sprintf("2.0.0 %s closing connection", c.server.config.Domain))

	if c.session != nil {
		if err := c.session.Logout(); err != nil {
			c.server.logf("session logout error: %v", err)
		}
	}

	c.mu.Lock()
	c.state = StateQuit
	c.mu.Unlock()

	return nil
}

// resetTransaction resets the current mail transaction.
func (c *Conn) resetTransaction() {
	if c.bdatState != nil {
		c.bdatState.abort(errTransactionAborted)
	}

	if c.session != nil {
		c.session.Reset()
	}

	c.mu.Lock()
	if c.state > StateGreeted {
		c.state = StateGreeted
	}
	c.recipientCount = 0
	c.bodyType = ""
	c.smtputf8 = false
	c.bdatState = nil
	c.mu.Unlock()
}

// writeError writes an error response.
func (c *Conn) writeError(err error) {
	if smtpErr, ok := err.(*SMTPError); ok {
		if smtpErr.EnhancedCode != NoEnhancedCode {
			c.writeResponse(smtpErr.Code, fmt.Sprintf("%s %s", smtpErr.EnhancedCode.String(), smtpErr.Message))
		} else {
			c.writeResponse(smtpErr.Code, smtpErr.Message)
		}
	} else {
		c.writeResponse(451, fmt.Sprintf("4.0.0 %s", err.Error()))
	}
}

// extractPathAndParams extracts the raw path content and parameters from an SMTP path.
// This does minimal parsing - just extracts what's between < and >.
// It also strips source routes per RFC 5321 §3.3 (e.g., "@relay1,@relay2:user@domain" → "user@domain").
// Full address validation is done separately by parseAddress.
func extractPathAndParams(s string) (path, params string, err error) {
	s = strings.TrimSpace(s)

	if s == "" {
		return "", "", errors.New("empty path")
	}

	// Handle null path <>
	if s == "<>" {
		return "", "", nil
	}

	// Must start with <
	if s[0] != '<' {
		return "", "", errors.New("path must start with <")
	}

	// Find closing >
	idx := strings.Index(s, ">")
	if idx == -1 {
		return "", "", errors.New("path must end with >")
	}

	path = s[1:idx]
	params = strings.TrimSpace(s[idx+1:])

	// Strip source route (RFC 5321 §3.3): "@relay1,@relay2:user@domain" → "user@domain"
	if path != "" && path[0] == '@' {
		if colonIdx := strings.LastIndex(path, ":"); colonIdx != -1 {
			path = path[colonIdx+1:]
		}
	}

	return path, params, nil
}

// parseMailOptions parses MAIL FROM parameters.
func (c *Conn) parseMailOptions(params string) (*MailOptions, error) {
	opts := &MailOptions{}

	if params == "" {
		return opts, nil
	}

	for param := range strings.FieldsSeq(params) {
		key, value, _ := strings.Cut(param, "=")
		key = strings.ToUpper(key)

		switch key {
		case "BODY":
			switch strings.ToUpper(value) {
			case "7BIT":
				opts.Body = Body7Bit
			case "8BITMIME":
				opts.Body = Body8BitMIME
			case "BINARYMIME":
				opts.Body = BodyBinaryMIME
			default:
				return nil, &SMTPError{Code: 501, Message: "Invalid BODY value"}
			}

		case "SIZE":
			if _, err := fmt.Sscanf(value, "%d", &opts.Size); err != nil {
				return nil, &SMTPError{Code: 501, Message: "Invalid SIZE value"}
			}

		case "SMTPUTF8":
			if !c.server.config.EnableSMTPUTF8 {
				return nil, &SMTPError{Code: 555, Message: "SMTPUTF8 not supported"}
			}
			opts.UTF8 = true

		case "BY":
			if !c.server.config.EnableDELIVERBY {
				return nil, &SMTPError{Code: 555, Message: "DELIVERBY not supported"}
			}

			deliveryBy, err := parseDeliveryByValue(value)
			if err != nil {
				return nil, err
			}
			if deliveryBy.Mode == DeliveryByModeReturn {
				if deliveryBy.Seconds <= 0 {
					return nil, &SMTPError{Code: 501, Message: "Invalid BY value"}
				}
				if min := c.server.config.DeliveryByMinSeconds; min > 0 && deliveryBy.Seconds < min {
					return nil, &SMTPError{Code: 555, Message: "BY time less than server minimum"}
				}
			}
			opts.DeliveryBy = deliveryBy

		case "REQUIRETLS":
			if !c.server.config.EnableREQUIRETLS || c.TLS() == nil {
				return nil, &SMTPError{Code: 555, Message: "REQUIRETLS not supported"}
			}
			opts.RequireTLS = true

		case "RET":
			if !c.server.config.EnableDSN {
				return nil, &SMTPError{Code: 555, Message: "DSN not supported"}
			}
			switch strings.ToUpper(value) {
			case "FULL":
				opts.Return = DSNReturnFull
			case "HDRS":
				opts.Return = DSNReturnHeaders
			default:
				return nil, &SMTPError{Code: 501, Message: "Invalid RET value"}
			}

		case "ENVID":
			if !c.server.config.EnableDSN {
				return nil, &SMTPError{Code: 555, Message: "DSN not supported"}
			}
			opts.EnvelopeID = value

		case "AUTH":
			if value == "<>" {
				empty := ""
				opts.Auth = &empty
			} else {
				opts.Auth = &value
			}

		default:
			// Unknown parameter - ignore per RFC
		}
	}

	return opts, nil
}

func parseDeliveryByValue(value string) (*DeliveryBy, error) {
	secondsPart, modePart, ok := strings.Cut(value, ";")
	if !ok || secondsPart == "" || modePart == "" {
		return nil, &SMTPError{Code: 501, Message: "Invalid BY value"}
	}

	seconds, err := strconv.ParseInt(secondsPart, 10, 64)
	if err != nil {
		return nil, &SMTPError{Code: 501, Message: "Invalid BY value"}
	}

	modePart = strings.ToUpper(modePart)
	trace := strings.HasSuffix(modePart, "T")
	if trace {
		modePart = strings.TrimSuffix(modePart, "T")
	}

	var mode DeliveryByMode
	switch modePart {
	case string(DeliveryByModeNotify):
		mode = DeliveryByModeNotify
	case string(DeliveryByModeReturn):
		mode = DeliveryByModeReturn
	default:
		return nil, &SMTPError{Code: 501, Message: "Invalid BY value"}
	}

	return &DeliveryBy{
		Seconds: seconds,
		Mode:    mode,
		Trace:   trace,
	}, nil
}

// parseRcptOptions parses RCPT TO parameters.
func (c *Conn) parseRcptOptions(params string) (*RcptOptions, error) {
	opts := &RcptOptions{}

	if params == "" {
		return opts, nil
	}

	for param := range strings.FieldsSeq(params) {
		key, value, _ := strings.Cut(param, "=")
		key = strings.ToUpper(key)

		switch key {
		case "NOTIFY":
			if !c.server.config.EnableDSN {
				return nil, &SMTPError{Code: 555, Message: "DSN not supported"}
			}
			for n := range strings.SplitSeq(value, ",") {
				switch strings.ToUpper(n) {
				case "NEVER":
					opts.Notify = append(opts.Notify, DSNNotifyNever)
				case "SUCCESS":
					opts.Notify = append(opts.Notify, DSNNotifySuccess)
				case "FAILURE":
					opts.Notify = append(opts.Notify, DSNNotifyFailure)
				case "DELAY":
					opts.Notify = append(opts.Notify, DSNNotifyDelay)
				default:
					return nil, &SMTPError{Code: 501, Message: "Invalid NOTIFY value"}
				}
			}

		case "ORCPT":
			if !c.server.config.EnableDSN {
				return nil, &SMTPError{Code: 555, Message: "DSN not supported"}
			}
			opts.OriginalRecipient = value

		default:
			// Unknown parameter - ignore per RFC
		}
	}

	return opts, nil
}
