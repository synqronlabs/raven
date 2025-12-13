package raven

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Transaction errors.
var (
	ErrNoRecipients      = errors.New("smtp: no recipients specified")
	ErrTransactionFailed = errors.New("smtp: transaction failed")
	ErrDataFailed        = errors.New("smtp: DATA command failed")
)

// SendResult contains the result of a mail transaction.
type SendResult struct {
	// Success indicates the overall transaction succeeded.
	Success bool

	// MessageID is the server-assigned message ID (if provided).
	MessageID string

	// Response is the final server response.
	Response *ClientResponse

	// RecipientResults contains per-recipient acceptance status.
	RecipientResults []RecipientResult
}

// RecipientResult contains the result for a single recipient.
type RecipientResult struct {
	// Address is the recipient address.
	Address string

	// Accepted indicates the recipient was accepted.
	Accepted bool

	// Response is the server's response for this recipient.
	Response *ClientResponse

	// Error is set if the recipient was rejected.
	Error error
}

// Send sends a mail message to the server.
// The mail content is validated against RFC 5322 requirements before sending.
func (c *Client) Send(mail *Mail) (*SendResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, ErrNoConnection
	}

	if len(mail.Envelope.To) == 0 {
		return nil, ErrNoRecipients
	}

	// Validate mail content against RFC 5322 requirements
	if c.config.ValidateBeforeSend {
		if err := mail.Content.Validate(); err != nil {
			return nil, fmt.Errorf("mail validation failed: %w", err)
		}
	}

	result := &SendResult{
		RecipientResults: make([]RecipientResult, 0, len(mail.Envelope.To)),
	}

	// Send MAIL FROM with appropriate extensions
	if err := c.sendMailFrom(mail); err != nil {
		return nil, err
	}

	// Send RCPT TO for each recipient
	acceptedCount := 0
	for _, rcpt := range mail.Envelope.To {
		rcptResult := c.sendRcptTo(rcpt)
		result.RecipientResults = append(result.RecipientResults, rcptResult)
		if rcptResult.Accepted {
			acceptedCount++
		}
	}

	// If no recipients were accepted, abort
	if acceptedCount == 0 {
		c.writeCommand("RSET")
		c.readResponse()
		return result, fmt.Errorf("%w: all recipients rejected", ErrTransactionFailed)
	}

	// Send message content
	raw := mail.Content.ToRaw()

	// Use BDAT if available and message is large, otherwise use DATA
	if c.extensions[ExtChunking] != "" && len(raw) > 1024*1024 {
		err := c.sendWithBDAT(raw)
		if err != nil {
			return result, err
		}
	} else {
		resp, err := c.sendWithDATA(raw)
		if err != nil {
			return result, err
		}
		result.Response = resp

		// Try to extract message ID from response
		result.MessageID = extractMessageID(resp.Message)
	}

	result.Success = true
	return result, nil
}

// SendOptions provides options for sending mail.
type SendOptions struct {
	// PreferBDAT forces use of BDAT/CHUNKING if available.
	PreferBDAT bool

	// ChunkSize specifies the chunk size for BDAT transfers.
	// Default is 64KB.
	ChunkSize int

	// SkipCapabilityCheck skips extension capability checks.
	// Use with caution - may cause errors if server doesn't support features.
	SkipCapabilityCheck bool

	// IgnoreRecipientErrors continues even if some recipients are rejected.
	IgnoreRecipientErrors bool

	// RequireAllRecipients fails the transaction if any recipient is rejected.
	RequireAllRecipients bool
}

// SendWithOptions sends mail with custom options.
func (c *Client) SendWithOptions(mail *Mail, opts SendOptions) (*SendResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, ErrNoConnection
	}

	if len(mail.Envelope.To) == 0 {
		return nil, ErrNoRecipients
	}

	result := &SendResult{
		RecipientResults: make([]RecipientResult, 0, len(mail.Envelope.To)),
	}

	// Send MAIL FROM
	if err := c.sendMailFrom(mail); err != nil {
		return nil, err
	}

	// Send RCPT TO
	acceptedCount := 0
	for _, rcpt := range mail.Envelope.To {
		rcptResult := c.sendRcptTo(rcpt)
		result.RecipientResults = append(result.RecipientResults, rcptResult)
		if rcptResult.Accepted {
			acceptedCount++
		} else if opts.RequireAllRecipients {
			c.writeCommand("RSET")
			c.readResponse()
			return result, fmt.Errorf("%w: recipient %s rejected", ErrTransactionFailed, rcpt.Address.Mailbox.String())
		}
	}

	if acceptedCount == 0 {
		c.writeCommand("RSET")
		c.readResponse()
		return result, fmt.Errorf("%w: all recipients rejected", ErrTransactionFailed)
	}

	// Send message content
	raw := mail.Content.ToRaw()

	useBDAT := opts.PreferBDAT && c.extensions[ExtChunking] != ""
	if useBDAT {
		chunkSize := opts.ChunkSize
		if chunkSize <= 0 {
			chunkSize = 64 * 1024 // 64KB default
		}
		err := c.sendWithBDATChunked(raw, chunkSize)
		if err != nil {
			return result, err
		}
	} else {
		resp, err := c.sendWithDATA(raw)
		if err != nil {
			return result, err
		}
		result.Response = resp
		result.MessageID = extractMessageID(resp.Message)
	}

	result.Success = true
	return result, nil
}

// sendMailFrom sends the MAIL FROM command with appropriate extension parameters.
func (c *Client) sendMailFrom(mail *Mail) error {
	var params []string

	// SIZE parameter
	if _, ok := c.extensions[ExtSize]; ok && mail.Envelope.Size > 0 {
		params = append(params, fmt.Sprintf("SIZE=%d", mail.Envelope.Size))
	}

	// BODY parameter (8BITMIME/BINARYMIME)
	if mail.Envelope.BodyType != "" {
		switch mail.Envelope.BodyType {
		case BodyType8BitMIME:
			if _, ok := c.extensions[Ext8BitMIME]; ok {
				params = append(params, "BODY=8BITMIME")
			}
		case BodyTypeBinaryMIME:
			if _, ok := c.extensions[ExtBinaryMIME]; ok {
				params = append(params, "BODY=BINARYMIME")
			}
		}
	}

	// SMTPUTF8 parameter
	if mail.Envelope.SMTPUTF8 {
		if _, ok := c.extensions[ExtSMTPUTF8]; ok {
			params = append(params, "SMTPUTF8")
		}
	}

	// REQUIRETLS parameter (RFC 8689)
	// The REQUIRETLS option MUST only be specified when:
	// - The session is using TLS
	// - The server advertises REQUIRETLS in EHLO
	if mail.Envelope.RequireTLS {
		if _, ok := c.extensions[ExtRequireTLS]; ok {
			params = append(params, "REQUIRETLS")
		} else {
			// Server doesn't support REQUIRETLS but message requires it
			return &SMTPError{
				Code:         550,
				EnhancedCode: ESCRequireTLSRequired.String(),
				Message:      "REQUIRETLS support required",
			}
		}
	}

	// AUTH parameter
	if mail.Envelope.Auth != "" {
		params = append(params, fmt.Sprintf("AUTH=<%s>", mail.Envelope.Auth))
	}

	// DSN parameters (envelope-level)
	if mail.Envelope.DSNParams != nil {
		if _, ok := c.extensions[ExtDSN]; ok {
			if mail.Envelope.DSNParams.RET != "" {
				params = append(params, fmt.Sprintf("RET=%s", mail.Envelope.DSNParams.RET))
			}
		}
	}

	if mail.Envelope.EnvID != "" {
		if _, ok := c.extensions[ExtDSN]; ok {
			params = append(params, fmt.Sprintf("ENVID=%s", mail.Envelope.EnvID))
		}
	}

	// Custom extension parameters
	for name, value := range mail.Envelope.ExtensionParams {
		if value != "" {
			params = append(params, fmt.Sprintf("%s=%s", name, value))
		} else {
			params = append(params, name)
		}
	}

	// Build command
	cmd := "MAIL FROM:" + mail.Envelope.From.String()
	if len(params) > 0 {
		cmd += " " + strings.Join(params, " ")
	}

	if err := c.writeCommand("%s", cmd); err != nil {
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

// sendRcptTo sends a RCPT TO command for a single recipient.
func (c *Client) sendRcptTo(rcpt Recipient) RecipientResult {
	result := RecipientResult{
		Address: rcpt.Address.Mailbox.String(),
	}

	var params []string

	// DSN parameters (per-recipient)
	if rcpt.DSNParams != nil {
		if _, ok := c.extensions[ExtDSN]; ok {
			if len(rcpt.DSNParams.Notify) > 0 {
				params = append(params, fmt.Sprintf("NOTIFY=%s", strings.Join(rcpt.DSNParams.Notify, ",")))
			}
			if rcpt.DSNParams.ORcpt != "" {
				params = append(params, fmt.Sprintf("ORCPT=%s", rcpt.DSNParams.ORcpt))
			}
		}
	}

	cmd := "RCPT TO:" + rcpt.Address.String()
	if len(params) > 0 {
		cmd += " " + strings.Join(params, " ")
	}

	if err := c.writeCommand("%s", cmd); err != nil {
		result.Error = err
		return result
	}

	resp, err := c.readResponse()
	if err != nil {
		result.Error = err
		return result
	}

	result.Response = resp

	if resp.IsSuccess() {
		result.Accepted = true
	} else {
		result.Error = resp.Error()
	}

	return result
}

// sendWithDATA sends message content using the traditional DATA command.
func (c *Client) sendWithDATA(data []byte) (*ClientResponse, error) {
	if err := c.writeCommand("DATA"); err != nil {
		return nil, err
	}

	resp, err := c.readResponse()
	if err != nil {
		return nil, err
	}

	// Expect 354 response
	if !resp.IsIntermediate() {
		return nil, fmt.Errorf("%w: expected 354, got %d", ErrDataFailed, resp.Code)
	}

	// Perform dot-stuffing and send data
	stuffed := dotStuff(data)

	// Write message data
	if c.config.WriteTimeout > 0 {
		c.conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout))
	}

	if _, err := c.writer.Write(stuffed); err != nil {
		return nil, err
	}

	// Ensure data ends with CRLF
	if len(stuffed) < 2 || stuffed[len(stuffed)-2] != '\r' || stuffed[len(stuffed)-1] != '\n' {
		if _, err := c.writer.WriteString("\r\n"); err != nil {
			return nil, err
		}
	}

	// Send terminating sequence
	if _, err := c.writer.WriteString(".\r\n"); err != nil {
		return nil, err
	}

	if err := c.writer.Flush(); err != nil {
		return nil, err
	}

	// Read final response
	resp, err = c.readResponse()
	if err != nil {
		return nil, err
	}

	if !resp.IsSuccess() {
		return resp, resp.Error()
	}

	return resp, nil
}

// sendWithBDAT sends message content using BDAT command (single chunk).
func (c *Client) sendWithBDAT(data []byte) error {
	return c.sendWithBDATChunked(data, len(data))
}

// sendWithBDATChunked sends message content using BDAT command in chunks.
func (c *Client) sendWithBDATChunked(data []byte, chunkSize int) error {
	remaining := data
	isLast := false

	for len(remaining) > 0 {
		chunk := remaining
		if len(chunk) > chunkSize {
			chunk = remaining[:chunkSize]
			remaining = remaining[chunkSize:]
		} else {
			remaining = nil
			isLast = true
		}

		var cmd string
		if isLast {
			cmd = fmt.Sprintf("BDAT %d LAST", len(chunk))
		} else {
			cmd = fmt.Sprintf("BDAT %d", len(chunk))
		}

		if err := c.writeCommand("%s", cmd); err != nil {
			return err
		}

		// Send chunk data (no dot-stuffing needed for BDAT)
		if _, err := c.writer.Write(chunk); err != nil {
			return err
		}

		if err := c.writer.Flush(); err != nil {
			return err
		}

		resp, err := c.readResponse()
		if err != nil {
			return err
		}

		if !resp.IsSuccess() {
			return resp.Error()
		}
	}

	return nil
}

// dotStuff performs SMTP dot-stuffing on the message data.
// Any line beginning with a period gets an additional period prepended.
func dotStuff(data []byte) []byte {
	// Count lines starting with dot
	count := 0
	atLineStart := true
	for _, b := range data {
		if atLineStart && b == '.' {
			count++
		}
		atLineStart = (b == '\n')
	}

	// If no dots at line start, return original
	if count == 0 {
		return data
	}

	// Create new buffer with space for extra dots
	result := make([]byte, 0, len(data)+count)
	atLineStart = true

	for _, b := range data {
		if atLineStart && b == '.' {
			result = append(result, '.')
		}
		result = append(result, b)
		atLineStart = (b == '\n')
	}

	return result
}

// extractMessageID tries to extract a message ID from the server response.
func extractMessageID(msg string) string {
	// Common patterns: "queued as ABC123", "id=ABC123", "<ABC123@server>"
	msg = strings.TrimSpace(msg)

	// Look for angle-bracketed ID
	if start := strings.Index(msg, "<"); start != -1 {
		if end := strings.Index(msg[start:], ">"); end != -1 {
			return msg[start : start+end+1]
		}
	}

	// Look for "queued as" pattern
	if idx := strings.Index(strings.ToLower(msg), "queued as "); idx != -1 {
		parts := strings.Fields(msg[idx+10:])
		if len(parts) > 0 {
			return parts[0]
		}
	}

	// Look for "id=" pattern
	if idx := strings.Index(strings.ToLower(msg), "id="); idx != -1 {
		parts := strings.Fields(msg[idx+3:])
		if len(parts) > 0 {
			return parts[0]
		}
	}

	return ""
}

// Verify sends the VRFY command to verify an address.
// Returns the verified address or an error if verification fails.
func (c *Client) Verify(address string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return "", ErrNoConnection
	}

	if err := c.writeCommand("VRFY %s", address); err != nil {
		return "", err
	}

	resp, err := c.readResponse()
	if err != nil {
		return "", err
	}

	if !resp.IsSuccess() {
		return "", resp.Error()
	}

	return resp.Message, nil
}

// Expand sends the EXPN command to expand a mailing list.
// Returns the list of addresses or an error.
func (c *Client) Expand(listName string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, ErrNoConnection
	}

	if err := c.writeCommand("EXPN %s", listName); err != nil {
		return nil, err
	}

	resp, err := c.readResponse()
	if err != nil {
		return nil, err
	}

	if !resp.IsSuccess() {
		return nil, resp.Error()
	}

	return resp.Lines, nil
}

// SendMultiple sends multiple messages in a single connection.
// This is more efficient than sending messages one at a time.
func (c *Client) SendMultiple(mails []*Mail) ([]*SendResult, error) {
	results := make([]*SendResult, 0, len(mails))

	for _, mail := range mails {
		result, err := c.Send(mail)
		if err != nil {
			// If transaction failed, try to reset and continue
			c.Reset()
			results = append(results, &SendResult{
				Success: false,
			})
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

// RawCommand sends a raw SMTP command and returns the response.
// This is for advanced use cases where you need to send custom commands.
func (c *Client) RawCommand(command string) (*ClientResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, ErrNoConnection
	}

	if err := c.writeCommand("%s", command); err != nil {
		return nil, err
	}

	return c.readResponse()
}

// RawData sends raw data to the server (e.g., for DATA content).
// The data should include the terminating ".\r\n".
func (c *Client) RawData(data []byte) (*ClientResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, ErrNoConnection
	}

	if c.config.WriteTimeout > 0 {
		c.conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout))
	}

	if _, err := c.writer.Write(data); err != nil {
		return nil, err
	}

	if err := c.writer.Flush(); err != nil {
		return nil, err
	}

	return c.readResponse()
}

// PipelineCommands sends multiple commands without waiting for responses (pipelining).
// Returns responses in the same order as commands.
// The server must support PIPELINING extension.
func (c *Client) PipelineCommands(commands []string) ([]*ClientResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, ErrNoConnection
	}

	// Check pipelining support
	if _, ok := c.extensions[ExtPipelining]; !ok {
		return nil, fmt.Errorf("%w: PIPELINING", ErrExtensionNotSupported)
	}

	// Send all commands
	for _, cmd := range commands {
		if err := c.writeCommand("%s", cmd); err != nil {
			return nil, err
		}
	}

	// Read all responses
	responses := make([]*ClientResponse, 0, len(commands))
	for range commands {
		resp, err := c.readResponse()
		if err != nil {
			return responses, err
		}
		responses = append(responses, resp)
	}

	return responses, nil
}

// StreamData streams large message data to the server using an io.Reader.
// This is more memory-efficient for very large messages.
func (c *Client) StreamData(r io.Reader) (*ClientResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, ErrNoConnection
	}

	// Send DATA command
	if err := c.writeCommand("DATA"); err != nil {
		return nil, err
	}

	resp, err := c.readResponse()
	if err != nil {
		return nil, err
	}

	if !resp.IsIntermediate() {
		return nil, fmt.Errorf("%w: expected 354, got %d", ErrDataFailed, resp.Code)
	}

	// Stream data with dot-stuffing
	if err := c.streamWithDotStuffing(r); err != nil {
		return nil, err
	}

	// Send terminating sequence
	if _, err := c.writer.WriteString(".\r\n"); err != nil {
		return nil, err
	}

	if err := c.writer.Flush(); err != nil {
		return nil, err
	}

	return c.readResponse()
}

// streamWithDotStuffing streams data while performing dot-stuffing.
func (c *Client) streamWithDotStuffing(r io.Reader) error {
	buf := make([]byte, 4096)
	atLineStart := true

	for {
		n, err := r.Read(buf)
		if n > 0 {
			data := buf[:n]

			// Process and write with dot-stuffing
			var out bytes.Buffer
			for _, b := range data {
				if atLineStart && b == '.' {
					out.WriteByte('.')
				}
				out.WriteByte(b)
				atLineStart = (b == '\n')
			}

			if _, err := c.writer.Write(out.Bytes()); err != nil {
				return err
			}
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	// Ensure data ends with CRLF
	if !atLineStart {
		if _, err := c.writer.WriteString("\r\n"); err != nil {
			return err
		}
	}

	return nil
}

// MaxSize returns the server's maximum message size (0 = unlimited/not advertised).
func (c *Client) MaxSize() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	if param, ok := c.extensions[ExtSize]; ok && param != "" {
		size, err := strconv.ParseInt(param, 10, 64)
		if err == nil {
			return size
		}
	}
	return 0
}
