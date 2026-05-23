package client

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	ravenmail "github.com/synqronlabs/raven/mail"
)

// escRequireTLSRequired is the enhanced status code for REQUIRETLS required (5.7.30).
const escRequireTLSRequired = "5.7.30"

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
func (c *Client) Send(mail *ravenmail.Mail) (*SendResult, error) {
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
		return nil, fmt.Errorf("sending MAIL FROM command: %w", err)
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
		c.bestEffortRSET()
		return result, fmt.Errorf("%w: all recipients rejected", ErrTransactionFailed)
	}

	// Send message content
	raw := mail.Content.ToRaw()

	// Use BDAT if available and message is large, otherwise use DATA
	if c.extensions[ravenmail.ExtChunking] != "" && len(raw) > 1024*1024 {
		err := c.sendWithBDAT(raw)
		if err != nil {
			return result, fmt.Errorf("sending message body with BDAT: %w", err)
		}
	} else {
		resp, err := c.sendWithDATA(raw)
		if err != nil {
			return result, fmt.Errorf("sending message body with DATA: %w", err)
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

// RawMessage contains a raw RFC 5322 message stream and the SMTP envelope
// used to deliver it.
type RawMessage struct {
	Envelope ravenmail.Envelope
	Data     io.Reader
}

// SendRaw streams a raw RFC 5322 message to the server.
//
// The caller supplies the SMTP envelope separately from the message stream.
// Data is streamed directly through DATA with SMTP dot-stuffing; it is not
// parsed, validated, or buffered in memory.
func (c *Client) SendRaw(envelope ravenmail.Envelope, data io.Reader) (*SendResult, error) {
	return c.SendRawWithOptions(envelope, data, SendOptions{})
}

// SendRawWithOptions streams a raw RFC 5322 message with custom send options.
func (c *Client) SendRawWithOptions(envelope ravenmail.Envelope, data io.Reader, opts SendOptions) (*SendResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, ErrNoConnection
	}

	if data == nil {
		return nil, errors.New("smtp: raw message data is nil")
	}

	result, acceptedCount, err := c.sendEnvelope(envelope, opts)
	if err != nil {
		return result, err
	}
	if acceptedCount == 0 {
		c.bestEffortRSET()
		return result, fmt.Errorf("%w: all recipients rejected", ErrTransactionFailed)
	}

	useBDAT := opts.PreferBDAT && c.extensions[ravenmail.ExtChunking] != ""
	if useBDAT {
		chunkSize := opts.ChunkSize
		if chunkSize <= 0 {
			chunkSize = 64 * 1024
		}
		if err := c.sendStreamWithBDAT(data, chunkSize); err != nil {
			return result, fmt.Errorf("sending raw message body with BDAT chunks: %w", err)
		}
	} else {
		resp, err := c.sendStreamWithDATA(data)
		if err != nil {
			return result, fmt.Errorf("sending raw message body with DATA: %w", err)
		}
		result.Response = resp
		result.MessageID = extractMessageID(resp.Message)
	}

	result.Success = true
	return result, nil
}

// SendWithOptions sends mail with custom options.
func (c *Client) SendWithOptions(mail *ravenmail.Mail, opts SendOptions) (*SendResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, ErrNoConnection
	}

	if len(mail.Envelope.To) == 0 {
		return nil, ErrNoRecipients
	}

	result, acceptedCount, err := c.sendEnvelope(mail.Envelope, opts)
	if err != nil {
		return result, err
	}
	if acceptedCount == 0 {
		c.bestEffortRSET()
		return result, fmt.Errorf("%w: all recipients rejected", ErrTransactionFailed)
	}

	// Send message content
	raw := mail.Content.ToRaw()

	useBDAT := opts.PreferBDAT && c.extensions[ravenmail.ExtChunking] != ""
	if useBDAT {
		chunkSize := opts.ChunkSize
		if chunkSize <= 0 {
			chunkSize = 64 * 1024 // 64KB default
		}
		err := c.sendWithBDATChunked(raw, chunkSize)
		if err != nil {
			return result, fmt.Errorf("sending message body with BDAT chunks: %w", err)
		}
	} else {
		resp, err := c.sendWithDATA(raw)
		if err != nil {
			return result, fmt.Errorf("sending message body with DATA: %w", err)
		}
		result.Response = resp
		result.MessageID = extractMessageID(resp.Message)
	}

	result.Success = true
	return result, nil
}

// sendMailFrom sends the MAIL FROM command with appropriate extension parameters.
func (c *Client) sendMailFrom(mail *ravenmail.Mail) error {
	return c.sendMailFromEnvelope(mail.Envelope)
}

func (c *Client) sendEnvelope(envelope ravenmail.Envelope, opts SendOptions) (*SendResult, int, error) {
	if len(envelope.To) == 0 {
		return nil, 0, ErrNoRecipients
	}

	result := &SendResult{
		RecipientResults: make([]RecipientResult, 0, len(envelope.To)),
	}

	if err := c.sendMailFromEnvelope(envelope); err != nil {
		return nil, 0, fmt.Errorf("sending MAIL FROM command: %w", err)
	}

	acceptedCount := 0
	for _, rcpt := range envelope.To {
		rcptResult := c.sendRcptTo(rcpt)
		result.RecipientResults = append(result.RecipientResults, rcptResult)
		if rcptResult.Accepted {
			acceptedCount++
		} else if opts.RequireAllRecipients {
			c.bestEffortRSET()
			return result, acceptedCount, fmt.Errorf("%w: recipient %s rejected", ErrTransactionFailed, rcpt.Address.Mailbox.String())
		}
	}

	return result, acceptedCount, nil
}

func (c *Client) sendMailFromEnvelope(envelope ravenmail.Envelope) error {
	var params []string

	// SIZE parameter
	if _, ok := c.extensions[ravenmail.ExtSize]; ok && envelope.Size > 0 {
		params = append(params, fmt.Sprintf("SIZE=%d", envelope.Size))
	}

	// BODY parameter (8BITMIME/BINARYMIME)
	if envelope.BodyType != "" {
		switch envelope.BodyType {
		case ravenmail.BodyType8BitMIME:
			if _, ok := c.extensions[ravenmail.Ext8BitMIME]; ok {
				params = append(params, "BODY=8BITMIME")
			}
		case ravenmail.BodyTypeBinaryMIME:
			if _, ok := c.extensions[ravenmail.ExtBinaryMIME]; ok {
				params = append(params, "BODY=BINARYMIME")
			}
		}
	}

	// SMTPUTF8 parameter
	if envelope.SMTPUTF8 {
		if _, ok := c.extensions[ravenmail.ExtSMTPUTF8]; ok {
			params = append(params, "SMTPUTF8")
		}
	}

	// REQUIRETLS parameter (RFC 8689)
	// The REQUIRETLS option MUST only be specified when:
	// - The session is using TLS
	// - The server advertises REQUIRETLS in EHLO
	if envelope.RequireTLS {
		if !c.isTLS {
			return &SMTPError{
				Code:         550,
				EnhancedCode: escRequireTLSRequired,
				Message:      "REQUIRETLS requires an active TLS session",
			}
		}
		if _, ok := c.extensions[ravenmail.ExtRequireTLS]; ok {
			params = append(params, "REQUIRETLS")
		} else {
			// Server doesn't support REQUIRETLS but message requires it
			return &SMTPError{
				Code:         550,
				EnhancedCode: escRequireTLSRequired,
				Message:      "REQUIRETLS support required",
			}
		}
	}

	// DELIVERBY parameter (RFC 2852)
	if envelope.DeliveryBy != nil {
		if _, ok := c.extensions[ravenmail.ExtDeliverBy]; !ok {
			return ErrDeliveryByNotSupported
		}

		value, err := formatDeliveryBy(envelope.DeliveryBy)
		if err != nil {
			return err
		}
		if envelope.DeliveryBy.Mode == ravenmail.DeliveryByModeReturn {
			minSeconds, err := parseDeliveryByMinimum(c.extensions[ravenmail.ExtDeliverBy])
			if err == nil && minSeconds > 0 && envelope.DeliveryBy.Seconds < minSeconds {
				return fmt.Errorf("smtp: DELIVERYBY BY time %d is below server minimum %d", envelope.DeliveryBy.Seconds, minSeconds)
			}
		}
		params = append(params, "BY="+value)
	}

	// AUTH parameter
	if envelope.Auth != "" {
		params = append(params, fmt.Sprintf("AUTH=<%s>", envelope.Auth))
	}

	// DSN parameters (envelope-level)
	if envelope.DSNParams != nil {
		if _, ok := c.extensions[ravenmail.ExtDSN]; ok {
			if envelope.DSNParams.RET != "" {
				params = append(params, fmt.Sprintf("RET=%s", envelope.DSNParams.RET))
			}
		}
	}

	if envelope.EnvID != "" {
		if _, ok := c.extensions[ravenmail.ExtDSN]; ok {
			params = append(params, fmt.Sprintf("ENVID=%s", envelope.EnvID))
		}
	}

	// Custom extension parameters
	for name, value := range envelope.ExtensionParams {
		if strings.EqualFold(name, "BY") && envelope.DeliveryBy != nil {
			continue
		}
		if value != "" {
			params = append(params, fmt.Sprintf("%s=%s", name, value))
		} else {
			params = append(params, name)
		}
	}

	// Build command
	cmd := "MAIL FROM:" + envelope.From.String()
	if len(params) > 0 {
		cmd += " " + strings.Join(params, " ")
	}

	if err := c.writeCommand("%s", cmd); err != nil {
		return fmt.Errorf("writing MAIL FROM command: %w", err)
	}

	resp, err := c.readResponse()
	if err != nil {
		return fmt.Errorf("reading MAIL FROM response: %w", err)
	}

	if !resp.IsSuccess() {
		return resp.Error()
	}

	return nil
}

func formatDeliveryBy(deliveryBy *ravenmail.DeliveryBy) (string, error) {
	if deliveryBy == nil {
		return "", errors.New("smtp: DELIVERYBY configuration is nil")
	}

	mode := ravenmail.DeliveryByMode(strings.ToUpper(string(deliveryBy.Mode)))
	switch mode {
	case ravenmail.DeliveryByModeNotify:
	case ravenmail.DeliveryByModeReturn:
		if deliveryBy.Seconds <= 0 {
			return "", errors.New("smtp: DELIVERYBY mode R requires seconds > 0")
		}
	default:
		return "", fmt.Errorf("smtp: invalid DELIVERYBY mode %q", deliveryBy.Mode)
	}

	value := fmt.Sprintf("%d;%s", deliveryBy.Seconds, mode)
	if deliveryBy.Trace {
		value += "T"
	}
	return value, nil
}

func parseDeliveryByMinimum(param string) (int64, error) {
	param = strings.TrimSpace(param)
	if param == "" {
		return 0, nil
	}

	minSeconds, err := strconv.ParseInt(param, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("smtp: invalid DELIVERBY minimum %q: %w", param, err)
	}
	return minSeconds, nil
}

// bestEffortRSET attempts to reset the current transaction state.
func (c *Client) bestEffortRSET() {
	if err := c.writeCommand("RSET"); err != nil {
		return
	}
	if _, err := c.readResponse(); err != nil {
		return
	}
}

// sendRcptTo sends a RCPT TO command for a single recipient.
func (c *Client) sendRcptTo(rcpt ravenmail.Recipient) RecipientResult {
	result := RecipientResult{
		Address: rcpt.Address.Mailbox.String(),
	}

	var params []string

	// DSN parameters (per-recipient)
	if rcpt.DSNParams != nil {
		if _, ok := c.extensions[ravenmail.ExtDSN]; ok {
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
		result.Error = fmt.Errorf("writing RCPT TO command for %s: %w", rcpt.Address.Mailbox.String(), err)
		return result
	}

	resp, err := c.readResponse()
	if err != nil {
		result.Error = fmt.Errorf("reading RCPT TO response for %s: %w", rcpt.Address.Mailbox.String(), err)
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
		return nil, fmt.Errorf("writing DATA command: %w", err)
	}

	resp, err := c.readResponse()
	if err != nil {
		return nil, fmt.Errorf("reading DATA intermediate response: %w", err)
	}

	// Expect 354 response
	if !resp.IsIntermediate() {
		return nil, fmt.Errorf("%w: expected 354, got %d", ErrDataFailed, resp.Code)
	}

	// Perform dot-stuffing and send data
	stuffed := dotStuff(data)

	// Write message data
	if c.config.WriteTimeout > 0 {
		if err := c.conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout)); err != nil {
			return nil, fmt.Errorf("setting write deadline for DATA payload: %w", err)
		}
	}

	if _, err := c.writer.Write(stuffed); err != nil {
		return nil, fmt.Errorf("writing DATA payload: %w", err)
	}

	// Ensure data ends with CRLF
	if len(stuffed) < 2 || stuffed[len(stuffed)-2] != '\r' || stuffed[len(stuffed)-1] != '\n' {
		if _, err := c.writer.WriteString("\r\n"); err != nil {
			return nil, fmt.Errorf("writing trailing CRLF for DATA payload: %w", err)
		}
	}

	// Send terminating sequence
	if _, err := c.writer.WriteString(".\r\n"); err != nil {
		return nil, fmt.Errorf("writing DATA terminator: %w", err)
	}

	if err := c.writer.Flush(); err != nil {
		return nil, fmt.Errorf("flushing DATA payload: %w", err)
	}

	// Read final response
	resp, err = c.readResponse()
	if err != nil {
		return nil, fmt.Errorf("reading DATA final response: %w", err)
	}

	if !resp.IsSuccess() {
		errResp := resp.Error()
		return resp, errResp
	}

	return resp, nil
}

func (c *Client) sendStreamWithDATA(r io.Reader) (*ClientResponse, error) {
	if err := c.writeCommand("DATA"); err != nil {
		return nil, fmt.Errorf("writing DATA command: %w", err)
	}

	resp, err := c.readResponse()
	if err != nil {
		return nil, fmt.Errorf("reading DATA stream intermediate response: %w", err)
	}

	if !resp.IsIntermediate() {
		return nil, fmt.Errorf("%w: expected 354, got %d", ErrDataFailed, resp.Code)
	}

	if c.config.WriteTimeout > 0 {
		if err := c.conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout)); err != nil {
			return nil, fmt.Errorf("setting write deadline for DATA stream payload: %w", err)
		}
	}

	if err := c.streamWithDotStuffing(r); err != nil {
		return nil, fmt.Errorf("streaming DATA payload: %w", err)
	}

	if _, err := c.writer.WriteString(".\r\n"); err != nil {
		return nil, fmt.Errorf("writing DATA stream terminator: %w", err)
	}

	if err := c.writer.Flush(); err != nil {
		return nil, fmt.Errorf("flushing DATA stream payload: %w", err)
	}

	finalResp, err := c.readResponse()
	if err != nil {
		return nil, fmt.Errorf("reading DATA stream final response: %w", err)
	}
	if !finalResp.IsSuccess() {
		return finalResp, finalResp.Error()
	}
	return finalResp, nil
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
			return fmt.Errorf("writing BDAT command: %w", err)
		}

		// Send chunk data (no dot-stuffing needed for BDAT)
		if _, err := c.writer.Write(chunk); err != nil {
			return fmt.Errorf("writing BDAT chunk (%d bytes): %w", len(chunk), err)
		}

		if err := c.writer.Flush(); err != nil {
			return fmt.Errorf("flushing BDAT chunk (%d bytes): %w", len(chunk), err)
		}

		resp, err := c.readResponse()
		if err != nil {
			return fmt.Errorf("reading BDAT response: %w", err)
		}

		if !resp.IsSuccess() {
			return resp.Error()
		}
	}

	return nil
}

func (c *Client) sendStreamWithBDAT(r io.Reader, chunkSize int) error {
	if chunkSize <= 0 {
		return errors.New("smtp: BDAT chunk size must be positive")
	}

	buf := make([]byte, chunkSize)
	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			if c.config.WriteTimeout > 0 {
				if err := c.conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout)); err != nil {
					return fmt.Errorf("setting write deadline for BDAT stream chunk: %w", err)
				}
			}

			isLast := readErr == io.EOF
			cmd := fmt.Sprintf("BDAT %d", n)
			if isLast {
				cmd += " LAST"
			}
			if err := c.writeCommand("%s", cmd); err != nil {
				return fmt.Errorf("writing BDAT stream command: %w", err)
			}
			if _, err := c.writer.Write(buf[:n]); err != nil {
				return fmt.Errorf("writing BDAT stream chunk (%d bytes): %w", n, err)
			}
			if err := c.writer.Flush(); err != nil {
				return fmt.Errorf("flushing BDAT stream chunk (%d bytes): %w", n, err)
			}
			resp, err := c.readResponse()
			if err != nil {
				return fmt.Errorf("reading BDAT stream response: %w", err)
			}
			if !resp.IsSuccess() {
				return resp.Error()
			}
			if isLast {
				return nil
			}
		}

		if readErr == io.EOF {
			if err := c.writeCommand("BDAT 0 LAST"); err != nil {
				return fmt.Errorf("writing empty BDAT LAST command: %w", err)
			}
			resp, err := c.readResponse()
			if err != nil {
				return fmt.Errorf("reading empty BDAT LAST response: %w", err)
			}
			if !resp.IsSuccess() {
				return resp.Error()
			}
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("reading stream source data: %w", readErr)
		}
	}
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
		return "", fmt.Errorf("writing VRFY command: %w", err)
	}

	resp, err := c.readResponse()
	if err != nil {
		return "", fmt.Errorf("reading VRFY response: %w", err)
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
		return nil, fmt.Errorf("writing EXPN command: %w", err)
	}

	resp, err := c.readResponse()
	if err != nil {
		return nil, fmt.Errorf("reading EXPN response: %w", err)
	}

	if !resp.IsSuccess() {
		return nil, resp.Error()
	}

	return resp.Lines, nil
}

// SendMultiple sends multiple messages in a single connection.
// This is more efficient than sending messages one at a time.
func (c *Client) SendMultiple(mails []*ravenmail.Mail) ([]*SendResult, error) {
	results := make([]*SendResult, 0, len(mails))

	for _, mail := range mails {
		result, err := c.Send(mail)
		if err != nil {
			// If transaction failed, try to reset and continue
			if resetErr := c.Reset(); resetErr != nil {
				if closeErr := c.Close(); closeErr != nil {
					_ = closeErr
				}
			}
			results = append(results, &SendResult{
				Success: false,
			})
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

// SendRawMultiple streams multiple raw messages in a single SMTP connection.
// Each message is sent as an independent transaction.
func (c *Client) SendRawMultiple(messages []RawMessage) ([]*SendResult, error) {
	results := make([]*SendResult, 0, len(messages))

	for _, msg := range messages {
		result, err := c.SendRaw(msg.Envelope, msg.Data)
		if err != nil {
			if resetErr := c.Reset(); resetErr != nil {
				if closeErr := c.Close(); closeErr != nil {
					_ = closeErr
				}
			}
			if result == nil {
				result = &SendResult{Success: false}
			} else {
				result.Success = false
			}
			results = append(results, result)
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
		return nil, fmt.Errorf("writing raw SMTP command %q: %w", command, err)
	}

	resp, err := c.readResponse()
	if err != nil {
		return nil, fmt.Errorf("reading response to raw SMTP command %q: %w", command, err)
	}
	return resp, nil
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
		if err := c.conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout)); err != nil {
			return nil, fmt.Errorf("setting write deadline for raw SMTP data: %w", err)
		}
	}

	if _, err := c.writer.Write(data); err != nil {
		return nil, fmt.Errorf("writing raw SMTP data: %w", err)
	}

	if err := c.writer.Flush(); err != nil {
		return nil, fmt.Errorf("flushing raw SMTP data: %w", err)
	}

	resp, err := c.readResponse()
	if err != nil {
		return nil, fmt.Errorf("reading response to raw SMTP data: %w", err)
	}
	return resp, nil
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
	if _, ok := c.extensions[ravenmail.ExtPipelining]; !ok {
		return nil, fmt.Errorf("%w: PIPELINING", ErrExtensionNotSupported)
	}

	// Send all commands
	for _, cmd := range commands {
		if err := c.writeCommand("%s", cmd); err != nil {
			return nil, fmt.Errorf("writing pipelined command %q: %w", cmd, err)
		}
	}

	// Read all responses
	responses := make([]*ClientResponse, 0, len(commands))
	for range commands {
		resp, err := c.readResponse()
		if err != nil {
			return responses, fmt.Errorf("reading pipelined command response: %w", err)
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

	return c.sendStreamWithDATA(r)
}

// streamWithDotStuffing streams data while performing dot-stuffing.
func (c *Client) streamWithDotStuffing(r io.Reader) error {
	buf := make([]byte, 32*1024)
	out := make([]byte, 0, len(buf)+512)
	atLineStart := true
	var last byte
	wrote := false

	for {
		n, err := r.Read(buf)
		if n > 0 {
			data := buf[:n]

			out = out[:0]
			for _, b := range data {
				if atLineStart && b == '.' {
					out = append(out, '.')
				}
				out = append(out, b)
				atLineStart = (b == '\n')
				last = b
				wrote = true
			}

			if _, err := c.writer.Write(out); err != nil {
				return fmt.Errorf("writing streamed DATA chunk: %w", err)
			}
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading stream source data: %w", err)
		}
	}

	// Ensure data ends with CRLF
	if wrote && last != '\n' {
		if _, err := c.writer.WriteString("\r\n"); err != nil {
			return fmt.Errorf("writing trailing CRLF for streamed DATA payload: %w", err)
		}
	}

	return nil
}

// MaxSize returns the server's maximum message size (0 = unlimited/not advertised).
func (c *Client) MaxSize() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	if param, ok := c.extensions[ravenmail.ExtSize]; ok && param != "" {
		size, err := strconv.ParseInt(param, 10, 64)
		if err == nil {
			return size
		}
	}
	return 0
}
