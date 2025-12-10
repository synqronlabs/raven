package raven

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/synqronlabs/raven/utils"
)

// handleHelo processes the HELO command.
func (s *Server) handleHelo(conn *Connection, hostname string) *Response {
	if hostname == "" {
		return &Response{Code: CodeSyntaxError, Message: "Hostname required"}
	}

	// Callback
	if s.config.Callbacks != nil && s.config.Callbacks.OnHelo != nil {
		if err := s.config.Callbacks.OnHelo(conn.Context(), conn, hostname); err != nil {
			return &Response{Code: CodeMailboxNotFound, Message: err.Error()}
		}
	}

	conn.SetClientHostname(hostname)
	conn.SetState(StateGreeted)
	conn.ResetTransaction()

	ip, err := utils.GetIPFromAddr(conn.RemoteAddr())
	if err != nil {
		ip = net.IPv4zero
	}

	msg := fmt.Sprintf("%s Hello %s [%s]", s.config.Hostname, ip.String(), conn.Trace.ID)
	if conn.Trace.ReverseDNS != "" {
		msg = fmt.Sprintf("%s Hello %s (%s) [%s]", s.config.Hostname, ip.String(), conn.Trace.ReverseDNS, conn.Trace.ID)
	}
	return &Response{
		Code:    CodeOK,
		Message: msg,
	}
}

// handleEhlo processes the EHLO command.
func (s *Server) handleEhlo(conn *Connection, hostname string) *Response {
	if hostname == "" {
		return &Response{Code: CodeSyntaxError, Message: "Hostname required"}
	}

	// Build extension list
	extensions := make(map[Extension]string)

	if s.config.Enable8BitMIME {
		extensions[Ext8BitMIME] = ""
		conn.SetExtension(Ext8BitMIME, "")
	}
	if s.config.EnableSMTPUTF8 {
		// RFC 6531 Section 3.1 (item 8): Servers offering SMTPUTF8 MUST provide
		// support for, and announce, the 8BITMIME extension.
		if !s.config.Enable8BitMIME {
			// Implicitly enable 8BITMIME when SMTPUTF8 is enabled
			extensions[Ext8BitMIME] = ""
			conn.SetExtension(Ext8BitMIME, "")
		}
		extensions[ExtSMTPUTF8] = ""
		conn.SetExtension(ExtSMTPUTF8, "")
	}
	if s.config.TLSConfig != nil && !conn.IsTLS() {
		extensions[ExtSTARTTLS] = ""
		conn.SetExtension(ExtSTARTTLS, "")
	}
	if s.config.MaxMessageSize > 0 {
		extensions[ExtSize] = strconv.FormatInt(s.config.MaxMessageSize, 10)
		conn.SetExtension(ExtSize, strconv.FormatInt(s.config.MaxMessageSize, 10))
	}
	if s.config.EnableDSN {
		extensions[ExtDSN] = ""
		conn.SetExtension(ExtDSN, "")
	}
	if s.config.EnableChunking {
		extensions[ExtChunking] = ""
		conn.SetExtension(ExtChunking, "")
		// RFC 3030 Section 3: BINARYMIME requires CHUNKING
		extensions[ExtBinaryMIME] = ""
		conn.SetExtension(ExtBinaryMIME, "")
	}
	// Only advertise AUTH if TLS is not required, or if TLS is active
	if len(s.config.AuthMechanisms) > 0 && (!s.config.RequireTLS || conn.IsTLS()) {
		authParams := strings.Join(s.config.AuthMechanisms, " ")
		extensions[ExtAuth] = authParams
		conn.SetExtension(ExtAuth, authParams)
	}
	extensions[ExtEnhancedStatusCodes] = ""
	conn.SetExtension(ExtEnhancedStatusCodes, "")

	// Callback - may modify extensions
	if s.config.Callbacks != nil && s.config.Callbacks.OnEhlo != nil {
		extOverride, err := s.config.Callbacks.OnEhlo(conn.Context(), conn, hostname)
		if err != nil {
			return &Response{Code: CodeMailboxNotFound, Message: err.Error()}
		}
		if extOverride != nil {
			extensions = extOverride
		}
	}

	conn.SetClientHostname(hostname)
	conn.SetState(StateGreeted)
	conn.ResetTransaction()

	ip, err := utils.GetIPFromAddr(conn.RemoteAddr())
	if err != nil {
		ip = net.IPv4zero
	}

	// Build multiline response
	greeting := fmt.Sprintf("%s Hello %s [%s]", s.config.Hostname, ip.String(), conn.Trace.ID)
	if conn.Trace.ReverseDNS != "" {
		greeting = fmt.Sprintf("%s Hello %s (%s) [%s]", s.config.Hostname, ip.String(), conn.Trace.ReverseDNS, conn.Trace.ID)
	}
	lines := []string{greeting}
	for ext, params := range extensions {
		if params != "" {
			lines = append(lines, fmt.Sprintf("%s %s", ext, params))
		} else {
			lines = append(lines, string(ext))
		}
	}

	s.writeMultilineResponse(conn, CodeOK, lines)
	return nil
}

// handleMail processes the MAIL FROM command.
func (s *Server) handleMail(conn *Connection, args string) *Response {
	if conn.State() < StateGreeted {
		return &Response{Code: CodeBadSequence, Message: "Send EHLO/HELO first"}
	}
	if conn.State() >= StateMail {
		return &Response{Code: CodeBadSequence, Message: "MAIL command already given"}
	}

	// Check TLS requirement
	if s.config.RequireTLS && !conn.IsTLS() {
		return &Response{
			Code:         CodeTransactionFailed,
			EnhancedCode: "5.7.0",
			Message:      "TLS required",
		}
	}

	// Check auth requirement
	if s.config.RequireAuth && !conn.IsAuthenticated() {
		return &Response{
			Code:         CodeTransactionFailed,
			EnhancedCode: "5.7.0",
			Message:      "Authentication required",
		}
	}

	// Parse MAIL FROM:<address> [params]
	args = strings.TrimSpace(args)
	if !strings.HasPrefix(strings.ToUpper(args), "FROM:") {
		return &Response{Code: CodeSyntaxError, Message: "Syntax: MAIL FROM:<address>"}
	}
	args = strings.TrimSpace(args[5:])

	from, params, err := parsePathWithParams(args)
	if err != nil {
		return &Response{Code: CodeSyntaxError, Message: err.Error()}
	}

	// RFC 6531: Reject non-ASCII addresses if SMTPUTF8 is not enabled or not requested
	if utils.ContainsNonASCII(from.Mailbox.LocalPart) || utils.ContainsNonASCII(from.Mailbox.Domain) {
		if !s.config.EnableSMTPUTF8 {
			return &Response{
				Code:         CodeMailboxNameInvalid,
				EnhancedCode: "5.6.7",
				Message:      "Address contains non-ASCII characters but SMTPUTF8 not supported",
			}
		}
		if _, hasSMTPUTF8 := params["SMTPUTF8"]; !hasSMTPUTF8 {
			return &Response{
				Code:         CodeMailboxNameInvalid,
				EnhancedCode: "5.6.7",
				Message:      "Address contains non-ASCII characters but SMTPUTF8 not requested",
			}
		}
	}

	// Check SIZE parameter
	if sizeStr, ok := params["SIZE"]; ok {
		size, err := strconv.ParseInt(sizeStr, 10, 64)
		if err != nil {
			return &Response{Code: CodeSyntaxError, Message: "Invalid SIZE parameter"}
		}
		if conn.Limits.MaxMessageSize > 0 && size > conn.Limits.MaxMessageSize {
			return &Response{
				Code:         CodeExceededStorage,
				EnhancedCode: "5.3.4",
				Message:      "Message too large",
			}
		}
	}

	// Callback
	if s.config.Callbacks != nil && s.config.Callbacks.OnMailFrom != nil {
		if err := s.config.Callbacks.OnMailFrom(conn.Context(), conn, from, params); err != nil {
			return &Response{Code: CodeMailboxNotFound, Message: err.Error()}
		}
	}

	// Start transaction
	mail := conn.BeginTransaction()
	mail.Envelope.From = from

	// Set default body type to 7BIT per RFC 5321
	mail.Envelope.BodyType = BodyType7Bit

	// Process parameters
	if bodyType, ok := params["BODY"]; ok {
		bodyTypeUpper := BodyType(strings.ToUpper(bodyType))
		// Validate BODY parameter per RFC 6152 and RFC 3030
		switch bodyTypeUpper {
		case BodyType7Bit, BodyType8BitMIME, BodyTypeBinaryMIME:
			mail.Envelope.BodyType = bodyTypeUpper
		default:
			return &Response{
				Code:         CodeParameterNotImpl,
				EnhancedCode: "5.5.4",
				Message:      "Invalid BODY parameter",
			}
		}
		// Check if 8BITMIME extension is enabled
		if bodyTypeUpper == BodyType8BitMIME && !s.config.Enable8BitMIME {
			return &Response{
				Code:         CodeParameterNotImpl,
				EnhancedCode: "5.5.4",
				Message:      "8BITMIME not supported",
			}
		}
		// Check if BINARYMIME extension is enabled (requires CHUNKING)
		if bodyTypeUpper == BodyTypeBinaryMIME && !s.config.EnableChunking {
			return &Response{
				Code:         CodeParameterNotImpl,
				EnhancedCode: "5.5.4",
				Message:      "BINARYMIME not supported",
			}
		}
	}
	if _, ok := params["SMTPUTF8"]; ok {
		if !s.config.EnableSMTPUTF8 {
			return &Response{
				Code:         CodeParameterNotImpl,
				EnhancedCode: "5.5.4",
				Message:      "SMTPUTF8 not supported",
			}
		}
		mail.Envelope.SMTPUTF8 = true
	}
	if envID, ok := params["ENVID"]; ok {
		if !s.config.EnableDSN {
			return &Response{
				Code:         CodeParameterNotImpl,
				EnhancedCode: "5.5.4",
				Message:      "DSN not supported",
			}
		}
		mail.Envelope.EnvID = envID
	}
	if ret, ok := params["RET"]; ok {
		if !s.config.EnableDSN {
			return &Response{
				Code:         CodeParameterNotImpl,
				EnhancedCode: "5.5.4",
				Message:      "DSN not supported",
			}
		}
		// RFC 3461 Section 4.3: RET parameter must be FULL or HDRS
		retUpper := strings.ToUpper(ret)
		if retUpper != "FULL" && retUpper != "HDRS" {
			return &Response{
				Code:         CodeSyntaxError,
				EnhancedCode: "5.5.4",
				Message:      "Invalid RET parameter: must be FULL or HDRS",
			}
		}
		mail.Envelope.DSNParams = &DSNEnvelopeParams{RET: retUpper}
	}
	if sizeStr, ok := params["SIZE"]; ok {
		mail.Envelope.Size, _ = strconv.ParseInt(sizeStr, 10, 64)
	}
	if conn.IsAuthenticated() {
		mail.Envelope.Auth = conn.Auth.Identity
	}
	mail.Envelope.ExtensionParams = params

	conn.SetState(StateMail)

	return &Response{
		Code:         CodeOK,
		EnhancedCode: "2.1.0",
		Message:      "OK",
	}
}

// handleRcpt processes the RCPT TO command.
func (s *Server) handleRcpt(conn *Connection, args string) *Response {
	if conn.State() < StateMail {
		return &Response{Code: CodeBadSequence, Message: "Send MAIL first"}
	}

	mail := conn.CurrentMail()
	if mail == nil {
		return &Response{Code: CodeBadSequence, Message: "No mail transaction"}
	}

	// Check recipient limit
	if conn.Limits.MaxRecipients > 0 && len(mail.Envelope.To) >= conn.Limits.MaxRecipients {
		return &Response{
			Code:         CodeInsufficientStorage,
			EnhancedCode: "5.5.3",
			Message:      "Too many recipients",
		}
	}

	// Parse RCPT TO:<address> [params]
	args = strings.TrimSpace(args)
	if !strings.HasPrefix(strings.ToUpper(args), "TO:") {
		return &Response{Code: CodeSyntaxError, Message: "Syntax: RCPT TO:<address>"}
	}
	args = strings.TrimSpace(args[3:])

	to, params, err := parsePathWithParams(args)
	if err != nil {
		return &Response{Code: CodeSyntaxError, Message: err.Error()}
	}

	// RFC 6531: Reject non-ASCII addresses if SMTPUTF8 is not enabled or not requested
	if utils.ContainsNonASCII(to.Mailbox.LocalPart) || utils.ContainsNonASCII(to.Mailbox.Domain) {
		if !s.config.EnableSMTPUTF8 {
			return &Response{
				Code:         CodeMailboxNameInvalid,
				EnhancedCode: "5.6.7",
				Message:      "Address contains non-ASCII characters but SMTPUTF8 not supported",
			}
		}
		if !mail.Envelope.SMTPUTF8 {
			return &Response{
				Code:         CodeMailboxNameInvalid,
				EnhancedCode: "5.6.7",
				Message:      "Address contains non-ASCII characters but SMTPUTF8 not requested",
			}
		}
	}

	// Callback
	if s.config.Callbacks != nil && s.config.Callbacks.OnRcptTo != nil {
		if err := s.config.Callbacks.OnRcptTo(conn.Context(), conn, to, params); err != nil {
			return &Response{Code: CodeMailboxNotFound, Message: err.Error()}
		}
	}

	// Add recipient
	rcpt := Recipient{Address: to}
	if notify, ok := params["NOTIFY"]; ok {
		if !s.config.EnableDSN {
			return &Response{
				Code:         CodeParameterNotImpl,
				EnhancedCode: "5.5.4",
				Message:      "DSN not supported",
			}
		}
		// RFC 3461 Section 4.1: Validate NOTIFY parameter values
		notifyValues := strings.Split(strings.ToUpper(notify), ",")
		hasNever := false
		for _, v := range notifyValues {
			v = strings.TrimSpace(v)
			switch v {
			case "NEVER":
				hasNever = true
			case "SUCCESS", "FAILURE", "DELAY":
				// Valid values
			default:
				return &Response{
					Code:         CodeSyntaxError,
					EnhancedCode: "5.5.4",
					Message:      "Invalid NOTIFY parameter value",
				}
			}
		}
		// RFC 3461: NEVER must appear by itself
		if hasNever && len(notifyValues) > 1 {
			return &Response{
				Code:         CodeSyntaxError,
				EnhancedCode: "5.5.4",
				Message:      "NOTIFY=NEVER must appear alone",
			}
		}
		rcpt.DSNParams = &DSNRecipientParams{
			Notify: notifyValues,
		}
	}
	if orcpt, ok := params["ORCPT"]; ok {
		if !s.config.EnableDSN {
			return &Response{
				Code:         CodeParameterNotImpl,
				EnhancedCode: "5.5.4",
				Message:      "DSN not supported",
			}
		}
		if rcpt.DSNParams == nil {
			rcpt.DSNParams = &DSNRecipientParams{}
		}
		rcpt.DSNParams.ORcpt = orcpt
	}

	mail.Envelope.To = append(mail.Envelope.To, rcpt)
	conn.SetState(StateRcpt)

	return &Response{
		Code:         CodeOK,
		EnhancedCode: "2.1.5",
		Message:      "OK",
	}
}

// handleData processes the DATA command.
func (s *Server) handleData(conn *Connection, reader *bufio.Reader, logger *slog.Logger) *Response {
	if conn.State() < StateRcpt {
		return &Response{Code: CodeBadSequence, Message: "Send RCPT first"}
	}

	mail := conn.CurrentMail()
	if mail == nil || len(mail.Envelope.To) == 0 {
		return &Response{Code: CodeBadSequence, Message: "No recipients"}
	}

	// Callback
	if s.config.Callbacks != nil && s.config.Callbacks.OnData != nil {
		if err := s.config.Callbacks.OnData(conn.Context(), conn); err != nil {
			return &Response{Code: CodeTransactionFailed, Message: err.Error()}
		}
	}

	conn.SetState(StateData)

	// Send intermediate response
	s.writeResponse(conn, Response{
		Code:    CodeStartMailInput,
		Message: "Start mail input; end with <CRLF>.<CRLF>",
	})

	// Set data timeout
	if err := conn.conn.SetReadDeadline(time.Now().Add(s.config.DataTimeout)); err != nil {
		return &Response{Code: CodeLocalError, Message: "Internal error"}
	}

	// Read message data
	data, err := s.readDataContent(reader, conn.Limits.MaxMessageSize)
	if err != nil {
		if errors.Is(err, ErrMessageTooLarge) {
			conn.ResetTransaction()
			return &Response{
				Code:         CodeExceededStorage,
				EnhancedCode: "5.3.4",
				Message:      "Message too large",
			}
		}
		if errors.Is(err, ErrBadLineEnding) {
			conn.ResetTransaction()
			return &Response{
				Code:         CodeSyntaxError,
				EnhancedCode: "5.6.0",
				Message:      "Message must use CRLF line endings",
			}
		}
		logger.Error("data read error", slog.Any("error", err))
		conn.ResetTransaction()
		return &Response{Code: CodeLocalError, Message: "Error reading message"}
	}

	// Validate message content based on BODY parameter
	switch mail.Envelope.BodyType {
	case BodyType7Bit:
		// RFC 5321: 7BIT requires strict ASCII (0-127) and line length <= 998 bytes
		if utils.ContainsNonASCII(string(data)) {
			conn.ResetTransaction()
			return &Response{
				Code:         CodeTransactionFailed,
				EnhancedCode: "5.6.0",
				Message:      "Message contains 8-bit data but BODY=7BIT was specified",
			}
		}
	case BodyTypeBinaryMIME:
		// RFC 3030: BINARYMIME requires BDAT command, not DATA
		conn.ResetTransaction()
		return &Response{
			Code:         CodeBadSequence,
			EnhancedCode: "5.5.0",
			Message:      "BINARYMIME requires BDAT command",
		}
	}

	// Parse message content into headers and body per RFC 5322
	headers, body := parseMessageContent(data)
	mail.Content.Headers = headers
	mail.Content.Body = body
	mail.Raw = data
	mail.ID = utils.GenerateID()
	// Update ReceivedAt to reflect when message content was actually received
	mail.ReceivedAt = time.Now()

	// Add Received header
	receivedHeader := conn.GenerateReceivedHeader("")
	mail.Trace = append([]TraceField{receivedHeader}, mail.Trace...)

	// OnMessage callback
	if s.config.Callbacks != nil && s.config.Callbacks.OnMessage != nil {
		if err := s.config.Callbacks.OnMessage(conn.Context(), conn, mail); err != nil {
			conn.ResetTransaction()
			return &Response{Code: CodeTransactionFailed, Message: err.Error()}
		}
	}

	// Complete transaction
	conn.CompleteTransaction()

	logger.Info("message received",
		slog.String("mail_id", mail.ID),
		slog.String("from", mail.Envelope.From.String()),
		slog.Int("recipients", len(mail.Envelope.To)),
		slog.Int("size", len(data)),
	)

	return &Response{
		Code:         CodeOK,
		EnhancedCode: "2.0.0",
		Message:      fmt.Sprintf("OK, queued as %s [%s]", mail.ID, conn.Trace.ID),
	}
}

// readDataContent reads the message content until <CRLF>.<CRLF>.
// Strictly requires CRLF line endings to prevent SMTP smuggling attacks.
func (s *Server) readDataContent(reader *bufio.Reader, maxSize int64) ([]byte, error) {
	var buf bytes.Buffer

	for {
		line, err := s.readLine(reader)
		if err != nil {
			return nil, err
		}

		// Check for end of data (line is ".", already stripped of CRLF)
		if line == "." {
			break
		}

		// Remove dot-stuffing (RFC 5321 Section 4.5.2)
		// Lines starting with "." have the leading dot removed
		if len(line) > 0 && line[0] == '.' {
			line = line[1:]
		}

		// Check size limit (account for CRLF that will be added back)
		lineWithCRLF := line + "\r\n"
		if maxSize > 0 && int64(buf.Len())+int64(len(lineWithCRLF)) > maxSize {
			return nil, ErrMessageTooLarge
		}

		buf.WriteString(lineWithCRLF)
	}

	return buf.Bytes(), nil
}

// handleBDAT processes the BDAT command (RFC 3030 CHUNKING extension).
// BDAT allows message data to be sent in chunks, with a size prefix for each chunk.
// Syntax: BDAT <size> [LAST]
func (s *Server) handleBDAT(conn *Connection, args string, reader *bufio.Reader, logger *slog.Logger) *Response {
	// Check if CHUNKING is enabled
	if !s.config.EnableChunking {
		return &Response{Code: CodeCommandNotImplemented, Message: "BDAT not available"}
	}

	// Must have recipients first (either from StateRcpt or ongoing BDAT)
	if conn.State() < StateRcpt && conn.State() != StateBDAT {
		return &Response{Code: CodeBadSequence, Message: "Send RCPT first"}
	}

	mail := conn.CurrentMail()
	if mail == nil || len(mail.Envelope.To) == 0 {
		return &Response{Code: CodeBadSequence, Message: "No recipients"}
	}

	// Parse BDAT arguments: <size> [LAST]
	args = strings.TrimSpace(args)
	if args == "" {
		return &Response{Code: CodeSyntaxError, Message: "Syntax: BDAT <size> [LAST]"}
	}

	parts := strings.Fields(args)
	if len(parts) < 1 || len(parts) > 2 {
		return &Response{Code: CodeSyntaxError, Message: "Syntax: BDAT <size> [LAST]"}
	}

	chunkSize, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || chunkSize < 0 {
		return &Response{Code: CodeSyntaxError, Message: "Invalid chunk size"}
	}

	isLast := false
	if len(parts) == 2 {
		if strings.ToUpper(parts[1]) != "LAST" {
			return &Response{Code: CodeSyntaxError, Message: "Syntax: BDAT <size> [LAST]"}
		}
		isLast = true
	}

	// Check if adding this chunk would exceed max message size
	currentSize := int64(len(mail.Raw))
	if conn.Limits.MaxMessageSize > 0 && currentSize+chunkSize > conn.Limits.MaxMessageSize {
		// Discard the chunk data to keep protocol in sync
		s.discardBDATChunk(reader, chunkSize)
		conn.ResetTransaction()
		return &Response{
			Code:         CodeExceededStorage,
			EnhancedCode: "5.3.4",
			Message:      "Message too large",
		}
	}

	// Callback before reading chunk
	if s.config.Callbacks != nil && s.config.Callbacks.OnBDAT != nil {
		if err := s.config.Callbacks.OnBDAT(conn.Context(), conn, chunkSize, isLast); err != nil {
			// Discard the chunk data to keep protocol in sync
			s.discardBDATChunk(reader, chunkSize)
			conn.ResetTransaction()
			return &Response{Code: CodeTransactionFailed, Message: err.Error()}
		}
	}

	conn.SetState(StateBDAT)

	// Set data timeout
	if err := conn.conn.SetReadDeadline(time.Now().Add(s.config.DataTimeout)); err != nil {
		return &Response{Code: CodeLocalError, Message: "Internal error"}
	}

	// Read the chunk data (binary, exact size)
	chunkData, err := s.readBDATChunk(reader, chunkSize)
	if err != nil {
		logger.Error("BDAT read error", slog.Any("error", err))
		conn.ResetTransaction()
		return &Response{Code: CodeLocalError, Message: "Error reading chunk data"}
	}

	// Append chunk to message
	mail.Raw = append(mail.Raw, chunkData...)

	// If this is the last chunk, complete the transaction
	if isLast {
		// Parse message content into headers and body per RFC 5322
		headers, body := parseMessageContent(mail.Raw)
		mail.Content.Headers = headers
		mail.Content.Body = body
		mail.ID = utils.GenerateID()
		// Update ReceivedAt to reflect when message content was actually received
		mail.ReceivedAt = time.Now()

		// Add Received header
		receivedHeader := conn.GenerateReceivedHeader("")
		mail.Trace = append([]TraceField{receivedHeader}, mail.Trace...)

		// OnMessage callback
		if s.config.Callbacks != nil && s.config.Callbacks.OnMessage != nil {
			if err := s.config.Callbacks.OnMessage(conn.Context(), conn, mail); err != nil {
				conn.ResetTransaction()
				return &Response{Code: CodeTransactionFailed, Message: err.Error()}
			}
		}

		// Complete transaction
		conn.CompleteTransaction()

		logger.Info("message received via BDAT",
			slog.String("mail_id", mail.ID),
			slog.String("from", mail.Envelope.From.String()),
			slog.Int("recipients", len(mail.Envelope.To)),
			slog.Int("size", len(mail.Raw)),
		)

		return &Response{
			Code:         CodeOK,
			EnhancedCode: "2.0.0",
			Message:      fmt.Sprintf("OK, queued as %s [%s]", mail.ID, conn.Trace.ID),
		}
	}

	// Not the last chunk, acknowledge and wait for more
	return &Response{
		Code:         CodeOK,
		EnhancedCode: "2.0.0",
		Message:      fmt.Sprintf("OK, %d bytes received", chunkSize),
	}
}

// readBDATChunk reads exactly 'size' bytes of binary data for a BDAT chunk.
func (s *Server) readBDATChunk(reader *bufio.Reader, size int64) ([]byte, error) {
	data := make([]byte, size)
	_, err := io.ReadFull(reader, data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// discardBDATChunk discards 'size' bytes from the reader (used on error).
func (s *Server) discardBDATChunk(reader *bufio.Reader, size int64) {
	_, _ = io.CopyN(io.Discard, reader, size)
}

// handleRset processes the RSET command.
func (s *Server) handleRset(conn *Connection) *Response {
	// Callback
	if s.config.Callbacks != nil && s.config.Callbacks.OnReset != nil {
		s.config.Callbacks.OnReset(conn.Context(), conn)
	}

	conn.ResetTransaction()

	return &Response{
		Code:         CodeOK,
		EnhancedCode: "2.0.0",
		Message:      "OK",
	}
}

// handleVrfy processes the VRFY command.
func (s *Server) handleVrfy(conn *Connection, args string) *Response {
	if args == "" {
		return &Response{Code: CodeSyntaxError, Message: "Syntax: VRFY <address>"}
	}

	// Callback
	if s.config.Callbacks != nil && s.config.Callbacks.OnVerify != nil {
		addr, err := s.config.Callbacks.OnVerify(conn.Context(), conn, args)
		if err != nil {
			return &Response{Code: CodeMailboxNotFound, Message: err.Error()}
		}
		return &Response{
			Code:    CodeOK,
			Message: addr.String(),
		}
	}

	// Default: disabled for privacy
	return &Response{
		Code:    CodeMailboxNotFound,
		Message: "VRFY disabled",
	}
}

// handleExpn processes the EXPN command.
func (s *Server) handleExpn(conn *Connection, args string) *Response {
	if args == "" {
		return &Response{Code: CodeSyntaxError, Message: "Syntax: EXPN <list>"}
	}

	// Callback
	if s.config.Callbacks != nil && s.config.Callbacks.OnExpand != nil {
		addrs, err := s.config.Callbacks.OnExpand(conn.Context(), conn, args)
		if err != nil {
			return &Response{Code: CodeMailboxNotFound, Message: err.Error()}
		}
		lines := make([]string, len(addrs))
		for i, addr := range addrs {
			lines[i] = addr.String()
		}
		s.writeMultilineResponse(conn, CodeOK, lines)
		return nil
	}

	// Default: disabled for privacy
	return &Response{
		Code:    CodeMailboxNotFound,
		Message: "EXPN disabled",
	}
}

// handleQuit processes the QUIT command.
func (s *Server) handleQuit(conn *Connection) *Response {
	conn.SetState(StateQuit)
	return &Response{
		Code:    CodeServiceClosing,
		Message: fmt.Sprintf("%s Service closing transmission channel [%s]", s.config.Hostname, conn.Trace.ID),
	}
}

// handleStartTLS processes the STARTTLS command.
func (s *Server) handleStartTLS(conn *Connection) *Response {
	if conn.State() < StateGreeted {
		return &Response{Code: CodeBadSequence, Message: "Send EHLO first"}
	}
	if s.config.TLSConfig == nil {
		return &Response{Code: CodeCommandNotImplemented, Message: "STARTTLS not available"}
	}
	if conn.IsTLS() {
		return &Response{Code: CodeBadSequence, Message: "TLS already active"}
	}

	// Callback
	if s.config.Callbacks != nil && s.config.Callbacks.OnStartTLS != nil {
		if err := s.config.Callbacks.OnStartTLS(conn.Context(), conn); err != nil {
			return &Response{Code: CodeTransactionFailed, Message: err.Error()}
		}
	}

	// Send ready response
	s.writeResponse(conn, Response{
		Code:    CodeServiceReady,
		Message: "Ready to start TLS",
	})

	// Upgrade connection
	if err := conn.UpgradeToTLS(s.config.TLSConfig); err != nil {
		conn.RecordError(err)
		// Connection is likely broken at this point
		return nil
	}

	return nil
}
