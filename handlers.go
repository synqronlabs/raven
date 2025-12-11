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

	ravenio "github.com/synqronlabs/raven/io"
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

	// ---- Intrinsic Extensions (always enabled) ----
	// These are fundamental modern SMTP capabilities per RFC compliance.
	// They do not require configuration and cannot be disabled.

	// 8BITMIME (RFC 6152) - Always enabled
	extensions[Ext8BitMIME] = ""
	conn.SetExtension(Ext8BitMIME, "")

	// SMTPUTF8 (RFC 6531) - Always enabled
	// Note: RFC 6531 requires 8BITMIME, which is already enabled above
	extensions[ExtSMTPUTF8] = ""
	conn.SetExtension(ExtSMTPUTF8, "")

	// ENHANCEDSTATUSCODES (RFC 2034) - Always enabled
	extensions[ExtEnhancedStatusCodes] = ""
	conn.SetExtension(ExtEnhancedStatusCodes, "")

	// PIPELINING (RFC 2920) - Always enabled
	extensions[ExtPipelining] = ""
	conn.SetExtension(ExtPipelining, "")

	// ---- Opt-in Extensions ----
	if s.config.TLSConfig != nil && !conn.IsTLS() {
		extensions[ExtSTARTTLS] = ""
		conn.SetExtension(ExtSTARTTLS, "")
	}
	if s.config.MaxMessageSize > 0 {
		sizeStr := strconv.FormatInt(s.config.MaxMessageSize, 10)
		extensions[ExtSize] = sizeStr
		conn.SetExtension(ExtSize, sizeStr)
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
	// AUTH (RFC 4954) - Opt-in: requires AuthMechanisms to be configured
	// Only advertise AUTH if TLS is not required, or if TLS is active
	if len(s.config.AuthMechanisms) > 0 && (!s.config.RequireTLS || conn.IsTLS()) {
		authParams := strings.Join(s.config.AuthMechanisms, " ")
		extensions[ExtAuth] = authParams
		conn.SetExtension(ExtAuth, authParams)
	}

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
	lines := make([]string, 1, len(extensions)+1)
	lines[0] = greeting
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
	// Get state info in a single lock acquisition
	stateInfo := conn.GetStateInfo()

	if stateInfo.State < StateGreeted {
		return &Response{Code: CodeBadSequence, Message: "Send EHLO/HELO first"}
	}
	if stateInfo.State >= StateMail {
		return &Response{Code: CodeBadSequence, Message: "MAIL command already given"}
	}

	// Check TLS requirement
	if s.config.RequireTLS && !stateInfo.IsTLS {
		return &Response{
			Code:         CodeTransactionFailed,
			EnhancedCode: "5.7.0",
			Message:      "TLS required",
		}
	}

	// Check auth requirement
	if s.config.RequireAuth && !stateInfo.IsAuthenticated {
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

	// RFC 6531: Non-ASCII addresses require SMTPUTF8 parameter to be specified
	// SMTPUTF8 is an intrinsic extension (always enabled), but clients must
	// explicitly request it for non-ASCII addresses per the RFC.
	if utils.ContainsNonASCII(from.Mailbox.LocalPart) || utils.ContainsNonASCII(from.Mailbox.Domain) {
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
		// Check if BINARYMIME extension is enabled (requires CHUNKING - opt-in)
		if bodyTypeUpper == BodyTypeBinaryMIME && !s.config.EnableChunking {
			return &Response{
				Code:         CodeParameterNotImpl,
				EnhancedCode: "5.5.4",
				Message:      "BINARYMIME not supported",
			}
		}
	}
	if _, ok := params["SMTPUTF8"]; ok {
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
		// RFC 3461 Section 5.4: ENVID parameter max 100 characters
		if len(envID) > 100 {
			return &Response{
				Code:         CodeSyntaxError,
				EnhancedCode: "5.5.4",
				Message:      "ENVID parameter too long (max 100 characters)",
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
		// RFC 3461 Section 5.4: RET parameter max 8 characters
		if len(ret) > 8 {
			return &Response{
				Code:         CodeSyntaxError,
				EnhancedCode: "5.5.4",
				Message:      "RET parameter too long",
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

	// RFC 6531: Non-ASCII addresses require SMTPUTF8 to have been requested in MAIL FROM
	// SMTPUTF8 is an intrinsic extension (always enabled), but clients must
	// explicitly request it for non-ASCII addresses per the RFC.
	if utils.ContainsNonASCII(to.Mailbox.LocalPart) || utils.ContainsNonASCII(to.Mailbox.Domain) {
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
		// RFC 3461 Section 5.4: NOTIFY parameter max 28 characters
		if len(notify) > 28 {
			return &Response{
				Code:         CodeSyntaxError,
				EnhancedCode: "5.5.4",
				Message:      "NOTIFY parameter too long (max 28 characters)",
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
		// RFC 3461 Section 5.4: ORCPT parameter max 500 characters
		if len(orcpt) > 500 {
			return &Response{
				Code:         CodeSyntaxError,
				EnhancedCode: "5.5.4",
				Message:      "ORCPT parameter too long (max 500 characters)",
			}
		}
		// RFC 3461 Section 4.2: ORCPT format is addr-type ";" xtext
		if !strings.Contains(orcpt, ";") {
			return &Response{
				Code:         CodeSyntaxError,
				EnhancedCode: "5.5.4",
				Message:      "Invalid ORCPT parameter: must be addr-type;address",
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

	// Check for BINARYMIME early - it requires BDAT command, not DATA
	if mail.Envelope.BodyType == BodyTypeBinaryMIME {
		conn.ResetTransaction()
		return &Response{
			Code:         CodeBadSequence,
			EnhancedCode: "5.5.0",
			Message:      "BINARYMIME requires BDAT command",
		}
	}

	// Read message data, validating 7BIT if required
	enforce7Bit := mail.Envelope.BodyType == BodyType7Bit
	data, err := s.readDataContent(reader, conn.Limits.MaxMessageSize, enforce7Bit)
	if err != nil {
		if errors.Is(err, ErrMessageTooLarge) {
			conn.ResetTransaction()
			return &Response{
				Code:         CodeExceededStorage,
				EnhancedCode: "5.3.4",
				Message:      "Message too large",
			}
		}
		if errors.Is(err, ravenio.ErrBadLineEnding) {
			conn.ResetTransaction()
			return &Response{
				Code:         CodeSyntaxError,
				EnhancedCode: "5.6.0",
				Message:      "Message must use CRLF line endings",
			}
		}
		if errors.Is(err, ravenio.Err8BitIn7BitMode) {
			conn.ResetTransaction()
			return &Response{
				Code:         CodeTransactionFailed,
				EnhancedCode: "5.6.0",
				Message:      "Message contains 8-bit data but BODY=8BITMIME was not specified",
			}
		}
		logger.Error("data read error", slog.Any("error", err))
		conn.ResetTransaction()
		return &Response{Code: CodeLocalError, Message: "Error reading message"}
	}

	// Parse message content into headers and body per RFC 5322 using FromRaw
	mail.Content.FromRaw(data)

	// RFC 5321 Section 6.3: Loop detection via Received header count
	// Simple counting of Received headers is an effective method of detecting loops.
	// RFC recommends a large rejection threshold, normally at least 100.
	if s.config.MaxReceivedHeaders > 0 {
		receivedCount := mail.Content.Headers.Count("Received")
		if receivedCount >= s.config.MaxReceivedHeaders {
			logger.Warn("mail loop detected",
				slog.Int("received_count", receivedCount),
				slog.Int("max_allowed", s.config.MaxReceivedHeaders),
				slog.String("from", mail.Envelope.From.String()),
			)
			conn.ResetTransaction()
			return &Response{
				Code:         CodeTransactionFailed,
				EnhancedCode: "5.4.6",
				Message:      "Mail loop detected",
			}
		}
	}

	mail.ID = utils.GenerateID()
	// Update ReceivedAt to reflect when message content was actually received
	mail.ReceivedAt = time.Now()

	// Add Received header per RFC 5321 Section 4.4
	// SMTP servers MUST prepend Received lines to messages
	receivedHeader := conn.GenerateReceivedHeader("")
	receivedHeader.ID = mail.ID
	mail.Trace = append([]TraceField{receivedHeader}, mail.Trace...)

	// Prepend Received header to message content per RFC 5321 Section 3.7.2
	// "SMTP servers MUST prepend Received lines to messages"
	mail.Content.Headers = append(Headers{{
		Name:  "Received",
		Value: receivedHeader.String(),
	}}, mail.Content.Headers...)

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
// If enforce7Bit is true, returns Err8BitIn7BitMode if any non-ASCII bytes are found.
func (s *Server) readDataContent(reader *bufio.Reader, maxSize int64, enforce7Bit bool) ([]byte, error) {
	// Pre-allocate buffer with reasonable initial capacity
	buf := bytes.NewBuffer(make([]byte, 0, 4096))
	var sizeExceeded bool
	var has8BitData bool

	for {
		line, err := ravenio.ReadLine(reader, s.config.MaxLineLength, enforce7Bit)
		if err != nil {
			if errors.Is(err, ravenio.Err8BitIn7BitMode) {
				// Mark that we found 8-bit data, but continue draining
				has8BitData = true
				// Continue reading with 7-bit enforcement disabled to drain the rest
				enforce7Bit = false
				continue
			}
			return nil, err
		}

		// Check for end of data (line is ".", already stripped of CRLF)
		if line == "." {
			break
		}

		// If we've already exceeded the size or found 8-bit data, just drain remaining content
		if sizeExceeded || has8BitData {
			continue
		}

		// Remove dot-stuffing (RFC 5321 Section 4.5.2)
		// Lines starting with "." have the leading dot removed
		if len(line) > 0 && line[0] == '.' {
			line = line[1:]
		}

		// Check size limit (account for CRLF that will be added back)
		newLen := int64(buf.Len()) + int64(len(line)) + 2
		if maxSize > 0 && newLen > maxSize {
			// Mark that we exceeded the size, but continue to drain the data
			sizeExceeded = true
			continue
		}

		// Write line and CRLF directly to avoid string concatenation
		buf.WriteString(line)
		buf.WriteString("\r\n")
	}

	if has8BitData {
		return nil, ravenio.Err8BitIn7BitMode
	}

	if sizeExceeded {
		return nil, ErrMessageTooLarge
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
	// Get state once to avoid multiple lock acquisitions
	state := conn.State()
	if state < StateRcpt && state != StateBDAT {
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
	currentSize := int64(len(mail.Content.Raw))
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

	// Pre-allocate capacity to avoid multiple reallocations when appending chunks
	if cap(mail.Content.Raw)-len(mail.Content.Raw) < len(chunkData) {
		newRaw := make([]byte, len(mail.Content.Raw), currentSize+chunkSize)
		copy(newRaw, mail.Content.Raw)
		mail.Content.Raw = newRaw
	}
	mail.Content.Raw = append(mail.Content.Raw, chunkData...)

	// If this is the last chunk, complete the transaction
	if isLast {
		// Parse message content into headers and body per RFC 5322 using FromRaw
		mail.Content.FromRaw(mail.Content.Raw)

		// RFC 5321 Section 6.3: Loop detection via Received header count
		// Simple counting of Received headers is an effective method of detecting loops.
		// RFC recommends a large rejection threshold, normally at least 100.
		if s.config.MaxReceivedHeaders > 0 {
			receivedCount := mail.Content.Headers.Count("Received")
			if receivedCount >= s.config.MaxReceivedHeaders {
				logger.Warn("mail loop detected",
					slog.Int("received_count", receivedCount),
					slog.Int("max_allowed", s.config.MaxReceivedHeaders),
					slog.String("from", mail.Envelope.From.String()),
				)
				conn.ResetTransaction()
				return &Response{
					Code:         CodeTransactionFailed,
					EnhancedCode: "5.4.6",
					Message:      "Mail loop detected",
				}
			}
		}

		mail.ID = utils.GenerateID()
		// Update ReceivedAt to reflect when message content was actually received
		mail.ReceivedAt = time.Now()

		// Add Received header to trace per RFC 5321 Section 4.4
		receivedHeader := conn.GenerateReceivedHeader("")
		receivedHeader.ID = mail.ID
		mail.Trace = append([]TraceField{receivedHeader}, mail.Trace...)

		// Prepend Received header to message content per RFC 5321 Section 3.7.2
		mail.Content.Headers = append(Headers{{
			Name:  "Received",
			Value: receivedHeader.String(),
		}}, mail.Content.Headers...)

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
			slog.Int("size", len(mail.Content.Raw)),
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

// DefaultHelpURL is the default help URL returned by the HELP command.
const DefaultHelpURL = "https://github.com/synqronlabs/raven"

// handleHelp processes the HELP command per RFC 5321 Section 4.1.1.8.
// The HELP command provides information about supported commands or the server.
func (s *Server) handleHelp(conn *Connection, topic string) *Response {
	topic = strings.TrimSpace(topic)

	// Callback for custom help responses
	if s.config.Callbacks != nil && s.config.Callbacks.OnHelp != nil {
		lines := s.config.Callbacks.OnHelp(conn.Context(), conn, topic)
		if lines != nil && len(lines) > 0 {
			s.writeMultilineResponse(conn, CodeHelpMessage, lines)
			return nil
		}
	}

	// Default help response
	if topic == "" {
		// General help
		lines := []string{
			"Raven ESMTP Server",
			"Supported commands: HELO EHLO MAIL RCPT DATA RSET NOOP QUIT HELP VRFY EXPN",
			"For more information, visit: " + DefaultHelpURL,
		}
		s.writeMultilineResponse(conn, CodeHelpMessage, lines)
		return nil
	}

	// Topic-specific help
	topicUpper := strings.ToUpper(topic)
	var helpText string
	switch topicUpper {
	case "HELO":
		helpText = "HELO <hostname> - Identify yourself to the server"
	case "EHLO":
		helpText = "EHLO <hostname> - Extended HELLO, identify and request extensions"
	case "MAIL":
		helpText = "MAIL FROM:<address> [params] - Start a mail transaction"
	case "RCPT":
		helpText = "RCPT TO:<address> [params] - Specify a recipient"
	case "DATA":
		helpText = "DATA - Start message input, end with <CRLF>.<CRLF>"
	case "BDAT":
		helpText = "BDAT <size> [LAST] - Send message data in chunks (CHUNKING extension)"
	case "RSET":
		helpText = "RSET - Reset the current transaction"
	case "NOOP":
		helpText = "NOOP - No operation (keepalive)"
	case "QUIT":
		helpText = "QUIT - Close the connection"
	case "VRFY":
		helpText = "VRFY <address> - Verify an address (may be disabled)"
	case "EXPN":
		helpText = "EXPN <list> - Expand a mailing list (may be disabled)"
	case "HELP":
		helpText = "HELP [topic] - Show help information"
	case "STARTTLS":
		helpText = "STARTTLS - Upgrade connection to TLS"
	case "AUTH":
		helpText = "AUTH <mechanism> [initial-response] - Authenticate"
	default:
		return &Response{
			Code:    CodeHelpMessage,
			Message: fmt.Sprintf("No help available for '%s'. Visit: %s", topic, DefaultHelpURL),
		}
	}

	return &Response{Code: CodeHelpMessage, Message: helpText}
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
		// Connection is broken at this point - client will disconnect
		return nil
	}

	return nil
}
