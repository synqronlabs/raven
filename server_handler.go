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

	// Create context with request data
	ctx := s.newContext(conn, nil)
	ctx.Request = Request{
		Command:  CmdHelo,
		Args:     hostname,
		Hostname: hostname,
	}

	return s.runHandlers(ctx, s.onHelo, s.defaultHeloHandler)
}

// defaultHeloHandler is the default HELO handler.
func (s *Server) defaultHeloHandler(c *Context) *Response {
	conn := c.Connection
	hostname := c.Request.Hostname

	conn.setClientHostname(hostname)
	conn.setState(StateGreeted)
	conn.resetTransaction()

	ip, err := utils.GetIPFromAddr(conn.RemoteAddr())
	if err != nil {
		ip = net.IPv4zero
	}

	return &Response{
		Code:    CodeOK,
		Message: fmt.Sprintf("%s Hello %s [%s]", s.hostname, ip.String(), conn.Trace.ID),
	}
}

// handleEhlo processes the EHLO command.
func (s *Server) handleEhlo(conn *Connection, hostname string) *Response {
	if hostname == "" {
		return &Response{Code: CodeSyntaxError, Message: "Hostname required"}
	}

	// Build extensions map
	extensions := s.buildExtensions(conn)

	// Create context with request data
	ctx := s.newContext(conn, nil)
	ctx.Request = Request{
		Command:    CmdEhlo,
		Args:       hostname,
		Hostname:   hostname,
		Extensions: extensions,
	}

	return s.runHandlers(ctx, s.onEhlo, s.defaultEhloHandler)
}

// defaultEhloHandler is the default EHLO handler.
func (s *Server) defaultEhloHandler(c *Context) *Response {
	conn := c.Connection
	hostname := c.Request.Hostname
	extensions := c.Request.Extensions

	// Add auth extensions if configured
	if s.enableChunking {
		extensions[ExtChunking] = ""
		conn.SetExtension(ExtChunking, "")
		extensions[ExtBinaryMIME] = ""
		conn.SetExtension(ExtBinaryMIME, "")
	}

	effectiveMechanisms := s.getEffectiveAuthMechanisms()
	if len(effectiveMechanisms) > 0 && (!s.requireTLS || conn.IsTLS()) {
		authParams := strings.Join(effectiveMechanisms, " ")
		extensions[ExtAuth] = authParams
		conn.SetExtension(ExtAuth, authParams)
	}

	if conn.IsTLS() && s.tlsConfig != nil {
		extensions[ExtRequireTLS] = ""
		conn.SetExtension(ExtRequireTLS, "")
	}

	conn.setClientHostname(hostname)
	conn.setState(StateGreeted)
	conn.resetTransaction()

	ip, err := utils.GetIPFromAddr(conn.RemoteAddr())
	if err != nil {
		ip = net.IPv4zero
	}

	// Build multiline response
	greeting := fmt.Sprintf("%s Hello %s [%s]", s.hostname, ip.String(), conn.Trace.ID)
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
	return nil // Response already sent
}

// buildExtensions builds the base extensions map for EHLO.
func (s *Server) buildExtensions(conn *Connection) map[Extension]string {
	extensions := make(map[Extension]string)

	// Intrinsic extensions (always enabled)
	extensions[Ext8BitMIME] = ""
	conn.SetExtension(Ext8BitMIME, "")
	extensions[ExtSMTPUTF8] = ""
	conn.SetExtension(ExtSMTPUTF8, "")
	extensions[ExtEnhancedStatusCodes] = ""
	conn.SetExtension(ExtEnhancedStatusCodes, "")
	extensions[ExtPipelining] = ""
	conn.SetExtension(ExtPipelining, "")

	// Opt-in extensions
	if s.tlsConfig != nil && !conn.IsTLS() {
		extensions[ExtSTARTTLS] = ""
		conn.SetExtension(ExtSTARTTLS, "")
	}
	if conn.Limits.MaxMessageSize > 0 {
		sizeStr := strconv.FormatInt(conn.Limits.MaxMessageSize, 10)
		extensions[ExtSize] = sizeStr
		conn.SetExtension(ExtSize, sizeStr)
	}
	if s.enableDSN {
		extensions[ExtDSN] = ""
		conn.SetExtension(ExtDSN, "")
	}

	return extensions
}

// handleMail processes the MAIL FROM command.
func (s *Server) handleMail(conn *Connection, args string) *Response {
	stateInfo := conn.getStateInfo()

	if stateInfo.State < StateGreeted {
		return &Response{Code: CodeBadSequence, Message: "Send EHLO/HELO first"}
	}
	if stateInfo.State >= StateMail {
		return &Response{Code: CodeBadSequence, Message: "MAIL command already given"}
	}

	if s.requireTLS && !stateInfo.IsTLS {
		return &Response{Code: CodeTransactionFailed, EnhancedCode: string(ESCSecurityError), Message: "TLS required"}
	}

	if s.requireAuth && !stateInfo.IsAuthenticated {
		return &Response{Code: CodeTransactionFailed, EnhancedCode: string(ESCSecurityError), Message: "Authentication required"}
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

	// Non-ASCII addresses require SMTPUTF8 parameter
	if utils.ContainsNonASCII(from.Mailbox.LocalPart) || utils.ContainsNonASCII(from.Mailbox.Domain) {
		if _, hasSMTPUTF8 := params["SMTPUTF8"]; !hasSMTPUTF8 {
			return &Response{
				Code:         CodeMailboxNameInvalid,
				EnhancedCode: string(ESCNonASCIINoSMTPUTF8),
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
			return &Response{Code: CodeExceededStorage, EnhancedCode: string(ESCMailSystemFull), Message: "Message too large"}
		}
	}

	// Create context with request data
	ctx := s.newContext(conn, nil)
	ctx.Request = Request{
		Command: CmdMail,
		Args:    args,
		From:    &from,
		Params:  params,
	}

	return s.runHandlers(ctx, s.onMailFrom, s.defaultMailFromHandler)
}

// defaultMailFromHandler is the default MAIL FROM handler.
func (s *Server) defaultMailFromHandler(c *Context) *Response {
	conn := c.Connection
	from := c.Request.From
	params := c.Request.Params

	// Start transaction
	mail := conn.beginTransaction()
	mail.Envelope.From = *from
	mail.Envelope.BodyType = BodyType7Bit

	// Process parameters
	if bodyType, ok := params["BODY"]; ok {
		bodyTypeUpper := BodyType(strings.ToUpper(bodyType))
		switch bodyTypeUpper {
		case BodyType7Bit, BodyType8BitMIME, BodyTypeBinaryMIME:
			mail.Envelope.BodyType = bodyTypeUpper
		default:
			return &Response{Code: CodeParameterNotImpl, EnhancedCode: string(ESCInvalidArgs), Message: "Invalid BODY parameter"}
		}
		if bodyTypeUpper == BodyTypeBinaryMIME && !s.enableChunking {
			return &Response{Code: CodeParameterNotImpl, EnhancedCode: string(ESCInvalidArgs), Message: "BINARYMIME not supported"}
		}
	}

	if _, ok := params["SMTPUTF8"]; ok {
		mail.Envelope.SMTPUTF8 = true
	}

	if _, ok := params["REQUIRETLS"]; ok {
		if !conn.IsTLS() {
			return &Response{Code: CodeTransactionFailed, EnhancedCode: string(ESCSecurityError), Message: "REQUIRETLS requires TLS connection"}
		}
		if !conn.HasExtension(ExtRequireTLS) {
			return &Response{Code: CodeTransactionFailed, EnhancedCode: string(ESCRequireTLSRequired), Message: "REQUIRETLS support required"}
		}
		mail.Envelope.RequireTLS = true
	}

	if envID, ok := params["ENVID"]; ok {
		if !s.enableDSN {
			return &Response{Code: CodeParameterNotImpl, EnhancedCode: string(ESCInvalidArgs), Message: "DSN not supported"}
		}
		if len(envID) > 100 {
			return &Response{Code: CodeSyntaxError, EnhancedCode: string(ESCInvalidArgs), Message: "ENVID parameter too long (max 100 characters)"}
		}
		mail.Envelope.EnvID = envID
	}

	if ret, ok := params["RET"]; ok {
		if !s.enableDSN {
			return &Response{Code: CodeParameterNotImpl, EnhancedCode: string(ESCInvalidArgs), Message: "DSN not supported"}
		}
		if len(ret) > 8 {
			return &Response{Code: CodeSyntaxError, EnhancedCode: string(ESCInvalidArgs), Message: "RET parameter too long"}
		}
		retUpper := strings.ToUpper(ret)
		if retUpper != "FULL" && retUpper != "HDRS" {
			return &Response{Code: CodeSyntaxError, EnhancedCode: string(ESCInvalidArgs), Message: "Invalid RET parameter: must be FULL or HDRS"}
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
	conn.setState(StateMail)

	return &Response{Code: CodeOK, EnhancedCode: string(ESCAddressValid), Message: "OK"}
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

	if conn.Limits.MaxRecipients > 0 && len(mail.Envelope.To) >= conn.Limits.MaxRecipients {
		return &Response{Code: CodeInsufficientStorage, EnhancedCode: string(ESCTempTooManyRecipients), Message: "Too many recipients"}
	}

	args = strings.TrimSpace(args)
	if !strings.HasPrefix(strings.ToUpper(args), "TO:") {
		return &Response{Code: CodeSyntaxError, Message: "Syntax: RCPT TO:<address>"}
	}
	args = strings.TrimSpace(args[3:])

	to, params, err := parsePathWithParams(args)
	if err != nil {
		return &Response{Code: CodeSyntaxError, Message: err.Error()}
	}

	if utils.ContainsNonASCII(to.Mailbox.LocalPart) || utils.ContainsNonASCII(to.Mailbox.Domain) {
		if !mail.Envelope.SMTPUTF8 {
			return &Response{
				Code:         CodeMailboxNameInvalid,
				EnhancedCode: string(ESCNonASCIINoSMTPUTF8),
				Message:      "Address contains non-ASCII characters but SMTPUTF8 not requested",
			}
		}
	}

	// Create context with request data
	ctx := s.newContext(conn, nil)
	ctx.Request = Request{
		Command: CmdRcpt,
		Args:    args,
		To:      &to,
		Params:  params,
	}

	return s.runHandlers(ctx, s.onRcptTo, s.defaultRcptToHandler)
}

// defaultRcptToHandler is the default RCPT TO handler.
func (s *Server) defaultRcptToHandler(c *Context) *Response {
	conn := c.Connection
	to := c.Request.To
	params := c.Request.Params

	mail := conn.CurrentMail()
	rcpt := Recipient{Address: *to}

	if notify, ok := params["NOTIFY"]; ok {
		if !s.enableDSN {
			return &Response{Code: CodeParameterNotImpl, EnhancedCode: string(ESCInvalidArgs), Message: "DSN not supported"}
		}
		if len(notify) > 28 {
			return &Response{Code: CodeSyntaxError, EnhancedCode: string(ESCInvalidArgs), Message: "NOTIFY parameter too long (max 28 characters)"}
		}
		notifyValues := strings.Split(strings.ToUpper(notify), ",")
		hasNever := false
		for _, v := range notifyValues {
			v = strings.TrimSpace(v)
			switch v {
			case "NEVER":
				hasNever = true
			case "SUCCESS", "FAILURE", "DELAY":
			default:
				return &Response{Code: CodeSyntaxError, EnhancedCode: string(ESCInvalidArgs), Message: "Invalid NOTIFY parameter value"}
			}
		}
		if hasNever && len(notifyValues) > 1 {
			return &Response{Code: CodeSyntaxError, EnhancedCode: string(ESCInvalidArgs), Message: "NOTIFY=NEVER must appear alone"}
		}
		rcpt.DSNParams = &DSNRecipientParams{Notify: notifyValues}
	}

	if orcpt, ok := params["ORCPT"]; ok {
		if !s.enableDSN {
			return &Response{Code: CodeParameterNotImpl, EnhancedCode: string(ESCInvalidArgs), Message: "DSN not supported"}
		}
		if len(orcpt) > 500 {
			return &Response{Code: CodeSyntaxError, EnhancedCode: string(ESCInvalidArgs), Message: "ORCPT parameter too long (max 500 characters)"}
		}
		if !strings.Contains(orcpt, ";") {
			return &Response{Code: CodeSyntaxError, EnhancedCode: string(ESCInvalidArgs), Message: "Invalid ORCPT parameter: must be addr-type;address"}
		}
		if rcpt.DSNParams == nil {
			rcpt.DSNParams = &DSNRecipientParams{}
		}
		rcpt.DSNParams.ORcpt = orcpt
	}

	mail.Envelope.To = append(mail.Envelope.To, rcpt)
	conn.setState(StateRcpt)

	return &Response{Code: CodeOK, EnhancedCode: string(ESCRecipientValid), Message: "OK"}
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

	// Create context for handlers
	ctx := s.newContext(conn, mail)
	ctx.Request = Request{Command: CmdData}

	// Run pre-data handlers
	if len(s.onData) > 0 {
		resp := s.runHandlers(ctx, s.onData, nil)
		if resp != nil && resp.IsError() {
			return resp
		}
	}

	conn.setState(StateData)

	// Send intermediate response
	s.writeResponse(conn, Response{Code: CodeStartMailInput, Message: "Start mail input; end with <CRLF>.<CRLF>"})

	if err := conn.conn.SetReadDeadline(time.Now().Add(conn.Limits.DataTimeout)); err != nil {
		return &Response{Code: CodeLocalError, EnhancedCode: string(ESCTempLocalError), Message: "Internal error"}
	}

	if mail.Envelope.BodyType == BodyTypeBinaryMIME {
		conn.resetTransaction()
		return &Response{Code: CodeBadSequence, EnhancedCode: string(ESCInvalidCommand), Message: "BINARYMIME requires BDAT command"}
	}

	enforce7Bit := mail.Envelope.BodyType == BodyType7Bit
	data, err := s.readDataContent(reader, conn.Limits.MaxMessageSize, enforce7Bit)
	if err != nil {
		conn.resetTransaction()
		if errors.Is(err, ErrMessageTooLarge) {
			return &Response{Code: CodeExceededStorage, EnhancedCode: string(ESCMailSystemFull), Message: "Message too large"}
		}
		if errors.Is(err, ravenio.ErrBadLineEnding) {
			return &Response{Code: CodeSyntaxError, EnhancedCode: string(ESCContentError), Message: "Message must use CRLF line endings"}
		}
		if errors.Is(err, ravenio.Err8BitIn7BitMode) {
			return &Response{Code: CodeTransactionFailed, EnhancedCode: string(ESCContentError), Message: "Message contains 8-bit data but BODY=8BITMIME was not specified"}
		}
		if errors.Is(err, ravenio.ErrLineTooLong) {
			return &Response{Code: CodeSyntaxError, EnhancedCode: string(ESCContentError), Message: "Line length exceeds maximum allowed"}
		}
		logger.Error("data read error", slog.Any("error", err))
		return &Response{Code: CodeLocalError, EnhancedCode: string(ESCTempLocalError), Message: "Error reading message"}
	}

	mail.Content.FromRaw(data)

	// Check TLS-Required header
	if !mail.Envelope.RequireTLS {
		tlsRequiredHeader := mail.Content.Headers.Get("TLS-Required")
		if strings.EqualFold(strings.TrimSpace(tlsRequiredHeader), "No") {
			if mail.Envelope.ExtensionParams == nil {
				mail.Envelope.ExtensionParams = make(map[string]string)
			}
			mail.Envelope.ExtensionParams["TLS-OPTIONAL"] = "yes"
		}
	}

	// Loop detection
	if err := detectLoop(mail, logger, s.maxReceivedHeaders); err != nil {
		conn.resetTransaction()
		return &Response{Code: CodeTransactionFailed, EnhancedCode: string(ESCRoutingLoop), Message: err.Error()}
	}

	mail.ID = utils.GenerateID()
	mail.ReceivedAt = time.Now()

	receivedHeader := conn.GenerateReceivedHeader("")
	receivedHeader.ID = mail.ID
	mail.Trace = append([]TraceField{receivedHeader}, mail.Trace...)
	mail.Content.Headers = append(Headers{{Name: "Received", Value: receivedHeader.String()}}, mail.Content.Headers...)

	// Update context with mail for OnMessage handlers
	ctx.Mail = mail

	// Run OnMessage handlers with default
	resp := s.runHandlers(ctx, s.onMessage, s.defaultMessageHandler(logger, len(data)))
	if resp != nil && resp.IsError() {
		conn.resetTransaction()
		return resp
	}

	conn.completeTransaction()
	return resp
}

// defaultMessageHandler returns a handler that completes the message transaction.
func (s *Server) defaultMessageHandler(logger *slog.Logger, size int) HandlerFunc {
	return func(c *Context) *Response {
		mail := c.Mail
		conn := c.Connection

		logger.Info("message received",
			slog.String("mail_id", mail.ID),
			slog.String("from", mail.Envelope.From.String()),
			slog.Int("recipients", len(mail.Envelope.To)),
			slog.Int("size", size),
		)

		return &Response{
			Code:         CodeOK,
			EnhancedCode: string(ESCSuccess),
			Message:      fmt.Sprintf("OK, queued as %s [%s]", mail.ID, conn.Trace.ID),
		}
	}
}

// detectLoop checks for mail loops by counting the "Received" headers.
func detectLoop(mail *Mail, logger *slog.Logger, maxAllowed int) error {
	if maxAllowed > 0 {
		receivedCount := mail.Content.Headers.Count("Received")
		if receivedCount >= maxAllowed {
			logger.Warn("mail loop detected",
				slog.Int("received_count", receivedCount),
				slog.Int("max_allowed", maxAllowed),
				slog.String("from", mail.Envelope.From.String()),
			)
			return errors.New("mail loop detected")
		}
	}
	return nil
}

// readDataContent reads the message content until <CRLF>.<CRLF>.
func (s *Server) readDataContent(reader *bufio.Reader, maxSize int64, enforce7Bit bool) ([]byte, error) {
	const maxInitialAlloc = 10 * 1024 * 1024
	var initCap int
	switch {
	case maxSize > 0 && maxSize <= maxInitialAlloc:
		initCap = int(maxSize)
	case maxSize > maxInitialAlloc:
		initCap = maxInitialAlloc
	default:
		initCap = 4096
	}
	buf := bytes.NewBuffer(make([]byte, 0, initCap))
	var sizeExceeded bool
	var has8BitData bool

	maxContentLineLength := MaxLineLength + 2

	for {
		line, err := ravenio.ReadLine(reader, maxContentLineLength, enforce7Bit)
		if err != nil {
			if errors.Is(err, ravenio.Err8BitIn7BitMode) {
				has8BitData = true
				enforce7Bit = false
				continue
			}
			return nil, err
		}

		if line == "." {
			break
		}

		if sizeExceeded || has8BitData {
			continue
		}

		if len(line) > 0 && line[0] == '.' {
			line = line[1:]
		}

		newLen := int64(buf.Len()) + int64(len(line)) + 2
		if maxSize > 0 && newLen > maxSize {
			sizeExceeded = true
			continue
		}

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

// handleBDAT processes the BDAT command (RFC 3030).
func (s *Server) handleBDAT(conn *Connection, args string, reader *bufio.Reader, logger *slog.Logger) *Response {
	if !s.enableChunking {
		return &Response{Code: CodeCommandNotImplemented, Message: "BDAT not implemented"}
	}

	state := conn.State()
	if state < StateRcpt && state != StateBDAT {
		return &Response{Code: CodeBadSequence, Message: "Send RCPT first"}
	}

	mail := conn.CurrentMail()
	if mail == nil || len(mail.Envelope.To) == 0 {
		return &Response{Code: CodeBadSequence, Message: "No recipients"}
	}

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

	currentSize := conn.getBDATBufferSize()
	if conn.Limits.MaxMessageSize > 0 && currentSize+chunkSize > conn.Limits.MaxMessageSize {
		s.discardBDATChunk(reader, chunkSize)
		conn.resetTransaction()
		return &Response{Code: CodeExceededStorage, EnhancedCode: string(ESCMailSystemFull), Message: "Message too large"}
	}

	// Run OnBdat handlers
	if len(s.onBdat) > 0 {
		ctx := s.newContext(conn, mail)
		ctx.Request = Request{Command: CmdBdat, Args: args}
		ctx.Set("size", chunkSize)
		ctx.Set("last", isLast)

		resp := s.runHandlers(ctx, s.onBdat, nil)
		if resp != nil && resp.IsError() {
			s.discardBDATChunk(reader, chunkSize)
			conn.resetTransaction()
			return resp
		}
	}

	conn.setState(StateBDAT)

	if err := conn.conn.SetReadDeadline(time.Now().Add(conn.Limits.DataTimeout)); err != nil {
		return &Response{Code: CodeLocalError, EnhancedCode: string(ESCTempLocalError), Message: "Internal error"}
	}

	chunkData, err := s.readBDATChunk(reader, chunkSize)
	if err != nil {
		logger.Error("BDAT read error", slog.Any("error", err))
		conn.resetTransaction()
		return &Response{Code: CodeLocalError, EnhancedCode: string(ESCTempLocalError), Message: "Error reading chunk data"}
	}

	conn.appendBDATChunk(chunkData)

	if isLast {
		rawData := conn.consumeBDATBuffer()
		mail.Content.FromRaw(rawData)

		if err := detectLoop(mail, logger, s.maxReceivedHeaders); err != nil {
			conn.resetTransaction()
			return &Response{Code: CodeTransactionFailed, EnhancedCode: string(ESCRoutingLoop), Message: err.Error()}
		}

		mail.ID = utils.GenerateID()
		mail.ReceivedAt = time.Now()

		receivedHeader := conn.GenerateReceivedHeader("")
		receivedHeader.ID = mail.ID
		mail.Trace = append([]TraceField{receivedHeader}, mail.Trace...)
		mail.Content.Headers = append(Headers{{Name: "Received", Value: receivedHeader.String()}}, mail.Content.Headers...)

		// Run OnMessage handlers
		ctx := s.newContext(conn, mail)
		resp := s.runHandlers(ctx, s.onMessage, s.defaultMessageHandler(logger, len(rawData)))
		if resp != nil && resp.IsError() {
			conn.resetTransaction()
			return resp
		}

		conn.completeTransaction()
		return resp
	}

	return &Response{Code: CodeOK, EnhancedCode: string(ESCSuccess), Message: fmt.Sprintf("OK, %d bytes received", chunkSize)}
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
	ctx := s.newContext(conn, nil)
	ctx.Request = Request{Command: CmdRset}

	return s.runHandlers(ctx, s.onReset, s.defaultRsetHandler)
}

// defaultRsetHandler is the default RSET handler.
func (s *Server) defaultRsetHandler(c *Context) *Response {
	c.Connection.resetTransaction()
	return &Response{Code: CodeOK, EnhancedCode: string(ESCSuccess), Message: "OK"}
}

// handleVrfy processes the VRFY command.
func (s *Server) handleVrfy(conn *Connection, args string) *Response {
	if args == "" {
		return &Response{Code: CodeSyntaxError, Message: "Syntax: VRFY <address>"}
	}

	ctx := s.newContext(conn, nil)
	ctx.Request = Request{Command: CmdVrfy, Args: args}

	return s.runHandlers(ctx, s.onVerify, s.defaultVrfyHandler)
}

// defaultVrfyHandler is the default VRFY handler (disabled for privacy).
func (s *Server) defaultVrfyHandler(c *Context) *Response {
	return &Response{Code: CodeCannotVRFY, Message: "Cannot VRFY user, but will accept message and attempt delivery"}
}

// handleExpn processes the EXPN command.
func (s *Server) handleExpn(conn *Connection, args string) *Response {
	if args == "" {
		return &Response{Code: CodeSyntaxError, Message: "Syntax: EXPN <list>"}
	}

	ctx := s.newContext(conn, nil)
	ctx.Request = Request{Command: CmdExpn, Args: args}

	return s.runHandlers(ctx, s.onExpand, s.defaultExpnHandler)
}

// defaultExpnHandler is the default EXPN handler.
// If a handler set "addresses" in context, it writes them as multiline response.
// Otherwise returns the standard "cannot EXPN" message.
func (s *Server) defaultExpnHandler(c *Context) *Response {
	// Check if handler set addresses
	if addrs, ok := c.Get("addresses"); ok {
		if addrList, ok := addrs.([]string); ok && len(addrList) > 0 {
			s.writeMultilineResponse(c.Connection, CodeOK, addrList)
			return nil
		}
	}
	return &Response{Code: CodeCannotVRFY, Message: "Cannot EXPN list, but will accept message and attempt delivery"}
}

// handleHelp processes the HELP command.
func (s *Server) handleHelp(conn *Connection, topic string) *Response {
	topic = strings.TrimSpace(topic)

	ctx := s.newContext(conn, nil)
	ctx.Request = Request{Command: CmdHelp, Args: topic}

	return s.runHandlers(ctx, s.onHelp, s.defaultHelpHandler)
}

// DefaultHelpURL is the default help URL returned by the HELP command.
const DefaultHelpURL = "https://github.com/synqronlabs/raven"

// defaultHelpHandler is the default HELP handler.
func (s *Server) defaultHelpHandler(c *Context) *Response {
	topic := c.Request.Args

	// Check if handler set custom help text
	if help, ok := c.Get("help"); ok {
		if lines, ok := help.([]string); ok && len(lines) > 0 {
			s.writeMultilineResponse(c.Connection, CodeHelpMessage, lines)
			return nil
		}
	}

	if topic == "" {
		lines := []string{
			"Raven ESMTP Server",
			"Supported commands: HELO EHLO MAIL RCPT DATA RSET NOOP QUIT HELP VRFY EXPN",
			"For more information, visit: " + DefaultHelpURL,
		}
		s.writeMultilineResponse(c.Connection, CodeHelpMessage, lines)
		return nil
	}

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
		return &Response{Code: CodeHelpMessage, Message: fmt.Sprintf("No help available for '%s'. Visit: %s", topic, DefaultHelpURL)}
	}

	return &Response{Code: CodeHelpMessage, Message: helpText}
}

// handleQuit processes the QUIT command.
func (s *Server) handleQuit(conn *Connection) *Response {
	conn.setState(StateQuit)
	return &Response{
		Code:    CodeServiceClosing,
		Message: fmt.Sprintf("%s Service closing transmission channel [%s]", s.hostname, conn.Trace.ID),
	}
}

// handleStartTLS processes the STARTTLS command.
func (s *Server) handleStartTLS(conn *Connection) *Response {
	if conn.State() < StateGreeted {
		return &Response{Code: CodeBadSequence, Message: "Send EHLO first"}
	}
	if s.tlsConfig == nil {
		return &Response{Code: CodeCommandNotImplemented, Message: "STARTTLS not implemented"}
	}
	if conn.IsTLS() {
		return &Response{Code: CodeBadSequence, Message: "TLS already active"}
	}

	s.writeResponse(conn, Response{Code: CodeServiceReady, Message: "Ready to start TLS"})

	if err := conn.UpgradeToTLS(s.tlsConfig); err != nil {
		return nil
	}

	return nil
}
