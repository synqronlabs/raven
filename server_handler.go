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

// detectLoop checks for mail loops by counting the "Received" headers,
// and returns an error if the count exceeds maxAllowed.
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

func (s *Server) handleHelo(conn *Connection, hostname string) *Response {
	if hostname == "" {
		resp := ResponseSyntaxError("Hostname required")
		return &resp
	}

	if s.config.Callbacks != nil && s.config.Callbacks.OnHelo != nil {
		if err := s.config.Callbacks.OnHelo(conn.Context(), conn, hostname); err != nil {
			resp := ResponseMailboxNotFound(err.Error())
			return &resp
		}
	}

	conn.setClientHostname(hostname)
	conn.setState(StateGreeted)
	conn.resetTransaction()

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

func (s *Server) handleEhlo(conn *Connection, hostname string) *Response {
	if hostname == "" {
		resp := ResponseSyntaxError("Hostname required")
		return &resp
	}

	extensions := s.buildExtensions(conn)
	if s.config.EnableChunking {
		extensions[ExtChunking] = ""
		conn.SetExtension(ExtChunking, "")
		// BINARYMIME requires CHUNKING
		extensions[ExtBinaryMIME] = ""
		conn.SetExtension(ExtBinaryMIME, "")
	}
	// AUTH - only advertise if TLS is not required or TLS is active
	effectiveMechanisms := s.getEffectiveAuthMechanisms()
	if len(effectiveMechanisms) > 0 && (!s.config.RequireTLS || conn.IsTLS()) {
		authParams := strings.Join(effectiveMechanisms, " ")
		extensions[ExtAuth] = authParams
		conn.SetExtension(ExtAuth, authParams)
	}

	// REQUIRETLS - only advertised when TLS is active
	if conn.IsTLS() && s.config.TLSConfig != nil {
		extensions[ExtRequireTLS] = ""
		conn.SetExtension(ExtRequireTLS, "")
	}

	if s.config.Callbacks != nil && s.config.Callbacks.OnEhlo != nil {
		extOverride, err := s.config.Callbacks.OnEhlo(conn.Context(), conn, hostname)
		if err != nil {
			resp := ResponseMailboxNotFound(err.Error())
			return &resp
		}
		if extOverride != nil {
			extensions = extOverride
		}
	}

	conn.setClientHostname(hostname)
	conn.setState(StateGreeted)
	conn.resetTransaction()

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

// buildExtensions centralizes all SMTP extension setup for a given connection.
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

	return extensions
}

func (s *Server) handleMail(conn *Connection, args string) *Response {
	// Get state info in a single lock acquisition
	stateInfo := conn.getStateInfo()

	if stateInfo.State < StateGreeted {
		resp := ResponseBadSequence("Send EHLO/HELO first")
		return &resp
	}
	if stateInfo.State >= StateMail {
		resp := ResponseBadSequence("MAIL command already given")
		return &resp
	}

	// Check TLS requirement
	if s.config.RequireTLS && !stateInfo.IsTLS {
		resp := ResponseTransactionFailed("TLS required", ESCSecurityError)
		return &resp
	}

	// Check auth requirement
	if s.config.RequireAuth && !stateInfo.IsAuthenticated {
		resp := ResponseTransactionFailed("Authentication required", ESCSecurityError)
		return &resp
	}

	// Parse MAIL FROM:<address> [params]
	args = strings.TrimSpace(args)
	if !strings.HasPrefix(strings.ToUpper(args), "FROM:") {
		resp := ResponseSyntaxError("Syntax: MAIL FROM:<address>")
		return &resp
	}
	args = strings.TrimSpace(args[5:])

	from, params, err := parsePathWithParams(args)
	if err != nil {
		resp := ResponseSyntaxError(err.Error())
		return &resp
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
			resp := ResponseSyntaxError("Invalid SIZE parameter")
			return &resp
		}
		if conn.Limits.MaxMessageSize > 0 && size > conn.Limits.MaxMessageSize {
			resp := ResponseExceededStorage("Message too large")
			return &resp
		}
	}

	// SPF check per RFC 7208
	var spfResult *SPFCheckResult
	if s.config.SPF != nil && s.config.SPF.Enabled {
		clientIP, err := utils.GetIPFromAddr(conn.RemoteAddr())
		if err == nil {
			// Determine the domain to check
			var senderDomain string
			if from.IsNull() {
				// Null sender: use HELO domain per RFC 7208 Section 2.4
				conn.mu.RLock()
				senderDomain = conn.Trace.ClientHostname
				conn.mu.RUnlock()
			} else {
				senderDomain = from.Mailbox.Domain
			}

			if senderDomain != "" {
				// Prepare sender identity
				sender := from.Mailbox.String()
				if sender == "" {
					sender = "postmaster@" + senderDomain
				}

				// Configure SPF check options
				checkOpts := s.config.SPF.CheckOptions
				if checkOpts == nil {
					checkOpts = DefaultSPFCheckOptions()
				}
				// Set HELO domain for macro expansion
				conn.mu.RLock()
				checkOpts.HeloDomain = conn.Trace.ClientHostname
				conn.mu.RUnlock()
				checkOpts.ReceiverDomain = s.config.Hostname

				// Perform SPF check
				spfResult = CheckSPF(clientIP, senderDomain, sender, checkOpts)

				// Handle SPF result based on configuration
				switch spfResult.Result {
				case SPFResultFail:
					if s.config.SPF.FailAction == SPFActionReject {
						return &Response{
							Code:         CodeTransactionFailed,
							EnhancedCode: string(ESCSecurityError),
							Message:      fmt.Sprintf("SPF check failed: %s", spfResult.Domain),
						}
					}
				case SPFResultSoftfail:
					if s.config.SPF.SoftFailAction == SPFActionReject {
						return &Response{
							Code:         CodeTransactionFailed,
							EnhancedCode: string(ESCSecurityError),
							Message:      fmt.Sprintf("SPF check softfailed: %s", spfResult.Domain),
						}
					}
				case SPFResultPermerror:
					// Permanent error in SPF record - log but usually accept
					s.config.Logger.Warn("SPF permerror",
						slog.String("domain", senderDomain),
						slog.String("client_ip", clientIP.String()),
						slog.Any("error", spfResult.Error),
					)
				case SPFResultTemperror:
					// Transient error - could temporarily reject
					s.config.Logger.Warn("SPF temperror",
						slog.String("domain", senderDomain),
						slog.String("client_ip", clientIP.String()),
						slog.Any("error", spfResult.Error),
					)
				}
			}
		}
	}

	if s.config.Callbacks != nil && s.config.Callbacks.OnMailFrom != nil {
		if err := s.config.Callbacks.OnMailFrom(conn.Context(), conn, from, params); err != nil {
			resp := ResponseMailboxNotFound(err.Error())
			return &resp
		}
	}

	// Start transaction
	mail := conn.beginTransaction()
	mail.Envelope.From = from

	// Store SPF result if available
	if spfResult != nil {
		mail.Envelope.SPFResult = spfResult
	}

	// Set default body type to 7BIT
	mail.Envelope.BodyType = BodyType7Bit

	// Process parameters
	if bodyType, ok := params["BODY"]; ok {
		bodyTypeUpper := BodyType(strings.ToUpper(bodyType))
		// Validate BODY parameter per RFC 6152
		switch bodyTypeUpper {
		case BodyType7Bit, BodyType8BitMIME, BodyTypeBinaryMIME:
			mail.Envelope.BodyType = bodyTypeUpper
		default:
			return &Response{
				Code:         CodeParameterNotImpl,
				EnhancedCode: string(ESCInvalidArgs),
				Message:      "Invalid BODY parameter",
			}
		}
		// Check if BINARYMIME extension is enabled (requires CHUNKING - opt-in)
		if bodyTypeUpper == BodyTypeBinaryMIME && !s.config.EnableChunking {
			return &Response{
				Code:         CodeParameterNotImpl,
				EnhancedCode: string(ESCInvalidArgs),
				Message:      "BINARYMIME not supported",
			}
		}
	}
	if _, ok := params["SMTPUTF8"]; ok {
		mail.Envelope.SMTPUTF8 = true
	}
	// The REQUIRETLS option MUST only be specified in the context of an SMTP
	// session meeting the security requirements:
	// - The session itself MUST employ TLS transmission
	// - The server MUST advertise REQUIRETLS in EHLO response
	if _, ok := params["REQUIRETLS"]; ok {
		// Check if connection is using TLS
		if !conn.IsTLS() {
			return &Response{
				Code:         CodeTransactionFailed,
				EnhancedCode: string(ESCSecurityError),
				Message:      "REQUIRETLS requires TLS connection",
			}
		}
		// Check if REQUIRETLS extension is advertised (connection should have it after TLS)
		if !conn.HasExtension(ExtRequireTLS) {
			return &Response{
				Code:         CodeTransactionFailed,
				EnhancedCode: string(ESCRequireTLSRequired),
				Message:      "REQUIRETLS support required",
			}
		}
		mail.Envelope.RequireTLS = true
	}
	if envID, ok := params["ENVID"]; ok {
		if !s.config.EnableDSN {
			return &Response{
				Code:         CodeParameterNotImpl,
				EnhancedCode: string(ESCInvalidArgs),
				Message:      "DSN not supported",
			}
		}
		// ENVID parameter max 100 characters
		if len(envID) > 100 {
			return &Response{
				Code:         CodeSyntaxError,
				EnhancedCode: string(ESCInvalidArgs),
				Message:      "ENVID parameter too long (max 100 characters)",
			}
		}
		mail.Envelope.EnvID = envID
	}
	if ret, ok := params["RET"]; ok {
		if !s.config.EnableDSN {
			return &Response{
				Code:         CodeParameterNotImpl,
				EnhancedCode: string(ESCInvalidArgs),
				Message:      "DSN not supported",
			}
		}
		// RET parameter max 8 characters
		if len(ret) > 8 {
			return &Response{
				Code:         CodeSyntaxError,
				EnhancedCode: string(ESCInvalidArgs),
				Message:      "RET parameter too long",
			}
		}
		// RET parameter must be FULL or HDRS
		retUpper := strings.ToUpper(ret)
		if retUpper != "FULL" && retUpper != "HDRS" {
			return &Response{
				Code:         CodeSyntaxError,
				EnhancedCode: string(ESCInvalidArgs),
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

	conn.setState(StateMail)

	return &Response{
		Code:         CodeOK,
		EnhancedCode: string(ESCAddressValid),
		Message:      "OK",
	}
}

func (s *Server) handleRcpt(conn *Connection, args string) *Response {
	if conn.State() < StateMail {
		resp := ResponseBadSequence("Send MAIL first")
		return &resp
	}

	mail := conn.CurrentMail()
	if mail == nil {
		resp := ResponseBadSequence("No mail transaction")
		return &resp
	}

	// Check recipient limit
	// Use 452 for "too many recipients"
	// This is a transient error - the client may try fewer recipients.
	if conn.Limits.MaxRecipients > 0 && len(mail.Envelope.To) >= conn.Limits.MaxRecipients {
		return &Response{
			Code:         CodeInsufficientStorage,
			EnhancedCode: string(ESCTempTooManyRecipients),
			Message:      "Too many recipients",
		}
	}

	// Parse RCPT TO:<address> [params]
	args = strings.TrimSpace(args)
	if !strings.HasPrefix(strings.ToUpper(args), "TO:") {
		resp := ResponseSyntaxError("Syntax: RCPT TO:<address>")
		return &resp
	}
	args = strings.TrimSpace(args[3:])

	to, params, err := parsePathWithParams(args)
	if err != nil {
		resp := ResponseSyntaxError(err.Error())
		return &resp
	}

	// Non-ASCII addresses require SMTPUTF8 to have been requested in MAIL FROM
	// SMTPUTF8 is an intrinsic extension (always enabled), but clients must
	// explicitly request it for non-ASCII addresses per the RFC.
	if utils.ContainsNonASCII(to.Mailbox.LocalPart) || utils.ContainsNonASCII(to.Mailbox.Domain) {
		if !mail.Envelope.SMTPUTF8 {
			return &Response{
				Code:         CodeMailboxNameInvalid,
				EnhancedCode: string(ESCNonASCIINoSMTPUTF8),
				Message:      "Address contains non-ASCII characters but SMTPUTF8 not requested",
			}
		}
	}

	if s.config.Callbacks != nil && s.config.Callbacks.OnRcptTo != nil {
		if err := s.config.Callbacks.OnRcptTo(conn.Context(), conn, to, params); err != nil {
			resp := ResponseMailboxNotFound(err.Error())
			return &resp
		}
	}

	rcpt := Recipient{Address: to}
	if notify, ok := params["NOTIFY"]; ok {
		if !s.config.EnableDSN {
			return &Response{
				Code:         CodeParameterNotImpl,
				EnhancedCode: string(ESCInvalidArgs),
				Message:      "DSN not supported",
			}
		}
		// NOTIFY parameter max 28 characters
		if len(notify) > 28 {
			return &Response{
				Code:         CodeSyntaxError,
				EnhancedCode: string(ESCInvalidArgs),
				Message:      "NOTIFY parameter too long (max 28 characters)",
			}
		}
		// Validate NOTIFY parameter values
		notifyValues := strings.Split(strings.ToUpper(notify), ",")
		hasNever := false
		for _, v := range notifyValues {
			v = strings.TrimSpace(v)
			switch v {
			case "NEVER":
				hasNever = true
			case "SUCCESS", "FAILURE", "DELAY":
			default:
				return &Response{
					Code:         CodeSyntaxError,
					EnhancedCode: string(ESCInvalidArgs),
					Message:      "Invalid NOTIFY parameter value",
				}
			}
		}
		// NEVER must appear by itself
		if hasNever && len(notifyValues) > 1 {
			return &Response{
				Code:         CodeSyntaxError,
				EnhancedCode: string(ESCInvalidArgs),
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
				EnhancedCode: string(ESCInvalidArgs),
				Message:      "DSN not supported",
			}
		}
		// ORCPT parameter max 500 characters
		if len(orcpt) > 500 {
			return &Response{
				Code:         CodeSyntaxError,
				EnhancedCode: string(ESCInvalidArgs),
				Message:      "ORCPT parameter too long (max 500 characters)",
			}
		}
		// ORCPT format is addr-type ";" xtext
		if !strings.Contains(orcpt, ";") {
			return &Response{
				Code:         CodeSyntaxError,
				EnhancedCode: string(ESCInvalidArgs),
				Message:      "Invalid ORCPT parameter: must be addr-type;address",
			}
		}
		if rcpt.DSNParams == nil {
			rcpt.DSNParams = &DSNRecipientParams{}
		}
		rcpt.DSNParams.ORcpt = orcpt
	}

	mail.Envelope.To = append(mail.Envelope.To, rcpt)
	conn.setState(StateRcpt)

	return &Response{
		Code:         CodeOK,
		EnhancedCode: string(ESCRecipientValid),
		Message:      "OK",
	}
}

func (s *Server) handleData(conn *Connection, reader *bufio.Reader, logger *slog.Logger) *Response {
	if conn.State() < StateRcpt {
		resp := ResponseBadSequence("Send RCPT first")
		return &resp
	}

	mail := conn.CurrentMail()
	if mail == nil || len(mail.Envelope.To) == 0 {
		resp := ResponseBadSequence("No recipients")
		return &resp
	}

	if s.config.Callbacks != nil && s.config.Callbacks.OnData != nil {
		if err := s.config.Callbacks.OnData(conn.Context(), conn); err != nil {
			resp := ResponseTransactionFailed(err.Error(), ESCPermFailure)
			return &resp
		}
	}

	conn.setState(StateData)

	// Send intermediate response
	s.writeResponse(conn, Response{
		Code:    CodeStartMailInput,
		Message: "Start mail input; end with <CRLF>.<CRLF>",
	})

	// Set data timeout
	if err := conn.conn.SetReadDeadline(time.Now().Add(s.config.DataTimeout)); err != nil {
		resp := ResponseLocalError("Internal error")
		return &resp
	}

	// Check for BINARYMIME early - it requires BDAT command, not DATA
	if mail.Envelope.BodyType == BodyTypeBinaryMIME {
		conn.resetTransaction()
		return &Response{
			Code:         CodeBadSequence,
			EnhancedCode: string(ESCInvalidCommand),
			Message:      "BINARYMIME requires BDAT command",
		}
	}

	// Read message data, validating 7BIT if required
	enforce7Bit := mail.Envelope.BodyType == BodyType7Bit
	data, err := s.readDataContent(reader, conn.Limits.MaxMessageSize, enforce7Bit)
	if err != nil {
		if errors.Is(err, ErrMessageTooLarge) {
			conn.resetTransaction()
			resp := ResponseExceededStorage("Message too large")
			return &resp
		}
		if errors.Is(err, ravenio.ErrBadLineEnding) {
			conn.resetTransaction()
			return &Response{
				Code:         CodeSyntaxError,
				EnhancedCode: string(ESCContentError),
				Message:      "Message must use CRLF line endings",
			}
		}
		if errors.Is(err, ravenio.Err8BitIn7BitMode) {
			conn.resetTransaction()
			resp := ResponseTransactionFailed("Message contains 8-bit data but BODY=8BITMIME was not specified", ESCContentError)
			return &resp
		}
		if errors.Is(err, ravenio.ErrLineTooLong) {
			conn.resetTransaction()
			return &Response{
				Code:         CodeSyntaxError,
				EnhancedCode: string(ESCContentError),
				Message:      "Line length exceeds maximum allowed",
			}
		}
		logger.Error("data read error", slog.Any("error", err))
		conn.resetTransaction()
		resp := ResponseLocalError("Error reading message")
		return &resp
	}

	// Parse message content into headers and body per RFC 5322 using FromRaw
	mail.Content.FromRaw(data)

	// If the REQUIRETLS MAIL FROM parameter was not specified,
	// check for TLS-Required header field in the message.
	// Note: If REQUIRETLS MAIL FROM parameter is specified, the TLS-Required header
	// field MUST be ignored (but MAY be included in onward relay).
	if !mail.Envelope.RequireTLS {
		tlsRequiredHeader := mail.Content.Headers.Get("TLS-Required")
		if strings.EqualFold(strings.TrimSpace(tlsRequiredHeader), "No") {
			// TLS-Required: No indicates sender wants TLS policies to be ignored
			// This is stored for the application to handle during relay
			if mail.Envelope.ExtensionParams == nil {
				mail.Envelope.ExtensionParams = make(map[string]string)
			}
			mail.Envelope.ExtensionParams["TLS-OPTIONAL"] = "yes"
		}
	}

	// Loop detection via Received header count
	// Simple counting of Received headers is an effective method of detecting loops.
	// RFC recommends a large rejection threshold, normally at least 100.
	if err := detectLoop(mail, logger, s.config.MaxReceivedHeaders); err != nil {
		conn.resetTransaction()
		resp := ResponseTransactionFailed(err.Error(), ESCRoutingLoop)
		return &resp
	}

	mail.ID = utils.GenerateID()
	// Update ReceivedAt to reflect when message content was actually received
	mail.ReceivedAt = time.Now()

	receivedHeader := conn.GenerateReceivedHeader("")
	receivedHeader.ID = mail.ID
	mail.Trace = append([]TraceField{receivedHeader}, mail.Trace...)

	// Prepend Received header to message content
	mail.Content.Headers = append(Headers{{
		Name:  "Received",
		Value: receivedHeader.String(),
	}}, mail.Content.Headers...)

	// Add Received-SPF header if SPF check was performed per RFC 7208 Section 9.1
	if mail.Envelope.SPFResult != nil {
		mail.Content.Headers = append(Headers{{
			Name:  "Received-SPF",
			Value: mail.Envelope.SPFResult.ReceivedSPFHeader()[len("Received-SPF: "):],
		}}, mail.Content.Headers...)
	}

	if s.config.Callbacks != nil && s.config.Callbacks.OnMessage != nil {
		if err := s.config.Callbacks.OnMessage(conn.Context(), conn, mail); err != nil {
			conn.resetTransaction()
			resp := ResponseTransactionFailed(err.Error(), ESCPermFailure)
			return &resp
		}
	}

	conn.completeTransaction()

	logger.Info("message received",
		slog.String("mail_id", mail.ID),
		slog.String("from", mail.Envelope.From.String()),
		slog.Int("recipients", len(mail.Envelope.To)),
		slog.Int("size", len(data)),
	)

	return &Response{
		Code:         CodeOK,
		EnhancedCode: string(ESCSuccess),
		Message:      fmt.Sprintf("OK, queued as %s [%s]", mail.ID, conn.Trace.ID),
	}
}

// readDataContent reads the message content until <CRLF>.<CRLF>.
// Strictly requires CRLF line endings to prevent SMTP smuggling attacks.
// If enforce7Bit is true, returns Err8BitIn7BitMode if any non-ASCII bytes are found.
// Line length is enforced per RFC 5322 (998 characters max, excluding CRLF).
func (s *Server) readDataContent(reader *bufio.Reader, maxSize int64, enforce7Bit bool) ([]byte, error) {
	// Pre-allocate buffer with reasonable initial capacity
	// Use maxSize as initial buffer capacity if it's set, within a reasonable limit, otherwise default to 4096
	const maxInitialAlloc = 10 * 1024 * 1024 // 10MB cap for initial alloc to avoid OOM
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

	// Use RFC 5322 MaxLineLength (998) for message content, not SMTP command limit
	// Add 2 for CRLF that ReadLine expects
	maxContentLineLength := MaxLineLength + 2

	for {
		line, err := ravenio.ReadLine(reader, maxContentLineLength, enforce7Bit)
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

		// Remove dot-stuffing
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

// handleBDAT processes the BDAT command (RFC 3030).
func (s *Server) handleBDAT(conn *Connection, args string, reader *bufio.Reader, logger *slog.Logger) *Response {
	// Check if CHUNKING is enabled
	if !s.config.EnableChunking {
		resp := ResponseCommandNotImplemented("BDAT")
		return &resp
	}

	// Must have recipients first (either from StateRcpt or ongoing BDAT)
	// Get state once to avoid multiple lock acquisitions
	state := conn.State()
	if state < StateRcpt && state != StateBDAT {
		resp := ResponseBadSequence("Send RCPT first")
		return &resp
	}

	mail := conn.CurrentMail()
	if mail == nil || len(mail.Envelope.To) == 0 {
		resp := ResponseBadSequence("No recipients")
		return &resp
	}

	// Parse BDAT arguments: <size> [LAST]
	args = strings.TrimSpace(args)
	if args == "" {
		resp := ResponseSyntaxError("Syntax: BDAT <size> [LAST]")
		return &resp
	}

	parts := strings.Fields(args)
	if len(parts) < 1 || len(parts) > 2 {
		resp := ResponseSyntaxError("Syntax: BDAT <size> [LAST]")
		return &resp
	}

	chunkSize, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || chunkSize < 0 {
		resp := ResponseSyntaxError("Invalid chunk size")
		return &resp
	}

	isLast := false
	if len(parts) == 2 {
		if strings.ToUpper(parts[1]) != "LAST" {
			resp := ResponseSyntaxError("Syntax: BDAT <size> [LAST]")
			return &resp
		}
		isLast = true
	}

	// Check if adding this chunk would exceed max message size
	currentSize := conn.getBDATBufferSize()
	if conn.Limits.MaxMessageSize > 0 && currentSize+chunkSize > conn.Limits.MaxMessageSize {
		// Discard the chunk data to keep protocol in sync
		s.discardBDATChunk(reader, chunkSize)
		conn.resetTransaction()
		resp := ResponseExceededStorage("Message too large")
		return &resp
	}

	if s.config.Callbacks != nil && s.config.Callbacks.OnBDAT != nil {
		if err := s.config.Callbacks.OnBDAT(conn.Context(), conn, chunkSize, isLast); err != nil {
			// Discard the chunk data to keep protocol in sync
			s.discardBDATChunk(reader, chunkSize)
			conn.resetTransaction()
			resp := ResponseTransactionFailed(err.Error(), ESCPermFailure)
			return &resp
		}
	}

	conn.setState(StateBDAT)

	// Set data timeout
	if err := conn.conn.SetReadDeadline(time.Now().Add(s.config.DataTimeout)); err != nil {
		resp := ResponseLocalError("Internal error")
		return &resp
	}

	// Read the chunk data (binary, exact size)
	chunkData, err := s.readBDATChunk(reader, chunkSize)
	if err != nil {
		logger.Error("BDAT read error", slog.Any("error", err))
		conn.resetTransaction()
		resp := ResponseLocalError("Error reading chunk data")
		return &resp
	}

	// Append chunk to connection's BDAT buffer
	conn.appendBDATChunk(chunkData)

	// If this is the last chunk, complete the transaction
	if isLast {
		// Get accumulated data and parse into headers and body
		rawData := conn.consumeBDATBuffer()
		mail.Content.FromRaw(rawData)

		// Loop detection via Received header count
		// Simple counting of Received headers is an effective method of detecting loops.
		// RFC recommends a large rejection threshold, normally at least 100.
		if err := detectLoop(mail, logger, s.config.MaxReceivedHeaders); err != nil {
			conn.resetTransaction()
			resp := ResponseTransactionFailed(err.Error(), ESCRoutingLoop)
			return &resp
		}

		mail.ID = utils.GenerateID()
		// Update ReceivedAt to reflect when message content was actually received
		mail.ReceivedAt = time.Now()

		// Add Received header to trace per
		receivedHeader := conn.GenerateReceivedHeader("")
		receivedHeader.ID = mail.ID
		mail.Trace = append([]TraceField{receivedHeader}, mail.Trace...)

		// Prepend Received header to message content
		mail.Content.Headers = append(Headers{{
			Name:  "Received",
			Value: receivedHeader.String(),
		}}, mail.Content.Headers...)

		// Add Received-SPF header if SPF check was performed per RFC 7208 Section 9.1
		if mail.Envelope.SPFResult != nil {
			mail.Content.Headers = append(Headers{{
				Name:  "Received-SPF",
				Value: mail.Envelope.SPFResult.ReceivedSPFHeader()[len("Received-SPF: "):],
			}}, mail.Content.Headers...)
		}

		// OnMessage callback
		if s.config.Callbacks != nil && s.config.Callbacks.OnMessage != nil {
			if err := s.config.Callbacks.OnMessage(conn.Context(), conn, mail); err != nil {
				conn.resetTransaction()
				resp := ResponseTransactionFailed(err.Error(), ESCPermFailure)
				return &resp
			}
		}

		// Complete transaction
		conn.completeTransaction()

		logger.Info("message received via BDAT",
			slog.String("mail_id", mail.ID),
			slog.String("from", mail.Envelope.From.String()),
			slog.Int("recipients", len(mail.Envelope.To)),
			slog.Int("size", len(rawData)),
		)

		return &Response{
			Code:         CodeOK,
			EnhancedCode: string(ESCSuccess),
			Message:      fmt.Sprintf("OK, queued as %s [%s]", mail.ID, conn.Trace.ID),
		}
	}

	// Not the last chunk, acknowledge and wait for more
	return &Response{
		Code:         CodeOK,
		EnhancedCode: string(ESCSuccess),
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

func (s *Server) handleRset(conn *Connection) *Response {
	if s.config.Callbacks != nil && s.config.Callbacks.OnReset != nil {
		s.config.Callbacks.OnReset(conn.Context(), conn)
	}

	conn.resetTransaction()

	resp := ResponseOK("OK", string(ESCSuccess))
	return &resp
}

// handleVrfy processes the VRFY command.
func (s *Server) handleVrfy(conn *Connection, args string) *Response {
	if args == "" {
		resp := ResponseSyntaxError("Syntax: VRFY <address>")
		return &resp
	}

	if s.config.Callbacks != nil && s.config.Callbacks.OnVerify != nil {
		addr, err := s.config.Callbacks.OnVerify(conn.Context(), conn, args)
		if err != nil {
			resp := ResponseMailboxNotFound(err.Error())
			return &resp
		}
		resp := ResponseOK(addr.String(), "")
		return &resp
	}

	// When VRFY is disabled for security/privacy,
	// the server SHOULD use 252 to indicate it cannot verify but will accept.
	// Using 550 would incorrectly indicate the mailbox doesn't exist.
	resp := ResponseCannotVRFY("")
	return &resp
}

// handleExpn processes the EXPN command.
func (s *Server) handleExpn(conn *Connection, args string) *Response {
	if args == "" {
		resp := ResponseSyntaxError("Syntax: EXPN <list>")
		return &resp
	}

	if s.config.Callbacks != nil && s.config.Callbacks.OnExpand != nil {
		addrs, err := s.config.Callbacks.OnExpand(conn.Context(), conn, args)
		if err != nil {
			resp := ResponseMailboxNotFound(err.Error())
			return &resp
		}
		lines := make([]string, len(addrs))
		for i, addr := range addrs {
			lines[i] = addr.String()
		}
		s.writeMultilineResponse(conn, CodeOK, lines)
		return nil
	}

	// When EXPN is disabled for security/privacy,
	// the server SHOULD use 252 to indicate it cannot expand but will accept.
	return &Response{
		Code:    CodeCannotVRFY,
		Message: "Cannot EXPN list, but will accept message and attempt delivery",
	}
}

// DefaultHelpURL is the default help URL returned by the HELP command.
const DefaultHelpURL = "https://github.com/synqronlabs/raven"

// handleHelp processes the HELP command.
func (s *Server) handleHelp(conn *Connection, topic string) *Response {
	topic = strings.TrimSpace(topic)

	if s.config.Callbacks != nil && s.config.Callbacks.OnHelp != nil {
		lines := s.config.Callbacks.OnHelp(conn.Context(), conn, topic)
		if len(lines) > 0 {
			// 214 for specific help information
			s.writeMultilineResponse(conn, CodeHelpMessage, lines)
			return nil
		}
	}

	if topic == "" {
		// 214 is also acceptable, but 211 is more appropriate for general system info
		lines := []string{
			"Raven ESMTP Server",
			"Supported commands: HELO EHLO MAIL RCPT DATA RSET NOOP QUIT HELP VRFY EXPN",
			"For more information, visit: " + DefaultHelpURL,
		}
		s.writeMultilineResponse(conn, CodeHelpMessage, lines)
		return nil
	}

	// Topic-specific help - use 214
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

func (s *Server) handleQuit(conn *Connection) *Response {
	conn.setState(StateQuit)
	resp := ResponseServiceClosing(s.config.Hostname, fmt.Sprintf("Service closing transmission channel [%s]", conn.Trace.ID))
	return &resp
}

func (s *Server) handleStartTLS(conn *Connection) *Response {
	if conn.State() < StateGreeted {
		resp := ResponseBadSequence("Send EHLO first")
		return &resp
	}
	if s.config.TLSConfig == nil {
		resp := ResponseCommandNotImplemented("STARTTLS")
		return &resp
	}
	if conn.IsTLS() {
		resp := ResponseBadSequence("TLS already active")
		return &resp
	}

	if s.config.Callbacks != nil && s.config.Callbacks.OnStartTLS != nil {
		if err := s.config.Callbacks.OnStartTLS(conn.Context(), conn); err != nil {
			resp := ResponseTransactionFailed(err.Error(), ESCPermFailure)
			return &resp
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
