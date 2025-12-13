package raven

import "fmt"

// SMTPCode represents SMTP reply codes (RFC 5321).
// 2yz: Success, 3yz: Continue, 4yz: Transient failure, 5yz: Permanent failure.
type SMTPCode int

const (
	// 2xx - Success
	CodeSystemStatus            SMTPCode = 211
	CodeHelpMessage             SMTPCode = 214
	CodeServiceReady            SMTPCode = 220
	CodeServiceClosing          SMTPCode = 221
	CodeAuthSuccess             SMTPCode = 235
	CodeOK                      SMTPCode = 250
	CodeUserNotLocalWillForward SMTPCode = 251
	CodeCannotVRFY              SMTPCode = 252

	// 3xx - Intermediate
	CodeAuthContinue   SMTPCode = 334
	CodeStartMailInput SMTPCode = 354

	// 4xx - Transient Failure
	CodeServiceUnavailable        SMTPCode = 421
	CodeMailboxUnavailable        SMTPCode = 450
	CodeLocalError                SMTPCode = 451
	CodeInsufficientStorage       SMTPCode = 452
	CodeUnableToAccommodateParams SMTPCode = 455

	// 5xx - Permanent Failure
	CodeCommandUnrecognized    SMTPCode = 500
	CodeSyntaxError            SMTPCode = 501
	CodeCommandNotImplemented  SMTPCode = 502
	CodeBadSequence            SMTPCode = 503
	CodeParameterNotImpl       SMTPCode = 504
	CodeAuthRequired           SMTPCode = 530
	CodeAuthCredentialsInvalid SMTPCode = 535
	CodeMailboxNotFound        SMTPCode = 550
	CodeUserNotLocalTryForward SMTPCode = 551
	CodeExceededStorage        SMTPCode = 552
	CodeMailboxNameInvalid     SMTPCode = 553
	CodeTransactionFailed      SMTPCode = 554
	CodeParamsNotRecognized    SMTPCode = 555
)

// EnhancedCode represents an enhanced status code (RFC 3463, RFC 2034).
// Format: "class.subject.detail" (e.g., "2.1.5").
type EnhancedCode string

const (
	// Success (2.x.x)
	ESCSuccess         EnhancedCode = "2.0.0"
	ESCAddressValid    EnhancedCode = "2.1.0"
	ESCRecipientValid  EnhancedCode = "2.1.5"
	ESCMessageAccepted EnhancedCode = "2.6.0"
	ESCSecuritySuccess EnhancedCode = "2.7.0"

	// Transient Failure (4.x.x)
	ESCTempFailure            EnhancedCode = "4.0.0"
	ESCTempMailboxUnavailable EnhancedCode = "4.2.0"

	// ESCTempSystemFull indicates temporary insufficient storage (4.2.2).
	ESCTempSystemFull EnhancedCode = "4.2.2"

	// ESCTempLocalError indicates temporary local processing error (4.3.0).
	ESCTempLocalError EnhancedCode = "4.3.0"

	// ESCTempInsufficientStorage indicates temporary insufficient storage (4.3.1).
	ESCTempInsufficientStorage EnhancedCode = "4.3.1"

	// ESCTempSystemNotCapable indicates system temporarily not capable (4.3.5).
	ESCTempSystemNotCapable EnhancedCode = "4.3.5"

	// ESCTempTooManyRecipients indicates too many recipients (4.5.3).
	ESCTempTooManyRecipients EnhancedCode = "4.5.3"

	// ESCTempInvalidArgs indicates invalid command arguments (4.5.4).
	ESCTempInvalidArgs EnhancedCode = "4.5.4"

	// ESCTempAuthFailed indicates temporary authentication failure (4.7.0).
	ESCTempAuthFailed EnhancedCode = "4.7.0"

	// ---- Permanent failure codes (5.x.x) ----

	// ESCPermFailure is the general permanent failure code (5.0.0).
	ESCPermFailure EnhancedCode = "5.0.0"

	// ESCBadDestMailbox indicates bad destination mailbox address (5.1.1).
	ESCBadDestMailbox EnhancedCode = "5.1.1"

	// ESCBadDestSystem indicates bad destination system address (5.1.2).
	ESCBadDestSystem EnhancedCode = "5.1.2"

	// ESCBadDestSyntax indicates bad destination mailbox syntax (5.1.3).
	ESCBadDestSyntax EnhancedCode = "5.1.3"

	// ESCMailboxUnavailable indicates mailbox unavailable (5.2.0).
	ESCMailboxUnavailable EnhancedCode = "5.2.0"

	// ESCMailboxFull indicates mailbox full (5.2.2).
	ESCMailboxFull EnhancedCode = "5.2.2"

	// ESCMessageTooLarge indicates message too large (5.2.3).
	ESCMessageTooLarge EnhancedCode = "5.2.3"

	// ESCMailSystemFull indicates mail system storage exceeded (5.3.4).
	ESCMailSystemFull EnhancedCode = "5.3.4"

	// ESCRoutingLoop indicates mail routing loop detected (5.4.6).
	ESCRoutingLoop EnhancedCode = "5.4.6"

	// ESCInvalidCommand indicates invalid/unrecognized command (5.5.0).
	ESCInvalidCommand EnhancedCode = "5.5.0"

	// ESCBadCommandSequence indicates bad command sequence (5.5.1).
	ESCBadCommandSequence EnhancedCode = "5.5.1"

	// ESCSyntaxError indicates syntax error in command or arguments (5.5.2).
	ESCSyntaxError EnhancedCode = "5.5.2"

	// ESCTooManyRecipients indicates too many recipients (permanent) (5.5.3).
	ESCTooManyRecipients EnhancedCode = "5.5.3"

	// ESCInvalidArgs indicates invalid command arguments (5.5.4).
	ESCInvalidArgs EnhancedCode = "5.5.4"

	// ESCContentError indicates message content/media error (5.6.0).
	ESCContentError EnhancedCode = "5.6.0"

	// ESCMediaNotSupported indicates media not supported (5.6.1).
	ESCMediaNotSupported EnhancedCode = "5.6.1"

	// ESCNonASCIINoSMTPUTF8 indicates non-ASCII used without SMTPUTF8 (5.6.7).
	ESCNonASCIINoSMTPUTF8 EnhancedCode = "5.6.7"

	// ESCSecurityError indicates security or policy error (5.7.0).
	ESCSecurityError EnhancedCode = "5.7.0"

	// ESCDeliveryNotAuth indicates delivery not authorized (5.7.1).
	ESCDeliveryNotAuth EnhancedCode = "5.7.1"

	// ESCAuthCredentialsInvalid indicates auth credentials invalid (5.7.8).
	ESCAuthCredentialsInvalid EnhancedCode = "5.7.8"

	// ESCAuthMechanismWeak indicates auth mechanism too weak (5.7.9).
	ESCAuthMechanismWeak EnhancedCode = "5.7.9"

	// ESCEncryptionRequired indicates encryption required (5.7.11).
	ESCEncryptionRequired EnhancedCode = "5.7.11"

	// ESCRequireTLSRequired indicates REQUIRETLS is required (5.7.30).
	ESCRequireTLSRequired EnhancedCode = "5.7.30"
)

// String returns the enhanced code as a string.
func (e EnhancedCode) String() string {
	return string(e)
}

// ForClass adjusts the enhanced code class to match the response code (RFC 2034).
func (e EnhancedCode) ForClass(class int) EnhancedCode {
	if len(e) < 1 {
		return e
	}
	s := string(e)
	switch class {
	case 2:
		return EnhancedCode("2" + s[1:])
	case 4:
		return EnhancedCode("4" + s[1:])
	case 5:
		return EnhancedCode("5" + s[1:])
	default:
		return e
	}
}

// Response represents an SMTP response to be sent to the client.
type Response struct {
	Code         SMTPCode
	EnhancedCode string
	Message      string
}

// String formats the response as an SMTP reply line.
func (r Response) String() string {
	if r.EnhancedCode != "" {
		return fmt.Sprintf("%d %s %s", r.Code, r.EnhancedCode, r.Message)
	}
	return fmt.Sprintf("%d %s", r.Code, r.Message)
}

// IsError returns true for 4xx or 5xx codes.
func (r Response) IsError() bool {
	return r.Code >= 400
}

// IsSuccess returns true for 2xx codes.
func (r Response) IsSuccess() bool {
	return r.Code >= 200 && r.Code < 300
}

// IsIntermediate returns true for 3xx codes.
func (r Response) IsIntermediate() bool {
	return r.Code >= 300 && r.Code < 400
}

// IsTransientError returns true for 4xx codes.
func (r Response) IsTransientError() bool {
	return r.Code >= 400 && r.Code < 500
}

// IsPermanentError returns true for 5xx codes.
func (r Response) IsPermanentError() bool {
	return r.Code >= 500
}

// ToError converts the response to an error.
func (r Response) ToError() error {
	if !r.IsError() {
		return nil
	}
	return fmt.Errorf("SMTP %d: %s", r.Code, r.Message)
}

// ResponseBuilder provides a fluent interface for constructing responses.
type ResponseBuilder struct {
	code         SMTPCode
	enhancedCode EnhancedCode
	message      string
}

// NewResponse creates a new ResponseBuilder.
func NewResponse(code SMTPCode) *ResponseBuilder {
	return &ResponseBuilder{code: code}
}

// WithEnhancedCode sets the enhanced status code (RFC 2034).
func (rb *ResponseBuilder) WithEnhancedCode(code EnhancedCode) *ResponseBuilder {
	rb.enhancedCode = code
	return rb
}

// WithMessage sets the response message text.
func (rb *ResponseBuilder) WithMessage(msg string) *ResponseBuilder {
	rb.message = msg
	return rb
}

// WithMessagef sets the response message using a format string.
func (rb *ResponseBuilder) WithMessagef(format string, args ...any) *ResponseBuilder {
	rb.message = fmt.Sprintf(format, args...)
	return rb
}

// Build creates the final Response.
func (rb *ResponseBuilder) Build() Response {
	return Response{
		Code:         rb.code,
		EnhancedCode: string(rb.enhancedCode),
		Message:      rb.message,
	}
}

// ResponseOK creates a standard 250 OK response with optional enhanced code.
func ResponseOK(message string, enhancedCode string) Response {
	return Response{
		Code:         CodeOK,
		EnhancedCode: enhancedCode,
		Message:      message,
	}
}

// ResponseServiceReady creates a 220 service ready response.
// The domain must be the first word after the code.
func ResponseServiceReady(domain string, message string) Response {
	msg := domain
	if message != "" {
		msg = domain + " " + message
	}
	return Response{
		Code:    CodeServiceReady,
		Message: msg,
	}
}

// ResponseServiceClosing creates a 221 service closing response.
// The domain must be the first word after the code.
func ResponseServiceClosing(domain string, message string) Response {
	msg := domain
	if message != "" {
		msg = domain + " " + message
	}
	return Response{
		Code:    CodeServiceClosing,
		Message: msg,
	}
}

// ResponseServiceUnavailable creates a 421 service unavailable response.
// The domain must be the first word after the code.
func ResponseServiceUnavailable(domain string, message string) Response {
	msg := domain
	if message != "" {
		msg = domain + " " + message
	}
	return Response{
		Code:    CodeServiceUnavailable,
		Message: msg,
	}
}

// ResponseBadSequence creates a 503 bad sequence of commands response.
func ResponseBadSequence(message string) Response {
	return Response{
		Code:    CodeBadSequence,
		Message: message,
	}
}

// ResponseSyntaxError creates a 501 syntax error response.
func ResponseSyntaxError(message string) Response {
	return Response{
		Code:    CodeSyntaxError,
		Message: message,
	}
}

// ResponseCommandNotRecognized creates a 500 command not recognized response.
func ResponseCommandNotRecognized(command string) Response {
	return Response{
		Code:    CodeCommandUnrecognized,
		Message: fmt.Sprintf("Command not recognized: %s", command),
	}
}

// ResponseCommandNotImplemented creates a 502 command not implemented response.
func ResponseCommandNotImplemented(command string) Response {
	return Response{
		Code:    CodeCommandNotImplemented,
		Message: fmt.Sprintf("%s not implemented", command),
	}
}

// ResponseMailboxNotFound creates a 550 mailbox not found response.
func ResponseMailboxNotFound(message string) Response {
	return Response{
		Code:    CodeMailboxNotFound,
		Message: message,
	}
}

// ResponseCannotVRFY creates a 252 response for VRFY when verification is disabled.
// Indicates the server cannot verify the address but will attempt delivery.
func ResponseCannotVRFY(message string) Response {
	if message == "" {
		message = "Cannot VRFY user, but will accept message and attempt delivery"
	}
	return Response{
		Code:    CodeCannotVRFY,
		Message: message,
	}
}

// ResponseUserNotLocalWillForward creates a 251 response for forwarding.
// The forward-path must be included.
func ResponseUserNotLocalWillForward(forwardPath string) Response {
	return Response{
		Code:    CodeUserNotLocalWillForward,
		Message: fmt.Sprintf("User not local; will forward to <%s>", forwardPath),
	}
}

// ResponseUserNotLocalTryForward creates a 551 response for user not local.
// The forward-path must be included for the client to retry.
func ResponseUserNotLocalTryForward(forwardPath string) Response {
	return Response{
		Code:    CodeUserNotLocalTryForward,
		Message: fmt.Sprintf("User not local; please try <%s>", forwardPath),
	}
}

// ResponseParamsNotRecognized creates a 555 response for unrecognized parameters.
// Used when MAIL FROM/RCPT TO parameters are not recognized.
func ResponseParamsNotRecognized(param string) Response {
	return Response{
		Code:         CodeParamsNotRecognized,
		EnhancedCode: string(ESCInvalidArgs),
		Message:      fmt.Sprintf("Parameter not recognized: %s", param),
	}
}

// ResponseUnableToAccommodateParams creates a 455 response for parameter accommodation failure.
// This is a transient error - client may retry later.
func ResponseUnableToAccommodateParams(message string) Response {
	return Response{
		Code:         CodeUnableToAccommodateParams,
		EnhancedCode: string(ESCTempInvalidArgs),
		Message:      message,
	}
}

// ResponseAuthRequired creates a 530 authentication required response.
// Used when authentication is required before proceeding.
func ResponseAuthRequired(message string) Response {
	if message == "" {
		message = "Authentication required"
	}
	return Response{
		Code:         CodeAuthRequired,
		EnhancedCode: string(ESCSecurityError),
		Message:      message,
	}
}

// ResponseAuthCredentialsInvalid creates a 535 authentication credentials invalid response.
// Used when authentication fails due to invalid credentials.
func ResponseAuthCredentialsInvalid(message string) Response {
	if message == "" {
		message = "Authentication credentials invalid"
	}
	return Response{
		Code:         CodeAuthCredentialsInvalid,
		EnhancedCode: string(ESCAuthCredentialsInvalid),
		Message:      message,
	}
}

// ResponseTransactionFailed creates a 554 transaction failed response.
func ResponseTransactionFailed(message string, enhancedCode EnhancedCode) Response {
	return Response{
		Code:         CodeTransactionFailed,
		EnhancedCode: string(enhancedCode),
		Message:      message,
	}
}

// ResponseLocalError creates a 451 local error response.
// Indicates the action was aborted due to a server error.
func ResponseLocalError(message string) Response {
	return Response{
		Code:         CodeLocalError,
		EnhancedCode: string(ESCTempLocalError),
		Message:      message,
	}
}

// ResponseExceededStorage creates a 552 exceeded storage response.
func ResponseExceededStorage(message string) Response {
	if message == "" {
		message = "Requested mail action aborted: exceeded storage allocation"
	}
	return Response{
		Code:         CodeExceededStorage,
		EnhancedCode: string(ESCMailSystemFull),
		Message:      message,
	}
}

// ResponseInsufficientStorage creates a 452 insufficient storage response.
// This is a transient error - client may retry later.
func ResponseInsufficientStorage(message string) Response {
	if message == "" {
		message = "Insufficient system storage"
	}
	return Response{
		Code:         CodeInsufficientStorage,
		EnhancedCode: string(ESCTempInsufficientStorage),
		Message:      message,
	}
}
