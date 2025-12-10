package raven

import "fmt"

// SMTPCode represents standard SMTP reply codes per RFC 5321.
type SMTPCode int

const (
	CodeServiceReady          SMTPCode = 220
	CodeServiceClosing        SMTPCode = 221
	CodeAuthSuccess           SMTPCode = 235
	CodeOK                    SMTPCode = 250
	CodeStartMailInput        SMTPCode = 354
	CodeServiceUnavailable    SMTPCode = 421
	CodeMailboxUnavailable    SMTPCode = 450
	CodeLocalError            SMTPCode = 451
	CodeInsufficientStorage   SMTPCode = 452
	CodeCommandUnrecognized   SMTPCode = 500
	CodeSyntaxError           SMTPCode = 501
	CodeCommandNotImplemented SMTPCode = 502
	CodeBadSequence           SMTPCode = 503
	CodeParameterNotImpl      SMTPCode = 504
	CodeMailboxNotFound       SMTPCode = 550
	CodeUserNotLocal          SMTPCode = 551
	CodeExceededStorage       SMTPCode = 552
	CodeMailboxNameInvalid    SMTPCode = 553
	CodeTransactionFailed     SMTPCode = 554
)

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
