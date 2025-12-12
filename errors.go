package raven

import "errors"

var (
	ErrServerClosed     = errors.New("smtp: server closed")
	ErrTooManyRecipents = errors.New("smtp: too many recipients")
	ErrMessageTooLarge  = errors.New("smtp: message too large")
	Err8BitIn7BitMode   = errors.New("smtp: 8-bit data in 7BIT mode")
	ErrTimeout          = errors.New("smtp: timeout")
	ErrTLSRequired      = errors.New("smtp: TLS required")
	ErrAuthRequired     = errors.New("smtp: authentication required")
	ErrInvalidCommand   = errors.New("smtp: invalid command")
	ErrLoopDetected     = errors.New("smtp: mail loop detected (too many Received headers)")
)
