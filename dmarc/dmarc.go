package dmarc

import (
	"errors"
)

// DMARC lookup and verification errors.
var (
	// ErrNoRecord indicates no DMARC DNS record was found.
	ErrNoRecord = errors.New("dmarc: no DMARC DNS record found")

	// ErrMultipleRecords indicates multiple DMARC DNS records were found.
	// Per RFC 7489, this must be treated as if the domain does not implement DMARC.
	ErrMultipleRecords = errors.New("dmarc: multiple DMARC DNS records found")

	// ErrSyntax indicates the DMARC record has invalid syntax.
	ErrSyntax = errors.New("dmarc: malformed DMARC DNS record")

	// ErrDNS indicates a DNS lookup error occurred.
	ErrDNS = errors.New("dmarc: DNS lookup error")

	// ErrNoFromHeader indicates the message has no From header.
	ErrNoFromHeader = errors.New("dmarc: no From header in message")

	// ErrInvalidFromHeader indicates the From header could not be parsed.
	ErrInvalidFromHeader = errors.New("dmarc: invalid From header")

	// ErrMultipleFromAddresses indicates multiple addresses in From header.
	// DMARC can only evaluate a single From domain.
	ErrMultipleFromAddresses = errors.New("dmarc: multiple addresses in From header")
)

// Status is the result of DMARC policy evaluation, for use in an
// Authentication-Results header per RFC 8601.
type Status string

const (
	// StatusNone indicates no DMARC TXT DNS record was found.
	StatusNone Status = "none"

	// StatusPass indicates SPF and/or DKIM passed with identifier alignment.
	StatusPass Status = "pass"

	// StatusFail indicates either both SPF and DKIM failed or the identifier
	// did not align with a pass.
	StatusFail Status = "fail"

	// StatusTemperror indicates a temporary error, typically a DNS lookup failure.
	// A later attempt may result in a conclusion.
	StatusTemperror Status = "temperror"

	// StatusPermerror indicates a permanent error, typically a malformed DMARC
	// DNS record.
	StatusPermerror Status = "permerror"
)

// Policy determines how receivers should handle messages that fail DMARC.
type Policy string

const (
	// PolicyEmpty is only for the optional SubdomainPolicy field.
	PolicyEmpty Policy = ""

	// PolicyNone requests no specific action be taken for failing messages.
	// This is typically used for monitoring/reporting during initial deployment.
	PolicyNone Policy = "none"

	// PolicyQuarantine requests that failing messages be treated as suspicious.
	// Receivers may deliver to spam folder or add additional scrutiny.
	PolicyQuarantine Policy = "quarantine"

	// PolicyReject requests that failing messages be rejected.
	PolicyReject Policy = "reject"
)

// Align specifies the alignment mode for identifier comparison.
type Align string

const (
	// AlignRelaxed requires the organizational domains to match.
	// This is the default mode.
	AlignRelaxed Align = "r"

	// AlignStrict requires exact domain matches.
	AlignStrict Align = "s"
)

// Result is the result of DMARC policy evaluation.
type Result struct {
	// Reject indicates whether the message should be rejected based on the
	// published policy. Note: Even if false, the message should not necessarily
	// be accepted - other checks like reputation and content analysis may still
	// lead to rejection.
	Reject bool

	// Status is the result of DMARC validation. A message can fail validation
	// but still not be rejected, e.g., if the policy is "none".
	Status Status

	// AlignedSPFPass indicates SPF passed with proper alignment.
	AlignedSPFPass bool

	// AlignedDKIMPass indicates at least one DKIM signature passed with
	// proper alignment.
	AlignedDKIMPass bool

	// Domain is the domain where the DMARC DNS record was found.
	// This may be the organizational domain rather than the From header domain.
	Domain string

	// Record is the parsed DMARC record, or nil if not found or invalid.
	Record *Record

	// RecordAuthentic indicates if the DMARC DNS response was DNSSEC-signed.
	RecordAuthentic bool

	// Err contains details about any error condition, such as parsing failures.
	Err error
}
