package server

import (
	"fmt"
	stdmail "net/mail"
	"strings"
	"time"

	ravenmail "github.com/synqronlabs/raven/mail"
)

// HeaderFixupOptions configures opt-in repair of RFC 5322 header violations in
// messages received by the server. It is intended for submission services
// (RFC 6409) that must accept mail from clients which do not produce strictly
// compliant headers.
//
// Every field is disabled by default, so the zero value leaves the header block
// untouched. Use AllHeaderFixups to enable every repair.
//
// Fixups rewrite the header block by parsing and re-serializing it, so the
// bytes delivered to Session.Data can differ from the bytes sent on the wire
// (for example, folded headers are refolded). Repairs that reorder or modify
// headers invalidate any pre-existing DKIM or ARC signatures covering those
// headers, which is why this behavior is not enabled by default.
type HeaderFixupOptions struct {
	// AddMessageID generates a unique Message-ID header when the message does
	// not already contain one.
	AddMessageID bool

	// AddDate inserts a Date header when the message does not already contain
	// one.
	AddDate bool

	// AddSender inserts a Sender header when From contains more than one
	// mailbox and no Sender is present. The first From mailbox is used.
	AddSender bool

	// NormalizeReturnPath rewrites a Return-Path value that is not enclosed in
	// angle brackets into a valid path. For example, "user@example.com"
	// becomes "<user@example.com>". Values that already begin with "<" and
	// empty values are left untouched.
	NormalizeReturnPath bool

	// DropEmptyAddressHeaders removes To, Cc, Bcc, and Reply-To headers whose
	// value is empty. RFC 5322 permits these fields to be absent, but an empty
	// address list is invalid.
	DropEmptyAddressHeaders bool

	// RemoveDuplicateSingleHeaders keeps the first occurrence of headers that
	// may appear at most once (Date, From, Sender, Reply-To, To, Cc, Bcc,
	// Message-ID, In-Reply-To, References, Return-Path, and Subject) and drops
	// later duplicates.
	RemoveDuplicateSingleHeaders bool

	// ReorderTraceHeaders moves Return-Path, Received, and Resent-* fields
	// ahead of regular headers so trace fields precede Resent-* blocks, which
	// in turn precede regular fields. Return-Path is placed before Received.
	ReorderTraceHeaders bool

	// MessageIDDomain overrides the domain used when generating a Message-ID.
	// When empty, the server Domain is used.
	MessageIDDomain string
}

// AllHeaderFixups returns HeaderFixupOptions with every repair enabled.
func AllHeaderFixups() HeaderFixupOptions {
	return HeaderFixupOptions{
		AddMessageID:                 true,
		AddDate:                      true,
		AddSender:                    true,
		NormalizeReturnPath:          true,
		DropEmptyAddressHeaders:      true,
		RemoveDuplicateSingleHeaders: true,
		ReorderTraceHeaders:          true,
	}
}

func (o HeaderFixupOptions) enabled() bool {
	return o.AddMessageID ||
		o.AddDate ||
		o.AddSender ||
		o.NormalizeReturnPath ||
		o.DropEmptyAddressHeaders ||
		o.RemoveDuplicateSingleHeaders ||
		o.ReorderTraceHeaders
}

// singleOccurrenceHeaderNames lists headers that must appear at most once
// (RFC 5322 section 3.6).
var singleOccurrenceHeaderNames = map[string]struct{}{
	"date":        {},
	"from":        {},
	"sender":      {},
	"reply-to":    {},
	"to":          {},
	"cc":          {},
	"bcc":         {},
	"message-id":  {},
	"in-reply-to": {},
	"references":  {},
	"return-path": {},
	"subject":     {},
}

// fixupHeaders applies the configured header repairs to a raw inbound header
// block. When no repair is enabled the original slice is returned unchanged.
func (s *Server) fixupHeaders(headers MessageHeaders) MessageHeaders {
	opts := s.config.HeaderFixups
	if !opts.enabled() || len(headers) == 0 {
		return headers
	}

	parsed := ravenmail.ParseHeaders(headers)
	if len(parsed) == 0 {
		return headers
	}

	if opts.DropEmptyAddressHeaders {
		parsed = dropEmptyAddressHeaders(parsed)
	}
	if opts.RemoveDuplicateSingleHeaders {
		parsed = dedupeSingleOccurrenceHeaders(parsed)
	}
	if opts.AddSender {
		parsed = addSenderIfNeeded(parsed)
	}
	if opts.NormalizeReturnPath {
		parsed = normalizeReturnPaths(parsed)
	}
	if opts.AddDate && !hasHeader(parsed, "date") {
		parsed = append(parsed, ravenmail.Header{
			Name:  "Date",
			Value: time.Now().Format(time.RFC1123Z),
		})
	}
	if opts.AddMessageID && !hasHeader(parsed, "message-id") {
		parsed = append(parsed, ravenmail.Header{
			Name:  "Message-ID",
			Value: s.generateMessageID(),
		})
	}
	if opts.ReorderTraceHeaders {
		parsed = reorderTraceHeaders(parsed)
	}

	return MessageHeaders(parsed.ToRaw())
}

// hasHeader reports whether headers contains name (case-insensitive).
func hasHeader(headers ravenmail.Headers, name string) bool {
	for _, hdr := range headers {
		if strings.EqualFold(hdr.Name, name) {
			return true
		}
	}
	return false
}

// emptyDroppableAddressHeaders lists optional address-list headers that may be
// removed when they carry no value.
var emptyDroppableAddressHeaders = map[string]struct{}{
	"to":       {},
	"cc":       {},
	"bcc":      {},
	"reply-to": {},
}

// dropEmptyAddressHeaders removes optional address headers whose value is
// empty, preserving the order of all remaining headers.
func dropEmptyAddressHeaders(headers ravenmail.Headers) ravenmail.Headers {
	out := headers[:0]
	for _, hdr := range headers {
		name := strings.ToLower(strings.TrimSpace(hdr.Name))
		if _, droppable := emptyDroppableAddressHeaders[name]; droppable && strings.TrimSpace(hdr.Value) == "" {
			continue
		}
		out = append(out, hdr)
	}
	return out
}

// normalizeReturnPaths rewrites each Return-Path value that is not enclosed in
// angle brackets. A single mailbox with a display name is reduced to its
// addr-spec.
func normalizeReturnPaths(headers ravenmail.Headers) ravenmail.Headers {
	for i := range headers {
		if !strings.EqualFold(strings.TrimSpace(headers[i].Name), "return-path") {
			continue
		}
		headers[i].Value = normalizeReturnPath(headers[i].Value)
	}
	return headers
}

// normalizeReturnPath returns a bracketed path for value. Empty values and
// values already beginning with "<" are returned unchanged.
func normalizeReturnPath(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.HasPrefix(trimmed, "<") {
		return value
	}

	if parsed, err := stdmail.ParseAddressList(trimmed); err == nil && len(parsed) == 1 {
		return "<" + parsed[0].Address + ">"
	}

	return "<" + trimmed + ">"
}

// dedupeSingleOccurrenceHeaders drops later duplicates of single-occurrence
// headers, preserving the first occurrence in the original order.
func dedupeSingleOccurrenceHeaders(headers ravenmail.Headers) ravenmail.Headers {
	seen := make(map[string]struct{}, len(headers))
	out := headers[:0]
	for _, hdr := range headers {
		name := strings.ToLower(strings.TrimSpace(hdr.Name))
		if _, single := singleOccurrenceHeaderNames[name]; single {
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
		}
		out = append(out, hdr)
	}
	return out
}

// addSenderIfNeeded appends a Sender header when From has multiple mailboxes
// and no Sender is present.
func addSenderIfNeeded(headers ravenmail.Headers) ravenmail.Headers {
	var from string
	for _, hdr := range headers {
		switch strings.ToLower(strings.TrimSpace(hdr.Name)) {
		case "from":
			if from == "" {
				from = hdr.Value
			}
		case "sender":
			return headers
		}
	}
	if from == "" {
		return headers
	}

	parsed, err := stdmail.ParseAddressList(from)
	if err != nil || len(parsed) < 2 {
		return headers
	}

	return append(headers, ravenmail.Header{Name: "Sender", Value: parsed[0].Address})
}

// reorderTraceHeaders moves Return-Path, Received, and Resent-* fields ahead of
// regular headers, preserving their relative order.
func reorderTraceHeaders(headers ravenmail.Headers) ravenmail.Headers {
	var returnPaths, received, resent, regular ravenmail.Headers
	for _, hdr := range headers {
		name := strings.ToLower(strings.TrimSpace(hdr.Name))
		switch {
		case name == "return-path":
			returnPaths = append(returnPaths, hdr)
		case name == "received":
			received = append(received, hdr)
		case strings.HasPrefix(name, "resent-"):
			resent = append(resent, hdr)
		default:
			regular = append(regular, hdr)
		}
	}

	if len(returnPaths) == 0 && len(received) == 0 && len(resent) == 0 {
		return headers
	}

	out := make(ravenmail.Headers, 0, len(headers))
	out = append(out, returnPaths...)
	out = append(out, received...)
	out = append(out, resent...)
	out = append(out, regular...)
	return out
}

// generateMessageID builds a unique Message-ID using the configured fixup
// domain, the server domain, or localhost as a final fallback.
func (s *Server) generateMessageID() string {
	domain := s.config.HeaderFixups.MessageIDDomain
	if domain == "" {
		domain = s.config.Domain
	}
	if domain == "" {
		domain = "localhost"
	}

	return fmt.Sprintf("<%d.%s@%s>", time.Now().UnixNano(), generateQueueID(), domain)
}
