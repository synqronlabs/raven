package mail

import (
	"fmt"
	"io"
	stdmime "mime"
	"mime/multipart"
	"strings"
)

var mimeSingleOccurrenceHeaders = map[string]bool{
	"content-type":              true,
	"content-transfer-encoding": true,
	"content-disposition":       true,
	"content-id":                true,
	"content-description":       true,
	"mime-version":              true,
}

// MIMEWalkPart describes a MIME entity encountered while streaming a message.
//
// Multipart entities have a nil Body and are visited before their children.
// Non-multipart entities expose their raw wire body through Body for the
// duration of the callback. WalkMIME drains any unread bytes after the callback
// returns so traversal can continue to the next sibling.
type MIMEWalkPart struct {
	Headers                 Headers
	ContentType             string
	ContentTransferEncoding ContentTransferEncoding
	Charset                 string
	Filename                string
	ContentID               string
	ContentDescription      string
	Boundary                string
	Depth                   int
	Body                    io.Reader
}

// IsMultipart reports whether this streamed MIME entity is multipart.
func (p *MIMEWalkPart) IsMultipart() bool {
	if p == nil {
		return false
	}
	return strings.HasPrefix(strings.ToLower(p.ContentType), "multipart/")
}

// MIMEWalkOptions controls bounds for streaming MIME traversal.
//
// Zero values leave the corresponding limit unbounded. MaxDepth counts MIME
// entities starting at 1 for the top-level entity. MaxParts counts every MIME
// entity encountered, including multipart containers.
type MIMEWalkOptions struct {
	MaxDepth int
	MaxParts int
}

// MIMEWalkFunc is called for each MIME entity visited by WalkMIME.
type MIMEWalkFunc func(part *MIMEWalkPart) error

type mimeWalkState struct {
	options MIMEWalkOptions
	parts   int
}

func (s *mimeWalkState) enter(depth int) error {
	if s.options.MaxDepth > 0 && depth+1 > s.options.MaxDepth {
		return fmt.Errorf("mime walk max depth exceeded: depth %d exceeds limit %d", depth+1, s.options.MaxDepth)
	}

	s.parts++
	if s.options.MaxParts > 0 && s.parts > s.options.MaxParts {
		return fmt.Errorf("mime walk max part count exceeded: part %d exceeds limit %d", s.parts, s.options.MaxParts)
	}

	return nil
}

// ValidateMIMEStream validates MIME structure from a streaming message body.
//
// Callers should validate top-level RFC 5322 message headers separately via
// Headers.Validate(). This function validates MIME-part header syntax, rejects
// malformed multipart containers, and drains the supplied body reader.
func ValidateMIMEStream(headers Headers, body io.Reader, options MIMEWalkOptions) error {
	return WalkMIME(headers, body, options, nil)
}

// WalkMIME walks a MIME body without building a full MIMEPart tree in memory.
//
// The supplied headers are the headers for the current entity, typically the
// top-level message headers. Missing Content-Type defaults to text/plain;
// charset=us-ascii. Multipart entities are visited depth-first in preorder.
func WalkMIME(headers Headers, body io.Reader, options MIMEWalkOptions, visit MIMEWalkFunc) error {
	if body == nil {
		body = strings.NewReader("")
	}
	state := &mimeWalkState{options: options}
	return walkMIME(headers, body, 0, visit, state)
}

func walkMIME(headers Headers, body io.Reader, depth int, visit MIMEWalkFunc, state *mimeWalkState) error {
	if err := state.enter(depth); err != nil {
		return err
	}

	part, err := newMIMEWalkPart(headers, depth)
	if err != nil {
		return err
	}

	if !part.IsMultipart() {
		part.Body = body
	}

	if visit != nil {
		if err := visit(part); err != nil {
			return err
		}
	}

	if part.IsMultipart() {
		reader := multipart.NewReader(body, part.Boundary)
		partCount := 0
		for {
			child, err := reader.NextRawPart()
			if err != nil {
				if err == io.EOF {
					break
				}
				return fmt.Errorf("reading multipart section for %q: %w", part.ContentType, err)
			}

			partCount++
			childHeaders := headersFromMIMEHeader(child.Header)
			if err := walkMIME(childHeaders, child, depth+1, visit, state); err != nil {
				return fmt.Errorf("walking multipart section %d for %q: %w", partCount, part.ContentType, err)
			}
		}

		if partCount == 0 {
			return fmt.Errorf("multipart message contains no parts")
		}
		return nil
	}

	if _, err := io.Copy(io.Discard, body); err != nil {
		return fmt.Errorf("draining MIME body for %q: %w", part.ContentType, err)
	}
	return nil
}

func newMIMEWalkPart(headers Headers, depth int) (*MIMEWalkPart, error) {
	if err := validateMIMEPartHeaders(headers); err != nil {
		return nil, err
	}

	part := &MIMEWalkPart{
		Headers:                 headers,
		ContentTransferEncoding: parseTransferEncoding(headers.Get("Content-Transfer-Encoding")),
		ContentDescription:      headers.Get("Content-Description"),
		Depth:                   depth,
	}
	if contentID := headers.Get("Content-ID"); contentID != "" {
		part.ContentID = strings.Trim(contentID, "<>")
	}
	if filename := filenameFromHeaders(&headers); filename != "" {
		part.Filename = filename
	}

	contentType := headers.Get("Content-Type")
	if contentType == "" {
		part.ContentType = "text/plain"
		part.Charset = "us-ascii"
		return part, nil
	}

	mediaType, params, err := stdmime.ParseMediaType(contentType)
	if err != nil || !strings.Contains(mediaType, "/") {
		return nil, fmt.Errorf("%w: Content-Type: invalid media type %q", ErrInvalidHeaderValue, contentType)
	}

	part.ContentType = mediaType
	part.Charset = params["charset"]
	part.Boundary = params["boundary"]
	if !part.IsMultipart() {
		return part, nil
	}

	if part.Boundary == "" {
		return nil, fmt.Errorf("multipart Content-Type missing boundary parameter")
	}
	if err := validateMultipartTransferEncoding(part.ContentTransferEncoding); err != nil {
		return nil, err
	}

	return part, nil
}

func validateMIMEPartHeaders(headers Headers) error {
	if err := validateHeaderBlock(headers); err != nil {
		return err
	}

	counts := make(map[string]int, len(headers))
	for _, hdr := range headers {
		canonicalName := strings.ToLower(hdr.Name)
		counts[canonicalName]++
		if mimeSingleOccurrenceHeaders[canonicalName] && counts[canonicalName] > 1 {
			return fmt.Errorf("%w: %s", ErrDuplicateSingleHeader, hdr.Name)
		}

		switch canonicalName {
		case "content-type", "content-disposition":
			if _, _, err := stdmime.ParseMediaType(hdr.Value); err != nil {
				return fmt.Errorf("%w: %s: %w", ErrInvalidHeaderValue, hdr.Name, err)
			}
		}
	}

	return nil
}

func validateMultipartTransferEncoding(encoding ContentTransferEncoding) error {
	switch encoding {
	case "", Encoding7Bit, Encoding8Bit, EncodingBinary:
		return nil
	default:
		return fmt.Errorf("%w: Content-Transfer-Encoding: multipart entities must not use %q", ErrInvalidHeaderValue, encoding)
	}
}
