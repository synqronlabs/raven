package mime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"strings"
)

// ContentTransferEncoding represents the encoding used for the MIME part's body.
type ContentTransferEncoding string

const (
	// Encoding7Bit is for 7-bit ASCII data (RFC 2045 default).
	Encoding7Bit ContentTransferEncoding = "7bit"
	// Encoding8Bit is for 8-bit data (requires 8BITMIME).
	Encoding8Bit ContentTransferEncoding = "8bit"
	// EncodingBinary is for binary data (requires BINARYMIME/CHUNKING).
	EncodingBinary ContentTransferEncoding = "binary"
	// EncodingQuotedPrintable is for quoted-printable encoding.
	EncodingQuotedPrintable ContentTransferEncoding = "quoted-printable"
	// EncodingBase64 is for base64 encoding.
	EncodingBase64 ContentTransferEncoding = "base64"
)

// ValidCompositeEncodings lists valid encodings for composite types (RFC 2045).
var ValidCompositeEncodings = map[ContentTransferEncoding]bool{
	Encoding7Bit:   true,
	Encoding8Bit:   true,
	EncodingBinary: true,
}

// ErrInvalidCompositeEncoding is returned for invalid composite type encodings (RFC 2045).
var ErrInvalidCompositeEncoding = errors.New("composite types (multipart, message) can only use 7bit, 8bit, or binary encoding")

// IsCompositeType returns true if the media type is a composite type (multipart or message).
func IsCompositeType(mediaType string) bool {
	return strings.HasPrefix(mediaType, "multipart/") || strings.HasPrefix(mediaType, "message/")
}

// ValidateCompositeEncoding validates composite type encodings (RFC 2045).
func ValidateCompositeEncoding(mediaType string, encoding ContentTransferEncoding) error {
	if !IsCompositeType(mediaType) {
		return nil // Non-composite types can use any encoding
	}
	if encoding == "" {
		return nil // Will default to 7bit
	}
	if !ValidCompositeEncodings[encoding] {
		return ErrInvalidCompositeEncoding
	}
	return nil
}

// Header represents a MIME header field.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Part represents a MIME body part (RFC 2045, RFC 2046).
type Part struct {
	Headers                 []Header                `json:"headers,omitempty"`
	ContentType             string                  `json:"content_type,omitempty"`
	ContentTransferEncoding ContentTransferEncoding `json:"content_transfer_encoding,omitempty"`
	Charset                 string                  `json:"charset,omitempty"`
	Filename                string                  `json:"filename,omitempty"`
	ContentID               string                  `json:"content_id,omitempty"`
	ContentDescription      string                  `json:"content_description,omitempty"`
	Body                    []byte                  `json:"body,omitempty"`
	Parts                   []*Part                 `json:"parts,omitempty"`
}

// HeaderGetter is an interface for types that can retrieve header values.
type HeaderGetter interface {
	Get(name string) string
}

// ParseSinglePart handles non-multipart MIME messages.
func ParseSinglePart(headers HeaderGetter, body []byte, mediaType string, params map[string]string) (*Part, error) {
	part := &Part{
		ContentType:             mediaType,
		ContentTransferEncoding: Encoding7Bit,
		Body:                    body,
	}

	if charset, ok := params["charset"]; ok {
		part.Charset = charset
	}

	cte := headers.Get("Content-Transfer-Encoding")
	if cte != "" {
		part.ContentTransferEncoding = ContentTransferEncoding(strings.ToLower(cte))
	}

	contentID := headers.Get("Content-ID")
	if contentID != "" {
		part.ContentID = strings.Trim(contentID, "<>")
	}

	contentDesc := headers.Get("Content-Description")
	if contentDesc != "" {
		part.ContentDescription = contentDesc
	}

	// Check for Content-Disposition (for attachments)
	contentDisp := headers.Get("Content-Disposition")
	if contentDisp != "" {
		_, dispParams, err := mime.ParseMediaType(contentDisp)
		if err == nil {
			if filename, ok := dispParams["filename"]; ok {
				part.Filename = filename
			}
		}
	}

	return part, nil
}

// ParseMultipart handles multipart MIME messages.
func ParseMultipart(body []byte, mediaType string, params map[string]string) (*Part, error) {
	boundary, ok := params["boundary"]
	if !ok || boundary == "" {
		return nil, errors.New("multipart Content-Type missing boundary parameter")
	}

	rootPart := &Part{
		ContentType:             mediaType,
		ContentTransferEncoding: Encoding7Bit,
		Parts:                   make([]*Part, 0, 4), // Pre-allocate for common case
	}

	reader := multipart.NewReader(bytes.NewReader(body), boundary)

	for {
		part, err := reader.NextPart()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("error reading multipart section: %w", err)
		}

		mimePart, err := ParseMultipartSection(part)
		if err != nil {
			return nil, fmt.Errorf("error parsing multipart section: %w", err)
		}

		rootPart.Parts = append(rootPart.Parts, mimePart)
	}

	if len(rootPart.Parts) == 0 {
		return nil, errors.New("multipart message contains no parts")
	}

	return rootPart, nil
}

// ParseMultipartSection parses a single part of a multipart message.
func ParseMultipartSection(part *multipart.Part) (*Part, error) {
	// Pre-allocate headers slice based on header count for efficiency
	headerCount := 0
	for _, values := range part.Header {
		headerCount += len(values)
	}

	mimePart := &Part{
		Headers:                 make([]Header, 0, headerCount),
		ContentTransferEncoding: Encoding7Bit,
	}

	// Convert textproto.MIMEHeader to our Headers type
	for name, values := range part.Header {
		for _, value := range values {
			mimePart.Headers = append(mimePart.Headers, Header{
				Name:  name,
				Value: value,
			})
		}
	}

	contentType := part.Header.Get("Content-Type")
	if contentType == "" {
		// Default to text/plain per RFC 2045
		mimePart.ContentType = "text/plain"
		mimePart.Charset = "us-ascii"
	} else {
		mediaType, params, err := mime.ParseMediaType(contentType)
		if err != nil {
			return nil, fmt.Errorf("invalid Content-Type in part: %w", err)
		}
		mimePart.ContentType = mediaType

		if charset, ok := params["charset"]; ok {
			mimePart.Charset = charset
		}

		// Check if this part is itself multipart (nested multipart)
		if strings.HasPrefix(mediaType, "multipart/") {
			boundary, ok := params["boundary"]
			if !ok || boundary == "" {
				return nil, errors.New("nested multipart missing boundary parameter")
			}

			// Use pre-allocated buffer for better performance
			body := bytes.NewBuffer(make([]byte, 0, 4096))
			_, err := body.ReadFrom(part)
			if err != nil {
				return nil, fmt.Errorf("error reading nested multipart body: %w", err)
			}

			nestedReader := multipart.NewReader(bytes.NewReader(body.Bytes()), boundary)
			mimePart.Parts = make([]*Part, 0, 4) // Pre-allocate for common case

			for {
				nestedPart, err := nestedReader.NextPart()
				if err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					return nil, fmt.Errorf("error reading nested multipart section: %w", err)
				}

				nestedMIME, err := ParseMultipartSection(nestedPart)
				if err != nil {
					return nil, err
				}
				mimePart.Parts = append(mimePart.Parts, nestedMIME)
			}

			mimePart.Body = body.Bytes()
			return mimePart, nil
		}
	}

	cte := part.Header.Get("Content-Transfer-Encoding")
	if cte != "" {
		mimePart.ContentTransferEncoding = ContentTransferEncoding(strings.ToLower(cte))
	}

	contentID := part.Header.Get("Content-ID")
	if contentID != "" {
		mimePart.ContentID = strings.Trim(contentID, "<>")
	}

	contentDesc := part.Header.Get("Content-Description")
	if contentDesc != "" {
		mimePart.ContentDescription = contentDesc
	}

	contentDisp := part.Header.Get("Content-Disposition")
	if contentDisp != "" {
		_, dispParams, err := mime.ParseMediaType(contentDisp)
		if err == nil {
			if filename, ok := dispParams["filename"]; ok {
				mimePart.Filename = filename
			}
		}
	}

	// Use pre-allocated buffer for better performance
	body := bytes.NewBuffer(make([]byte, 0, 4096))
	_, err := body.ReadFrom(part)
	if err != nil {
		return nil, fmt.Errorf("error reading part body: %w", err)
	}
	mimePart.Body = body.Bytes()

	return mimePart, nil
}

// Parse parses MIME content from headers and body.
// It automatically detects whether the content is single-part or multipart.
// Per RFC 2045 Section 5.2, defaults to text/plain; charset=us-ascii when
// Content-Type is missing or invalid.
func Parse(headers HeaderGetter, body []byte) (*Part, error) {
	contentType := headers.Get("Content-Type")
	if contentType == "" {
		part := &Part{
			ContentType:             "text/plain",
			Charset:                 "us-ascii",
			ContentTransferEncoding: Encoding7Bit,
			Body:                    body,
		}
		// Check for Content-Description even without Content-Type
		if desc := headers.Get("Content-Description"); desc != "" {
			part.ContentDescription = desc
		}
		return part, nil
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		part := &Part{
			ContentType:             "text/plain",
			Charset:                 "us-ascii",
			ContentTransferEncoding: Encoding7Bit,
			Body:                    body,
		}
		if desc := headers.Get("Content-Description"); desc != "" {
			part.ContentDescription = desc
		}
		return part, nil
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		return ParseMultipart(body, mediaType, params)
	}

	return ParseSinglePart(headers, body, mediaType, params)
}

// ToJSON serializes the Mail object to JSON bytes.
func (p *Part) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

// ToJSONIndent serializes the Mail object to pretty-printed JSON bytes.
func (p *Part) ToJSONIndent() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// IsMultipart returns true if this part is a multipart message.
func (p *Part) IsMultipart() bool {
	return strings.HasPrefix(p.ContentType, "multipart/") && len(p.Parts) > 0
}

// ToBytes serializes the MIME part back to raw bytes.
// For multipart messages, it recursively serializes all nested parts.
func (p *Part) ToBytes() ([]byte, error) {
	if !p.IsMultipart() {
		// For non-multipart, just return the body
		return p.Body, nil
	}

	_, params, err := mime.ParseMediaType(p.ContentType)
	if err != nil {
		return nil, fmt.Errorf("invalid Content-Type: %w", err)
	}
	boundary, ok := params["boundary"]
	if !ok || boundary == "" {
		return nil, errors.New("multipart Content-Type missing boundary parameter")
	}

	// Estimate buffer size for better performance
	estimatedSize := len(p.Body)
	for _, part := range p.Parts {
		estimatedSize += len(part.Body) + 256 // 256 for headers overhead
	}
	buf := bytes.NewBuffer(make([]byte, 0, estimatedSize))

	for _, part := range p.Parts {
		buf.WriteString("--")
		buf.WriteString(boundary)
		buf.WriteString("\r\n")

		if err := writePartHeaders(buf, part); err != nil {
			return nil, err
		}

		buf.WriteString("\r\n")

		// Write part body (recursively for nested multipart)
		partBody, err := part.ToBytes()
		if err != nil {
			return nil, err
		}
		buf.Write(partBody)
		buf.WriteString("\r\n")
	}

	buf.WriteString("--")
	buf.WriteString(boundary)
	buf.WriteString("--\r\n")

	return buf.Bytes(), nil
}

// writePartHeaders writes the headers for a MIME part.
func writePartHeaders(buf *bytes.Buffer, part *Part) error {
	if len(part.Headers) > 0 {
		for _, h := range part.Headers {
			buf.WriteString(h.Name)
			buf.WriteString(": ")
			buf.WriteString(h.Value)
			buf.WriteString("\r\n")
		}
		return nil
	}

	if part.ContentType != "" {
		buf.WriteString("Content-Type: ")
		buf.WriteString(part.ContentType)
		if part.Charset != "" && strings.HasPrefix(part.ContentType, "text/") {
			buf.WriteString("; charset=\"")
			buf.WriteString(part.Charset)
			buf.WriteString("\"")
		}
		// For multipart, we need to include the boundary
		if strings.HasPrefix(part.ContentType, "multipart/") {
			_, params, err := mime.ParseMediaType(part.ContentType)
			if err == nil {
				if boundary, ok := params["boundary"]; ok {
					buf.WriteString("; boundary=\"")
					buf.WriteString(boundary)
					buf.WriteString("\"")
				}
			}
		}
		if part.Filename != "" {
			buf.WriteString("; name=\"")
			buf.WriteString(part.Filename)
			buf.WriteString("\"")
		}
		buf.WriteString("\r\n")
	}

	if part.Filename != "" {
		buf.WriteString("Content-Disposition: attachment; filename=\"")
		buf.WriteString(part.Filename)
		buf.WriteString("\"\r\n")
	}

	if part.ContentTransferEncoding != "" {
		buf.WriteString("Content-Transfer-Encoding: ")
		buf.WriteString(string(part.ContentTransferEncoding))
		buf.WriteString("\r\n")
	}

	if part.ContentID != "" {
		buf.WriteString("Content-ID: <")
		buf.WriteString(part.ContentID)
		buf.WriteString(">\r\n")
	}

	if part.ContentDescription != "" {
		buf.WriteString("Content-Description: ")
		buf.WriteString(part.ContentDescription)
		buf.WriteString("\r\n")
	}

	return nil
}
