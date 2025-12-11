package mime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"strings"
)

// ContentTransferEncoding represents the encoding used for the MIME part's body.
type ContentTransferEncoding string

const (
	// Encoding7Bit is for 7-bit ASCII data.
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

// Header represents a MIME header field.
type Header struct {
	// Name is the header field name (e.g., "From", "Subject").
	Name string `json:"name"`
	// Value is the header field value.
	Value string `json:"value"`
}

// Part represents a MIME body part for multipart messages (RFC 2045, RFC 2046).
type Part struct {
	// Headers contains the MIME headers for this part.
	Headers []Header `json:"headers,omitempty"`

	// ContentType is the MIME content type (e.g., "text/plain", "image/png").
	ContentType string `json:"content_type,omitempty"`

	// ContentTransferEncoding specifies how the body is encoded.
	ContentTransferEncoding ContentTransferEncoding `json:"content_transfer_encoding,omitempty"`

	// Charset is the character set for text parts (e.g., "utf-8", "iso-8859-1").
	Charset string `json:"charset,omitempty"`

	// Filename is the suggested filename for attachment parts.
	Filename string `json:"filename,omitempty"`

	// ContentID is the Content-ID for inline parts (used in multipart/related).
	ContentID string `json:"content_id,omitempty"`

	// Body is the decoded content of this part.
	Body []byte `json:"body,omitempty"`

	// Parts contains nested parts for multipart content types.
	Parts []*Part `json:"parts,omitempty"`
}

// HeaderGetter is an interface for types that can retrieve header values.
type HeaderGetter interface {
	Get(name string) string
}

// ParseSinglePart handles non-multipart MIME messages.
func ParseSinglePart(headers HeaderGetter, body []byte, mediaType string, params map[string]string) (*Part, error) {
	part := &Part{
		ContentType: mediaType,
		Body:        body,
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
		ContentType: mediaType,
		Parts:       make([]*Part, 0),
	}

	reader := multipart.NewReader(bytes.NewReader(body), boundary)

	for {
		part, err := reader.NextPart()
		if err != nil {
			if err.Error() == "EOF" {
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
	mimePart := &Part{
		Headers: make([]Header, 0),
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

			body := new(bytes.Buffer)
			_, err := body.ReadFrom(part)
			if err != nil {
				return nil, fmt.Errorf("error reading nested multipart body: %w", err)
			}

			// Parse nested multipart
			nestedReader := multipart.NewReader(bytes.NewReader(body.Bytes()), boundary)
			mimePart.Parts = make([]*Part, 0)

			for {
				nestedPart, err := nestedReader.NextPart()
				if err != nil {
					if err.Error() == "EOF" {
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

	contentDisp := part.Header.Get("Content-Disposition")
	if contentDisp != "" {
		_, dispParams, err := mime.ParseMediaType(contentDisp)
		if err == nil {
			if filename, ok := dispParams["filename"]; ok {
				mimePart.Filename = filename
			}
		}
	}

	body := new(bytes.Buffer)
	_, err := body.ReadFrom(part)
	if err != nil {
		return nil, fmt.Errorf("error reading part body: %w", err)
	}
	mimePart.Body = body.Bytes()

	return mimePart, nil
}

// Parse parses MIME content from headers and body.
// It automatically detects whether the content is single-part or multipart.
func Parse(headers HeaderGetter, body []byte) (*Part, error) {
	contentType := headers.Get("Content-Type")
	if contentType == "" {
		// No Content-Type header - treat as text/plain (RFC 2045 default)
		return &Part{
			ContentType: "text/plain",
			Charset:     "us-ascii",
			Body:        body,
		}, nil
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("invalid Content-Type header: %w", err)
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

	var buf bytes.Buffer

	_, params, err := mime.ParseMediaType(p.ContentType)
	if err != nil {
		return nil, fmt.Errorf("invalid Content-Type: %w", err)
	}
	boundary, ok := params["boundary"]
	if !ok || boundary == "" {
		return nil, errors.New("multipart Content-Type missing boundary parameter")
	}

	for _, part := range p.Parts {
		// Write boundary delimiter
		buf.WriteString("--")
		buf.WriteString(boundary)
		buf.WriteString("\r\n")

		// Write part headers
		if err := writePartHeaders(&buf, part); err != nil {
			return nil, err
		}

		// Write blank line between headers and body
		buf.WriteString("\r\n")

		// Write part body (recursively for nested multipart)
		partBody, err := part.ToBytes()
		if err != nil {
			return nil, err
		}
		buf.Write(partBody)
		buf.WriteString("\r\n")
	}

	// Write closing boundary
	buf.WriteString("--")
	buf.WriteString(boundary)
	buf.WriteString("--\r\n")

	return buf.Bytes(), nil
}

// writePartHeaders writes the headers for a MIME part.
func writePartHeaders(buf *bytes.Buffer, part *Part) error {
	// If the part has explicit headers, use them
	if len(part.Headers) > 0 {
		for _, h := range part.Headers {
			buf.WriteString(h.Name)
			buf.WriteString(": ")
			buf.WriteString(h.Value)
			buf.WriteString("\r\n")
		}
		return nil
	}

	// Otherwise, reconstruct headers from part properties
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

	return nil
}
