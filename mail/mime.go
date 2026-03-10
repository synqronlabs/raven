package mail

import (
	"bytes"
	"fmt"
	"io"
	stdmime "mime"
	"mime/multipart"
	"net/textproto"
	"strings"
)

type headerGetter interface {
	Get(name string) string
}

// MIMEPart represents a MIME entity parsed from Content, including multipart
// children and the raw wire body bytes for each part.
type MIMEPart struct {
	Headers                 Headers                 `json:"headers,omitempty"`
	ContentType             string                  `json:"content_type,omitempty"`
	ContentTransferEncoding ContentTransferEncoding `json:"content_transfer_encoding,omitempty"`
	Charset                 string                  `json:"charset,omitempty"`
	Filename                string                  `json:"filename,omitempty"`
	ContentID               string                  `json:"content_id,omitempty"`
	ContentDescription      string                  `json:"content_description,omitempty"`
	Body                    []byte                  `json:"body,omitempty"`
	Parts                   []*MIMEPart             `json:"parts,omitempty"`

	boundary string
}

// IsMultipart returns true if the part is multipart and has child parts.
func (p *MIMEPart) IsMultipart() bool {
	if p == nil {
		return false
	}
	return strings.HasPrefix(strings.ToLower(p.ContentType), "multipart/") && len(p.Parts) > 0
}

// ToBytes serializes a MIME part tree back to raw body bytes.
func (p *MIMEPart) ToBytes() ([]byte, error) {
	if p == nil {
		return nil, nil
	}
	if !p.IsMultipart() {
		return p.Body, nil
	}

	boundary, err := p.multipartBoundary()
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(make([]byte, 0, len(p.Body)+len(p.Parts)*256))
	writer := multipart.NewWriter(buf)
	if err := writer.SetBoundary(boundary); err != nil {
		return nil, fmt.Errorf("setting multipart boundary %q: %w", boundary, err)
	}

	for _, part := range p.Parts {
		headers, err := part.mimeHeader()
		if err != nil {
			return nil, fmt.Errorf("building headers for multipart section %q: %w", part.ContentType, err)
		}
		sectionWriter, err := writer.CreatePart(headers)
		if err != nil {
			return nil, fmt.Errorf("creating multipart section %q: %w", part.ContentType, err)
		}
		partBody, err := part.ToBytes()
		if err != nil {
			return nil, fmt.Errorf("serializing multipart section %q: %w", part.ContentType, err)
		}
		if _, err := sectionWriter.Write(partBody); err != nil {
			return nil, fmt.Errorf("writing multipart section %q: %w", part.ContentType, err)
		}
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("closing multipart writer for %q: %w", p.ContentType, err)
	}

	return buf.Bytes(), nil
}

func parseMIME(headers headerGetter, body []byte) (*MIMEPart, error) {
	contentType := headers.Get("Content-Type")
	if contentType == "" {
		return fallbackMIMEPart(headers, body), nil
	}

	mediaType, params, err := stdmime.ParseMediaType(contentType)
	if err != nil || !strings.Contains(mediaType, "/") {
		return fallbackMIMEPart(headers, body), nil
	}

	cte := parseTransferEncoding(headers.Get("Content-Transfer-Encoding"))
	if strings.HasPrefix(strings.ToLower(mediaType), "multipart/") {
		part, err := parseMultipartBody(body, mediaType, params)
		if err != nil {
			return nil, fmt.Errorf("parsing multipart body for media type %q: %w", mediaType, err)
		}
		part.ContentTransferEncoding = cte
		return part, nil
	}

	part := &MIMEPart{
		ContentType:             mediaType,
		ContentTransferEncoding: cte,
		Body:                    body,
	}
	if charset, ok := params["charset"]; ok {
		part.Charset = charset
	}
	if desc := headers.Get("Content-Description"); desc != "" {
		part.ContentDescription = desc
	}
	if contentID := headers.Get("Content-ID"); contentID != "" {
		part.ContentID = strings.Trim(contentID, "<>")
	}
	if filename := filenameFromHeaders(headers); filename != "" {
		part.Filename = filename
	}
	return part, nil
}

func fallbackMIMEPart(headers headerGetter, body []byte) *MIMEPart {
	part := &MIMEPart{
		ContentType:             "text/plain",
		Charset:                 "us-ascii",
		ContentTransferEncoding: parseTransferEncoding(headers.Get("Content-Transfer-Encoding")),
		Body:                    body,
	}
	if desc := headers.Get("Content-Description"); desc != "" {
		part.ContentDescription = desc
	}
	if contentID := headers.Get("Content-ID"); contentID != "" {
		part.ContentID = strings.Trim(contentID, "<>")
	}
	if filename := filenameFromHeaders(headers); filename != "" {
		part.Filename = filename
	}
	return part
}

func parseMultipartBody(body []byte, mediaType string, params map[string]string) (*MIMEPart, error) {
	boundary := params["boundary"]
	if boundary == "" {
		return nil, fmt.Errorf("multipart Content-Type missing boundary parameter")
	}

	root := &MIMEPart{
		ContentType: mediaType,
		Body:        body,
		Parts:       make([]*MIMEPart, 0, 4),
		boundary:    boundary,
	}

	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		part, err := reader.NextRawPart()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("reading multipart section: %w", err)
		}

		child, err := parseMultipartSection(part)
		if err != nil {
			return nil, fmt.Errorf("parsing multipart section: %w", err)
		}
		root.Parts = append(root.Parts, child)
	}

	if len(root.Parts) == 0 {
		return nil, fmt.Errorf("multipart message contains no parts")
	}

	return root, nil
}

func parseMultipartSection(part *multipart.Part) (*MIMEPart, error) {
	headers := headersFromMIMEHeader(part.Header)
	contentType := part.Header.Get("Content-Type")
	cte := parseTransferEncoding(part.Header.Get("Content-Transfer-Encoding"))

	if contentType == "" {
		body, err := io.ReadAll(part)
		if err != nil {
			return nil, fmt.Errorf("reading part body: %w", err)
		}
		return &MIMEPart{
			Headers:                 headers,
			ContentType:             "text/plain",
			Charset:                 "us-ascii",
			ContentTransferEncoding: cte,
			ContentID:               strings.Trim(part.Header.Get("Content-ID"), "<>"),
			ContentDescription:      part.Header.Get("Content-Description"),
			Filename:                filenameFromMIMEHeader(part.Header),
			Body:                    body,
		}, nil
	}

	mediaType, params, err := stdmime.ParseMediaType(contentType)
	if err != nil || !strings.Contains(mediaType, "/") {
		return nil, fmt.Errorf("invalid Content-Type in part: %q", contentType)
	}

	if strings.HasPrefix(strings.ToLower(mediaType), "multipart/") {
		body, err := io.ReadAll(part)
		if err != nil {
			return nil, fmt.Errorf("reading nested multipart body: %w", err)
		}
		nested, err := parseMultipartBody(body, mediaType, params)
		if err != nil {
			return nil, fmt.Errorf("parsing nested multipart %q: %w", mediaType, err)
		}
		nested.Headers = headers
		nested.ContentTransferEncoding = cte
		nested.Charset = params["charset"]
		nested.Filename = filenameFromMIMEHeader(part.Header)
		nested.ContentID = strings.Trim(part.Header.Get("Content-ID"), "<>")
		nested.ContentDescription = part.Header.Get("Content-Description")
		return nested, nil
	}

	body, err := io.ReadAll(part)
	if err != nil {
		return nil, fmt.Errorf("reading part body: %w", err)
	}

	return &MIMEPart{
		Headers:                 headers,
		ContentType:             mediaType,
		ContentTransferEncoding: cte,
		Charset:                 params["charset"],
		Filename:                filenameFromMIMEHeader(part.Header),
		ContentID:               strings.Trim(part.Header.Get("Content-ID"), "<>"),
		ContentDescription:      part.Header.Get("Content-Description"),
		Body:                    body,
	}, nil
}

func headersFromMIMEHeader(header textproto.MIMEHeader) Headers {
	count := 0
	for _, values := range header {
		count += len(values)
	}
	result := make(Headers, 0, count)
	for name, values := range header {
		for _, value := range values {
			result = append(result, Header{Name: name, Value: value})
		}
	}
	return result
}

func filenameFromHeaders(headers headerGetter) string {
	contentDisp := headers.Get("Content-Disposition")
	if contentDisp == "" {
		return ""
	}
	_, params, err := stdmime.ParseMediaType(contentDisp)
	if err != nil {
		return ""
	}
	return params["filename"]
}

func filenameFromMIMEHeader(header textproto.MIMEHeader) string {
	contentDisp := header.Get("Content-Disposition")
	if contentDisp == "" {
		return ""
	}
	_, params, err := stdmime.ParseMediaType(contentDisp)
	if err != nil {
		return ""
	}
	return params["filename"]
}

func parseTransferEncoding(value string) ContentTransferEncoding {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return ContentTransferEncoding(strings.ToLower(value))
}

func (p *MIMEPart) multipartBoundary() (string, error) {
	if p.boundary != "" {
		return p.boundary, nil
	}
	if len(p.Headers) > 0 {
		if contentType := p.Headers.Get("Content-Type"); contentType != "" {
			_, params, err := stdmime.ParseMediaType(contentType)
			if err == nil && params["boundary"] != "" {
				return params["boundary"], nil
			}
		}
	}
	_, params, err := stdmime.ParseMediaType(p.ContentType)
	if err == nil && params["boundary"] != "" {
		return params["boundary"], nil
	}
	return "", fmt.Errorf("multipart Content-Type missing boundary parameter")
}

func (p *MIMEPart) mimeHeader() (textproto.MIMEHeader, error) {
	headers := make(textproto.MIMEHeader)
	for _, header := range p.Headers {
		if isManagedMIMEHeader(header.Name) {
			continue
		}
		headers.Add(header.Name, header.Value)
	}

	if contentType, ok, err := p.effectiveContentTypeHeader(); err != nil {
		return nil, err
	} else if ok {
		headers.Set("Content-Type", contentType)
	}
	if disposition, ok := p.effectiveContentDispositionHeader(); ok {
		headers.Set("Content-Disposition", disposition)
	}
	if encoding, ok := p.effectiveTransferEncodingHeader(); ok {
		headers.Set("Content-Transfer-Encoding", encoding)
	}
	if contentID, ok := p.effectiveContentIDHeader(); ok {
		headers.Set("Content-ID", contentID)
	}
	if description, ok := p.effectiveContentDescriptionHeader(); ok {
		headers.Set("Content-Description", description)
	}
	return headers, nil
}

func isManagedMIMEHeader(name string) bool {
	switch {
	case strings.EqualFold(name, "Content-Type"):
		return true
	case strings.EqualFold(name, "Content-Disposition"):
		return true
	case strings.EqualFold(name, "Content-Transfer-Encoding"):
		return true
	case strings.EqualFold(name, "Content-ID"):
		return true
	case strings.EqualFold(name, "Content-Description"):
		return true
	default:
		return false
	}
}

func (p *MIMEPart) effectiveContentTypeHeader() (string, bool, error) {
	original := p.Headers.Get("Content-Type")
	if original == "" && p.ContentType == "" {
		return "", false, nil
	}

	mediaType := p.ContentType
	params := map[string]string{}
	if original != "" {
		if parsedType, parsedParams, err := stdmime.ParseMediaType(original); err == nil && strings.Contains(parsedType, "/") {
			if mediaType == "" {
				mediaType = parsedType
			}
			for key, value := range parsedParams {
				params[key] = value
			}
		}
	}
	if p.ContentType != "" {
		if parsedType, parsedParams, err := stdmime.ParseMediaType(p.ContentType); err == nil && strings.Contains(parsedType, "/") {
			mediaType = parsedType
			for key, value := range parsedParams {
				params[key] = value
			}
		}
	}

	if mediaType == "" {
		return original, true, nil
	}
	if p.Charset != "" && strings.HasPrefix(strings.ToLower(mediaType), "text/") {
		params["charset"] = p.Charset
	}
	if p.Filename != "" {
		params["name"] = p.Filename
	}
	if strings.HasPrefix(strings.ToLower(mediaType), "multipart/") {
		boundary, err := p.multipartBoundary()
		if err != nil {
			return "", false, err
		}
		params["boundary"] = boundary
	}
	if len(params) == 0 {
		return mediaType, true, nil
	}
	return stdmime.FormatMediaType(mediaType, params), true, nil
}

func (p *MIMEPart) effectiveContentDispositionHeader() (string, bool) {
	original := p.Headers.Get("Content-Disposition")
	if original == "" {
		if p.Filename == "" {
			return "", false
		}
		return stdmime.FormatMediaType("attachment", map[string]string{"filename": p.Filename}), true
	}

	disposition, params, err := stdmime.ParseMediaType(original)
	if err != nil {
		if p.Filename == "" {
			return original, true
		}
		return stdmime.FormatMediaType("attachment", map[string]string{"filename": p.Filename}), true
	}
	if p.Filename != "" {
		params["filename"] = p.Filename
	}
	if len(params) == 0 {
		return disposition, true
	}
	return stdmime.FormatMediaType(disposition, params), true
}

func (p *MIMEPart) effectiveTransferEncodingHeader() (string, bool) {
	if p.ContentTransferEncoding != "" {
		if original := strings.TrimSpace(p.Headers.Get("Content-Transfer-Encoding")); original != "" {
			return string(p.ContentTransferEncoding), true
		}
		if len(p.Headers) == 0 || p.ContentTransferEncoding != Encoding7Bit {
			return string(p.ContentTransferEncoding), true
		}
	}
	if original := strings.TrimSpace(p.Headers.Get("Content-Transfer-Encoding")); original != "" {
		return original, true
	}
	return "", false
}

func (p *MIMEPart) effectiveContentIDHeader() (string, bool) {
	if p.ContentID != "" {
		return "<" + p.ContentID + ">", true
	}
	if original := p.Headers.Get("Content-ID"); original != "" {
		return original, true
	}
	return "", false
}

func (p *MIMEPart) effectiveContentDescriptionHeader() (string, bool) {
	if p.ContentDescription != "" {
		return p.ContentDescription, true
	}
	if original := p.Headers.Get("Content-Description"); original != "" {
		return original, true
	}
	return "", false
}
