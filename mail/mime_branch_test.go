package mail

import (
	"bytes"
	"mime/multipart"
	"net/textproto"
	"strings"
	"testing"
)

func TestMIMEPart_IsMultipart_Branches(t *testing.T) {
	if (*MIMEPart)(nil).IsMultipart() {
		t.Fatal("nil MIMEPart should not be multipart")
	}
	if (&MIMEPart{ContentType: "multipart/mixed"}).IsMultipart() {
		t.Fatal("multipart without children should not be multipart")
	}
	if (&MIMEPart{ContentType: "text/plain", Parts: []*MIMEPart{{}}}).IsMultipart() {
		t.Fatal("non-multipart content type should not be multipart")
	}
	if !(&MIMEPart{ContentType: "Multipart/Mixed", Parts: []*MIMEPart{{ContentType: "text/plain"}}}).IsMultipart() {
		t.Fatal("multipart content with children should be multipart")
	}
}

func TestMIMEPart_ToBytes_NilAndMissingBoundary(t *testing.T) {
	data, err := (*MIMEPart)(nil).ToBytes()
	if err != nil {
		t.Fatalf("nil ToBytes error: %v", err)
	}
	if data != nil {
		t.Errorf("nil ToBytes data = %v, want nil", data)
	}

	_, err = (&MIMEPart{ContentType: "multipart/mixed", Parts: []*MIMEPart{{ContentType: "text/plain"}}}).ToBytes()
	if err == nil || !strings.Contains(err.Error(), "boundary") {
		t.Fatalf("expected missing boundary error, got %v", err)
	}
}

func TestParseMIME_InvalidMultipartAndFallbackBranches(t *testing.T) {
	headers := Headers{
		{Name: "Content-Type", Value: "invalid-content-type"},
		{Name: "Content-Transfer-Encoding", Value: "quoted-printable"},
		{Name: "Content-ID", Value: "<abc@example.com>"},
		{Name: "Content-Description", Value: "desc"},
		{Name: "Content-Disposition", Value: `attachment; filename="f.txt"`},
	}
	part, err := parseMIME(&headers, []byte("body"))
	if err != nil {
		t.Fatalf("parseMIME fallback: %v", err)
	}
	if part.ContentType != "text/plain" || part.Charset != "us-ascii" {
		t.Fatalf("fallback part = %#v", part)
	}
	if part.ContentTransferEncoding != EncodingQuotedPrintable {
		t.Errorf("ContentTransferEncoding = %q", part.ContentTransferEncoding)
	}
	if part.Filename != "f.txt" || part.ContentID != "abc@example.com" || part.ContentDescription != "desc" {
		t.Errorf("fallback metadata mismatch: %#v", part)
	}

	multipartHeaders := Headers{{Name: "Content-Type", Value: "multipart/mixed"}}
	_, err = parseMIME(&multipartHeaders, []byte("body"))
	if err == nil || !strings.Contains(err.Error(), "boundary") {
		t.Fatalf("expected multipart boundary error, got %v", err)
	}
}

func TestParseMultipartBody_ErrorBranches(t *testing.T) {
	if _, err := parseMultipartBody([]byte("body"), "multipart/mixed", map[string]string{}); err == nil {
		t.Fatal("expected missing boundary error")
	}
	if _, err := parseMultipartBody([]byte("--b--\r\n"), "multipart/mixed", map[string]string{"boundary": "b"}); err == nil {
		t.Fatal("expected no parts error")
	}
	body := []byte("--b\r\nContent-Type: !!!bad!!!\r\n\r\nbody\r\n--b--\r\n")
	if _, err := parseMultipartBody(body, "multipart/mixed", map[string]string{"boundary": "b"}); err == nil {
		t.Fatal("expected invalid part content-type error")
	}
}

func TestParseMultipartSection_Branches(t *testing.T) {
	t.Run("no content type defaults", func(t *testing.T) {
		root := multipart.NewReader(bytes.NewReader([]byte("--b\r\n\r\nbody\r\n--b--\r\n")), "b")
		part, err := root.NextRawPart()
		if err != nil {
			t.Fatalf("NextRawPart: %v", err)
		}
		parsed, err := parseMultipartSection(part)
		if err != nil {
			t.Fatalf("parseMultipartSection: %v", err)
		}
		if parsed.ContentType != "text/plain" || parsed.Charset != "us-ascii" {
			t.Errorf("parsed = %#v", parsed)
		}
	})

	t.Run("nested multipart", func(t *testing.T) {
		body := []byte("--o\r\nContent-Type: multipart/alternative; boundary=i\r\n\r\n--i\r\nContent-Type: text/plain\r\n\r\na\r\n--i--\r\n--o--\r\n")
		root := multipart.NewReader(bytes.NewReader(body), "o")
		part, err := root.NextRawPart()
		if err != nil {
			t.Fatalf("NextRawPart: %v", err)
		}
		parsed, err := parseMultipartSection(part)
		if err != nil {
			t.Fatalf("parseMultipartSection nested: %v", err)
		}
		if !parsed.IsMultipart() || len(parsed.Parts) != 1 {
			t.Fatalf("nested parsed = %#v", parsed)
		}
	})

	t.Run("nested multipart missing boundary", func(t *testing.T) {
		body := []byte("--o\r\nContent-Type: multipart/alternative\r\n\r\nbody\r\n--o--\r\n")
		root := multipart.NewReader(bytes.NewReader(body), "o")
		part, err := root.NextRawPart()
		if err != nil {
			t.Fatalf("NextRawPart: %v", err)
		}
		if _, err := parseMultipartSection(part); err == nil {
			t.Fatal("expected nested multipart boundary error")
		}
	})
}

func TestFilenameHelpers_AndTransferEncodingBranches(t *testing.T) {
	emptyHeaders := Headers{}
	if got := filenameFromHeaders(&emptyHeaders); got != "" {
		t.Errorf("filenameFromHeaders empty = %q, want empty", got)
	}
	headers := Headers{{Name: "Content-Disposition", Value: `attachment; filename="ok.txt"`}}
	if got := filenameFromHeaders(&headers); got != "ok.txt" {
		t.Errorf("filenameFromHeaders = %q", got)
	}
	badHeaders := Headers{{Name: "Content-Disposition", Value: "!!!bad!!!"}}
	if got := filenameFromHeaders(&badHeaders); got != "" {
		t.Errorf("filenameFromHeaders bad = %q, want empty", got)
	}

	emptyMIMEHeader := textproto.MIMEHeader{}
	if got := filenameFromMIMEHeader(emptyMIMEHeader); got != "" {
		t.Errorf("filenameFromMIMEHeader empty = %q, want empty", got)
	}
	mimeHeader := textproto.MIMEHeader{"Content-Disposition": {`inline; filename="img.png"`}}
	if got := filenameFromMIMEHeader(mimeHeader); got != "img.png" {
		t.Errorf("filenameFromMIMEHeader = %q", got)
	}
	badMIMEHeader := textproto.MIMEHeader{"Content-Disposition": {"!!!bad!!!"}}
	if got := filenameFromMIMEHeader(badMIMEHeader); got != "" {
		t.Errorf("filenameFromMIMEHeader bad = %q, want empty", got)
	}

	if got := parseTransferEncoding("  Base64 "); got != EncodingBase64 {
		t.Errorf("parseTransferEncoding = %q", got)
	}
	if got := parseTransferEncoding(""); got != "" {
		t.Errorf("parseTransferEncoding empty = %q, want empty", got)
	}
}

func TestMultipartBoundaryAndHeaderHelpers(t *testing.T) {
	part := &MIMEPart{boundary: "cached"}
	if got, err := part.multipartBoundary(); err != nil || got != "cached" {
		t.Fatalf("multipartBoundary cached = %q, %v", got, err)
	}

	part = &MIMEPart{Headers: Headers{{Name: "Content-Type", Value: `multipart/mixed; boundary="header-b"`}}}
	if got, err := part.multipartBoundary(); err != nil || got != "header-b" {
		t.Fatalf("multipartBoundary header = %q, %v", got, err)
	}

	part = &MIMEPart{ContentType: `multipart/mixed; boundary="field-b"`}
	if got, err := part.multipartBoundary(); err != nil || got != "field-b" {
		t.Fatalf("multipartBoundary field = %q, %v", got, err)
	}

	part = &MIMEPart{ContentType: "multipart/mixed"}
	if _, err := part.multipartBoundary(); err == nil {
		t.Fatal("expected multipartBoundary error")
	}

	nonManaged := &MIMEPart{Headers: Headers{{Name: "X-Test", Value: "keep"}}}
	headers, err := nonManaged.mimeHeader()
	if err != nil {
		t.Fatalf("mimeHeader non-managed: %v", err)
	}
	if headers.Get("X-Test") != "keep" {
		t.Errorf("X-Test = %q", headers.Get("X-Test"))
	}

	badMultipart := &MIMEPart{ContentType: "multipart/mixed", Parts: []*MIMEPart{{ContentType: "text/plain"}}}
	if _, err := badMultipart.mimeHeader(); err == nil {
		t.Fatal("expected mimeHeader boundary error")
	}
}

func TestEffectiveHeaderHelpers_Branches(t *testing.T) {
	part := &MIMEPart{}
	if value, ok, err := part.effectiveContentTypeHeader(); err != nil || ok || value != "" {
		t.Fatalf("empty effectiveContentTypeHeader = %q, %v, %v", value, ok, err)
	}

	part = &MIMEPart{Headers: Headers{{Name: "Content-Type", Value: "!!!bad!!!"}}}
	if value, ok, err := part.effectiveContentTypeHeader(); err != nil || !ok || value != "!!!bad!!!" {
		t.Fatalf("invalid original effectiveContentTypeHeader = %q, %v, %v", value, ok, err)
	}
	part = &MIMEPart{Headers: Headers{{Name: "Content-Type", Value: `text/plain; charset="utf-8"; format=flowed`}}}
	if value, ok, err := part.effectiveContentTypeHeader(); err != nil || !ok || !strings.Contains(value, "format=flowed") {
		t.Fatalf("original-only effectiveContentTypeHeader = %q, %v, %v", value, ok, err)
	}

	part = &MIMEPart{ContentType: "text/plain"}
	if value, ok, err := part.effectiveContentTypeHeader(); err != nil || !ok || value != "text/plain" {
		t.Fatalf("simple effectiveContentTypeHeader = %q, %v, %v", value, ok, err)
	}

	part = &MIMEPart{ContentType: "multipart/mixed", Parts: []*MIMEPart{{ContentType: "text/plain"}}}
	if _, _, err := part.effectiveContentTypeHeader(); err == nil {
		t.Fatal("expected multipart content type boundary error")
	}

	part = &MIMEPart{}
	if value, ok := part.effectiveContentDispositionHeader(); ok || value != "" {
		t.Fatalf("empty effectiveContentDispositionHeader = %q, %v", value, ok)
	}
	part = &MIMEPart{Filename: "fresh.txt"}
	if value, ok := part.effectiveContentDispositionHeader(); !ok || !strings.Contains(value, "filename=fresh.txt") {
		t.Fatalf("generated disposition = %q, %v", value, ok)
	}
	part = &MIMEPart{Headers: Headers{{Name: "Content-Disposition", Value: "!!!bad!!!"}}}
	if value, ok := part.effectiveContentDispositionHeader(); !ok || value != "!!!bad!!!" {
		t.Fatalf("invalid original disposition = %q, %v", value, ok)
	}
	part = &MIMEPart{Headers: Headers{{Name: "Content-Disposition", Value: "attachment"}}, Filename: "new.bin"}
	if value, ok := part.effectiveContentDispositionHeader(); !ok || !strings.Contains(value, "filename=new.bin") {
		t.Fatalf("effectiveContentDispositionHeader updated = %q, %v", value, ok)
	}

	part = &MIMEPart{ContentTransferEncoding: Encoding7Bit}
	if value, ok := part.effectiveTransferEncodingHeader(); !ok || value != string(Encoding7Bit) {
		t.Fatalf("effectiveTransferEncodingHeader field only = %q, %v", value, ok)
	}
	part = &MIMEPart{Headers: Headers{{Name: "Content-Transfer-Encoding", Value: "quoted-printable"}}}
	if value, ok := part.effectiveTransferEncodingHeader(); !ok || value != "quoted-printable" {
		t.Fatalf("effectiveTransferEncodingHeader header only = %q, %v", value, ok)
	}
	part = &MIMEPart{}
	if value, ok := part.effectiveTransferEncodingHeader(); ok || value != "" {
		t.Fatalf("effectiveTransferEncodingHeader empty = %q, %v", value, ok)
	}

	part = &MIMEPart{Headers: Headers{{Name: "Content-ID", Value: "<orig@example.com>"}}}
	if value, ok := part.effectiveContentIDHeader(); !ok || value != "<orig@example.com>" {
		t.Fatalf("effectiveContentIDHeader original = %q, %v", value, ok)
	}
	part = &MIMEPart{}
	if value, ok := part.effectiveContentIDHeader(); ok || value != "" {
		t.Fatalf("effectiveContentIDHeader empty = %q, %v", value, ok)
	}

	part = &MIMEPart{Headers: Headers{{Name: "Content-Description", Value: "orig desc"}}}
	if value, ok := part.effectiveContentDescriptionHeader(); !ok || value != "orig desc" {
		t.Fatalf("effectiveContentDescriptionHeader original = %q, %v", value, ok)
	}
	part = &MIMEPart{}
	if value, ok := part.effectiveContentDescriptionHeader(); ok || value != "" {
		t.Fatalf("effectiveContentDescriptionHeader empty = %q, %v", value, ok)
	}
}

func TestContentFromMIME_NilPart(t *testing.T) {
	var content Content
	err := content.FromMIME(nil)
	if err == nil || err.Error() != "mime part is required" {
		t.Fatalf("expected nil part error, got %v", err)
	}
}

func TestContentFromMIME_MultipartError(t *testing.T) {
	var content Content
	err := content.FromMIME(&MIMEPart{ContentType: "multipart/mixed", Parts: []*MIMEPart{{ContentType: "text/plain"}}})
	if err == nil {
		t.Fatal("expected multipart serialization error")
	}
}

func TestContentValidate_EmptyBody(t *testing.T) {
	content := Content{Headers: Headers{{Name: "Date", Value: "Thu, 12 Dec 2024 10:00:00 +0000"}, {Name: "From", Value: "sender@example.com"}}}
	if err := content.Validate(); err != nil {
		t.Fatalf("Validate empty body: %v", err)
	}
}
