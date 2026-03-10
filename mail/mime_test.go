package mail

import (
	"bytes"
	"io"
	stdmime "mime"
	"mime/multipart"
	"strings"
	"testing"
)

func TestContentToMIME_PreservesRawTransferEncodedSinglePart(t *testing.T) {
	c := Content{
		Headers: Headers{
			{Name: "Content-Type", Value: "text/plain; charset=utf-8"},
			{Name: "Content-Transfer-Encoding", Value: "base64"},
			{Name: "Content-ID", Value: "<part-1@example.com>"},
			{Name: "Content-Description", Value: "encoded body"},
			{Name: "Content-Disposition", Value: `attachment; filename="payload.txt"`},
		},
		Body: []byte("SGVsbG8sIFdvcmxkIQ=="),
	}

	part, err := c.ToMIME()
	if err != nil {
		t.Fatalf("ToMIME: %v", err)
	}
	if part.IsMultipart() {
		t.Fatal("single-part content reported as multipart")
	}
	if part.ContentType != "text/plain" {
		t.Errorf("ContentType = %q, want text/plain", part.ContentType)
	}
	if part.Charset != "utf-8" {
		t.Errorf("Charset = %q, want utf-8", part.Charset)
	}
	if part.ContentTransferEncoding != EncodingBase64 {
		t.Errorf("ContentTransferEncoding = %q, want %q", part.ContentTransferEncoding, EncodingBase64)
	}
	if part.ContentID != "part-1@example.com" {
		t.Errorf("ContentID = %q, want part-1@example.com", part.ContentID)
	}
	if part.ContentDescription != "encoded body" {
		t.Errorf("ContentDescription = %q, want encoded body", part.ContentDescription)
	}
	if part.Filename != "payload.txt" {
		t.Errorf("Filename = %q, want payload.txt", part.Filename)
	}
	if !bytes.Equal(part.Body, c.Body) {
		t.Errorf("Body = %q, want %q", part.Body, c.Body)
	}
}

func TestContentToMIME_MultipartQuotedPrintablePreservesRawBody(t *testing.T) {
	const boundary = "mixed-raw-qp"
	body := []byte("--mixed-raw-qp\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"X-Trace: keep-me\r\n\r\n" +
		"Hello=0D=0AWorld=21\r\n" +
		"--mixed-raw-qp--\r\n")

	c := Content{
		Headers: Headers{{Name: "Content-Type", Value: `multipart/mixed; boundary="` + boundary + `"`}},
		Body:    body,
	}

	part, err := c.ToMIME()
	if err != nil {
		t.Fatalf("ToMIME: %v", err)
	}
	if !part.IsMultipart() {
		t.Fatal("multipart content not detected as multipart")
	}
	if len(part.Parts) != 1 {
		t.Fatalf("len(Parts) = %d, want 1", len(part.Parts))
	}

	child := part.Parts[0]
	if child.ContentTransferEncoding != EncodingQuotedPrintable {
		t.Errorf("ContentTransferEncoding = %q, want %q", child.ContentTransferEncoding, EncodingQuotedPrintable)
	}
	if !bytes.Equal(child.Body, []byte("Hello=0D=0AWorld=21")) {
		t.Errorf("Body = %q, want raw quoted-printable bytes", child.Body)
	}
	if child.Headers.Get("Content-Transfer-Encoding") != "quoted-printable" {
		t.Errorf("raw header CTE = %q, want quoted-printable", child.Headers.Get("Content-Transfer-Encoding"))
	}
	if child.Headers.Get("X-Trace") != "keep-me" {
		t.Errorf("X-Trace = %q, want keep-me", child.Headers.Get("X-Trace"))
	}

	serialized, err := part.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes: %v", err)
	}
	reader := multipart.NewReader(bytes.NewReader(serialized), boundary)
	rawPart, err := reader.NextRawPart()
	if err != nil {
		t.Fatalf("NextRawPart: %v", err)
	}
	rawBody, err := io.ReadAll(rawPart)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(rawBody, []byte("Hello=0D=0AWorld=21")) {
		t.Errorf("serialized body = %q, want raw quoted-printable bytes", rawBody)
	}
	if rawPart.Header.Get("Content-Transfer-Encoding") != "quoted-printable" {
		t.Errorf("serialized CTE = %q, want quoted-printable", rawPart.Header.Get("Content-Transfer-Encoding"))
	}
}

func TestMIMEPartToBytes_MergesStructuredFieldsWithExistingHeaders(t *testing.T) {
	root := &MIMEPart{
		ContentType: `multipart/mixed; boundary="root-boundary"`,
		Parts: []*MIMEPart{{
			Headers: Headers{
				{Name: "Content-Type", Value: `text/plain; charset=utf-8; format=flowed`},
				{Name: "Content-Disposition", Value: `inline; filename="old.txt"; creation-date="Mon, 01 Jan 2024 00:00:00 GMT"`},
				{Name: "Content-Transfer-Encoding", Value: "quoted-printable"},
				{Name: "Content-ID", Value: "<old@example.com>"},
				{Name: "Content-Description", Value: "old description"},
				{Name: "X-Custom", Value: "keep-me"},
			},
			ContentType:             "text/plain",
			Charset:                 "iso-8859-1",
			Filename:                "new.txt",
			ContentTransferEncoding: EncodingBase64,
			ContentID:               "new@example.com",
			ContentDescription:      "new description",
			Body:                    []byte("YWJj"),
		}},
	}

	serialized, err := root.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes: %v", err)
	}

	reader := multipart.NewReader(bytes.NewReader(serialized), "root-boundary")
	child, err := reader.NextRawPart()
	if err != nil {
		t.Fatalf("NextRawPart: %v", err)
	}
	contentType := child.Header.Get("Content-Type")
	mediaType, params, err := stdmime.ParseMediaType(contentType)
	if err != nil {
		t.Fatalf("ParseMediaType(Content-Type): %v", err)
	}
	if mediaType != "text/plain" {
		t.Errorf("Content-Type media type = %q, want text/plain", mediaType)
	}
	if params["charset"] != "iso-8859-1" {
		t.Errorf("charset = %q, want iso-8859-1", params["charset"])
	}
	if params["format"] != "flowed" {
		t.Errorf("format = %q, want flowed", params["format"])
	}
	if params["name"] != "new.txt" {
		t.Errorf("name = %q, want new.txt", params["name"])
	}

	disposition := child.Header.Get("Content-Disposition")
	dispType, dispParams, err := stdmime.ParseMediaType(disposition)
	if err != nil {
		t.Fatalf("ParseMediaType(Content-Disposition): %v", err)
	}
	if dispType != "inline" {
		t.Errorf("disposition = %q, want inline", dispType)
	}
	if dispParams["filename"] != "new.txt" {
		t.Errorf("filename = %q, want new.txt", dispParams["filename"])
	}
	if dispParams["creation-date"] != "Mon, 01 Jan 2024 00:00:00 GMT" {
		t.Errorf("creation-date = %q, want original value", dispParams["creation-date"])
	}
	if child.Header.Get("Content-Transfer-Encoding") != "base64" {
		t.Errorf("CTE = %q, want base64", child.Header.Get("Content-Transfer-Encoding"))
	}
	if child.Header.Get("Content-ID") != "<new@example.com>" {
		t.Errorf("Content-ID = %q, want <new@example.com>", child.Header.Get("Content-ID"))
	}
	if child.Header.Get("Content-Description") != "new description" {
		t.Errorf("Content-Description = %q, want new description", child.Header.Get("Content-Description"))
	}
	if child.Header.Get("X-Custom") != "keep-me" {
		t.Errorf("X-Custom = %q, want keep-me", child.Header.Get("X-Custom"))
	}
	body, err := io.ReadAll(child)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(body) != "YWJj" {
		t.Errorf("body = %q, want YWJj", body)
	}
}

func TestContentToMIME_DoesNotInventTransferEncodingHeader(t *testing.T) {
	const boundary = "no-cte"
	body := []byte("--no-cte\r\nContent-Type: text/plain\r\n\r\nplain body\r\n--no-cte--\r\n")
	c := Content{
		Headers: Headers{{Name: "Content-Type", Value: `multipart/mixed; boundary="` + boundary + `"`}},
		Body:    body,
	}

	part, err := c.ToMIME()
	if err != nil {
		t.Fatalf("ToMIME: %v", err)
	}
	if len(part.Parts) != 1 {
		t.Fatalf("len(Parts) = %d, want 1", len(part.Parts))
	}
	if part.Parts[0].ContentTransferEncoding != "" {
		t.Errorf("ContentTransferEncoding = %q, want empty", part.Parts[0].ContentTransferEncoding)
	}

	serialized, err := part.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes: %v", err)
	}
	reader := multipart.NewReader(bytes.NewReader(serialized), boundary)
	rawPart, err := reader.NextRawPart()
	if err != nil {
		t.Fatalf("NextRawPart: %v", err)
	}
	if rawPart.Header.Get("Content-Transfer-Encoding") != "" {
		t.Errorf("unexpected Content-Transfer-Encoding header: %q", rawPart.Header.Get("Content-Transfer-Encoding"))
	}
}

func TestContentToMIME_FallbackPreservesExplicitTransferEncoding(t *testing.T) {
	c := Content{
		Headers: Headers{{Name: "Content-Transfer-Encoding", Value: "base64"}},
		Body:    []byte("U29tZSBib2R5"),
	}

	part, err := c.ToMIME()
	if err != nil {
		t.Fatalf("ToMIME: %v", err)
	}
	if part.ContentType != "text/plain" {
		t.Errorf("ContentType = %q, want text/plain", part.ContentType)
	}
	if part.Charset != "us-ascii" {
		t.Errorf("Charset = %q, want us-ascii", part.Charset)
	}
	if part.ContentTransferEncoding != EncodingBase64 {
		t.Errorf("ContentTransferEncoding = %q, want %q", part.ContentTransferEncoding, EncodingBase64)
	}
	if !bytes.Equal(part.Body, c.Body) {
		t.Errorf("Body = %q, want %q", part.Body, c.Body)
	}
}

func countMIMEParts(part *MIMEPart) int {
	if part == nil {
		return 0
	}
	total := 1
	for _, child := range part.Parts {
		total += countMIMEParts(child)
	}
	return total
}

func TestMIMEPart_ToBytes_RoundTripsNestedMultipartStructure(t *testing.T) {
	const outerBoundary = "outer-boundary"
	body := []byte("--outer-boundary\r\n" +
		"Content-Type: multipart/alternative; boundary=inner-boundary\r\n\r\n" +
		"--inner-boundary\r\nContent-Type: text/plain\r\n\r\nplain\r\n" +
		"--inner-boundary\r\nContent-Type: text/html\r\n\r\n<b>html</b>\r\n" +
		"--inner-boundary--\r\n" +
		"--outer-boundary--\r\n")

	c := Content{
		Headers: Headers{{Name: "Content-Type", Value: `multipart/mixed; boundary="` + outerBoundary + `"`}},
		Body:    body,
	}

	part, err := c.ToMIME()
	if err != nil {
		t.Fatalf("ToMIME: %v", err)
	}
	serialized, err := part.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes: %v", err)
	}
	reparsed, err := parseMIME(&Headers{{Name: "Content-Type", Value: `multipart/mixed; boundary="` + outerBoundary + `"`}}, serialized)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if countMIMEParts(reparsed) != countMIMEParts(part) {
		t.Errorf("part count changed after round-trip: got %d, want %d", countMIMEParts(reparsed), countMIMEParts(part))
	}
	if !strings.Contains(string(serialized), "inner-boundary") {
		t.Errorf("serialized multipart missing nested boundary: %q", serialized)
	}
}
