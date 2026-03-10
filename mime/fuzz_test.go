package mime

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/tinylib/msgp/msgp"
)

// testHeaders is a simple map-backed HeaderGetter used in parse tests.
// Keys must match exactly the canonical names used by Parse/ParseSinglePart
// (e.g. "Content-Type", "Content-ID").
type testHeaders map[string]string

func (h testHeaders) Get(name string) string {
	return h[name]
}

// ---- Parse: no Content-Type -------------------------------------------------

func TestParse_NoContentType(t *testing.T) {
	body := []byte("Hello, World!")
	part, err := Parse(testHeaders{}, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if part.ContentType != "text/plain" {
		t.Errorf("ContentType = %q, want text/plain", part.ContentType)
	}
	if part.Charset != "us-ascii" {
		t.Errorf("Charset = %q, want us-ascii", part.Charset)
	}
	if part.ContentTransferEncoding != Encoding7Bit {
		t.Errorf("CTE = %q, want %q", part.ContentTransferEncoding, Encoding7Bit)
	}
	if !bytes.Equal(part.Body, body) {
		t.Errorf("Body = %q, want %q", part.Body, body)
	}
}

func TestParse_NoContentType_WithDescription(t *testing.T) {
	headers := testHeaders{"Content-Description": "A plain text document"}
	part, err := Parse(headers, []byte("body"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if part.ContentDescription != "A plain text document" {
		t.Errorf("ContentDescription = %q, want %q", part.ContentDescription, "A plain text document")
	}
}

// ---- Parse: invalid Content-Type fallback -----------------------------------

func TestParse_InvalidContentType_FallsBackToTextPlain(t *testing.T) {
	body := []byte("some data")
	part, err := Parse(testHeaders{"Content-Type": "!!!not/a/type!!!"}, body)
	if err != nil {
		t.Fatalf("unexpected error for invalid Content-Type: %v", err)
	}
	if part.ContentType != "text/plain" {
		t.Errorf("ContentType = %q, want text/plain (fallback)", part.ContentType)
	}
	if !bytes.Equal(part.Body, body) {
		t.Errorf("Body mismatch: got %q, want %q", part.Body, body)
	}
}

func TestParse_InvalidContentType_WithDescription(t *testing.T) {
	headers := testHeaders{
		"Content-Type":        "!!!bad!!!",
		"Content-Description": "described",
	}
	part, err := Parse(headers, []byte("x"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if part.ContentDescription != "described" {
		t.Errorf("ContentDescription = %q, want %q", part.ContentDescription, "described")
	}
}

// ---- Parse: single-part routing through ParseSinglePart ---------------------

func TestParse_TextPlainWithCharset(t *testing.T) {
	headers := testHeaders{"Content-Type": "text/plain; charset=utf-8"}
	part, err := Parse(headers, []byte("Hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if part.ContentType != "text/plain" {
		t.Errorf("ContentType = %q, want text/plain", part.ContentType)
	}
	if part.Charset != "utf-8" {
		t.Errorf("Charset = %q, want utf-8", part.Charset)
	}
}

func TestParse_ApplicationOctetStream(t *testing.T) {
	body := []byte{0x00, 0x01, 0x02, 0x03}
	headers := testHeaders{"Content-Type": "application/octet-stream"}
	part, err := Parse(headers, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if part.ContentType != "application/octet-stream" {
		t.Errorf("ContentType = %q, want application/octet-stream", part.ContentType)
	}
	if !bytes.Equal(part.Body, body) {
		t.Errorf("Body mismatch")
	}
}

// ---- ParseSinglePart: direct tests ------------------------------------------

func TestParseSinglePart_AllHeaders(t *testing.T) {
	headers := testHeaders{
		"Content-Transfer-Encoding": "base64",
		"Content-ID":                "<image001@example.com>",
		"Content-Description":       "Profile picture",
		"Content-Disposition":       `attachment; filename="photo.jpg"`,
	}
	body := []byte("/9j/base64data")
	part, err := ParseSinglePart(headers, body, "image/jpeg", map[string]string{"charset": "utf-8"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if part.ContentTransferEncoding != EncodingBase64 {
		t.Errorf("CTE = %q, want base64", part.ContentTransferEncoding)
	}
	// Angle brackets must be stripped from Content-ID.
	if part.ContentID != "image001@example.com" {
		t.Errorf("ContentID = %q, want image001@example.com", part.ContentID)
	}
	if part.ContentDescription != "Profile picture" {
		t.Errorf("ContentDescription = %q, want %q", part.ContentDescription, "Profile picture")
	}
	if part.Filename != "photo.jpg" {
		t.Errorf("Filename = %q, want photo.jpg", part.Filename)
	}
	if part.Charset != "utf-8" {
		t.Errorf("Charset = %q, want utf-8", part.Charset)
	}
	if !bytes.Equal(part.Body, body) {
		t.Errorf("Body mismatch")
	}
}

func TestParseSinglePart_ContentIDWithoutAngles(t *testing.T) {
	headers := testHeaders{"Content-ID": "plain-id-without-angles"}
	part, err := ParseSinglePart(headers, nil, "text/plain", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if part.ContentID != "plain-id-without-angles" {
		t.Errorf("ContentID = %q, want plain-id-without-angles", part.ContentID)
	}
}

func TestParseSinglePart_InvalidContentDispositionIgnored(t *testing.T) {
	headers := testHeaders{"Content-Disposition": "!!!invalid!!!"}
	part, err := ParseSinglePart(headers, []byte("body"), "text/plain", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if part.Filename != "" {
		t.Errorf("Filename = %q, want empty (invalid disposition quietly ignored)", part.Filename)
	}
}

func TestParseSinglePart_NilParams(t *testing.T) {
	part, err := ParseSinglePart(testHeaders{}, []byte("data"), "application/pdf", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if part.ContentType != "application/pdf" {
		t.Errorf("ContentType = %q, want application/pdf", part.ContentType)
	}
}

func TestParseSinglePart_QuotedPrintableCTE(t *testing.T) {
	headers := testHeaders{"Content-Transfer-Encoding": "Quoted-Printable"}
	part, err := ParseSinglePart(headers, []byte("body"), "text/plain", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// CTE values are lowercased.
	if part.ContentTransferEncoding != EncodingQuotedPrintable {
		t.Errorf("CTE = %q, want quoted-printable", part.ContentTransferEncoding)
	}
}

// ---- ParseMultipart ---------------------------------------------------------

func TestParseMultipart_MissingBoundaryParam(t *testing.T) {
	_, err := ParseMultipart([]byte("body"), "multipart/mixed", map[string]string{})
	if err == nil {
		t.Fatal("expected error for missing boundary param, got nil")
	}
}

func TestParseMultipart_EmptyBoundary(t *testing.T) {
	_, err := ParseMultipart([]byte("body"), "multipart/mixed", map[string]string{"boundary": ""})
	if err == nil {
		t.Fatal("expected error for empty boundary, got nil")
	}
}

func TestParseMultipart_EmptyParts(t *testing.T) {
	body := []byte("--abc--\r\n")
	_, err := ParseMultipart(body, "multipart/mixed", map[string]string{"boundary": "abc"})
	if err == nil {
		t.Fatal("expected error for multipart with no parts, got nil")
	}
	if !strings.Contains(err.Error(), "no parts") {
		t.Errorf("error %q should mention 'no parts'", err.Error())
	}
}

func TestParseMultipart_SinglePart(t *testing.T) {
	body := []byte("--abc\r\nContent-Type: text/plain\r\n\r\nHello\r\n--abc--\r\n")
	part, err := ParseMultipart(body, "multipart/mixed", map[string]string{"boundary": "abc"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(part.Parts) != 1 {
		t.Fatalf("expected 1 part, got %d", len(part.Parts))
	}
	if part.Parts[0].ContentType != "text/plain" {
		t.Errorf("part[0].ContentType = %q, want text/plain", part.Parts[0].ContentType)
	}
	if !bytes.Equal(part.Parts[0].Body, []byte("Hello")) {
		t.Errorf("part[0].Body = %q, want Hello", part.Parts[0].Body)
	}
}

func TestParseMultipart_MultipleParts(t *testing.T) {
	body := []byte("" +
		"--bnd\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"First\r\n" +
		"--bnd\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<b>Second</b>\r\n" +
		"--bnd--\r\n")
	part, err := ParseMultipart(body, "multipart/alternative", map[string]string{"boundary": "bnd"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(part.Parts) != 2 {
		t.Fatalf("expected 2 parts, got %d", len(part.Parts))
	}
	if !bytes.Equal(part.Parts[0].Body, []byte("First")) {
		t.Errorf("part[0].Body = %q, want First", part.Parts[0].Body)
	}
	if !bytes.Equal(part.Parts[1].Body, []byte("<b>Second</b>")) {
		t.Errorf("part[1].Body = %q, want <b>Second</b>", part.Parts[1].Body)
	}
}

func TestParseMultipart_PartWithNoContentType_DefaultsToTextPlain(t *testing.T) {
	body := []byte("--abc\r\n\r\nHello\r\n--abc--\r\n")
	part, err := ParseMultipart(body, "multipart/mixed", map[string]string{"boundary": "abc"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(part.Parts) == 0 {
		t.Fatal("expected 1 part, got 0")
	}
	p := part.Parts[0]
	if p.ContentType != "text/plain" {
		t.Errorf("ContentType = %q, want text/plain (default)", p.ContentType)
	}
	if p.Charset != "us-ascii" {
		t.Errorf("Charset = %q, want us-ascii (default)", p.Charset)
	}
}

func TestParseMultipart_PartWithAllHeaders(t *testing.T) {
	body := []byte("" +
		"--xyz\r\n" +
		"Content-Type: image/jpeg\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-ID: <img001@test.com>\r\n" +
		"Content-Description: A photo\r\n" +
		`Content-Disposition: attachment; filename="photo.jpg"` + "\r\n" +
		"\r\n" +
		"/9j/data\r\n" +
		"--xyz--\r\n")
	part, err := ParseMultipart(body, "multipart/mixed", map[string]string{"boundary": "xyz"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(part.Parts) == 0 {
		t.Fatal("expected 1 part")
	}
	p := part.Parts[0]
	if p.ContentTransferEncoding != EncodingBase64 {
		t.Errorf("CTE = %q, want base64", p.ContentTransferEncoding)
	}
	if p.ContentID != "img001@test.com" {
		t.Errorf("ContentID = %q, want img001@test.com", p.ContentID)
	}
	if p.ContentDescription != "A photo" {
		t.Errorf("ContentDescription = %q, want A photo", p.ContentDescription)
	}
	if p.Filename != "photo.jpg" {
		t.Errorf("Filename = %q, want photo.jpg", p.Filename)
	}
}

func TestParseMultipart_InvalidPartContentType(t *testing.T) {
	// "!!!invalid!!!" has no slash: not a valid RFC 2045 media type.
	body := []byte("" +
		"--abc\r\n" +
		"Content-Type: !!!invalid!!!\r\n" +
		"\r\n" +
		"body\r\n" +
		"--abc--\r\n")
	_, err := ParseMultipart(body, "multipart/mixed", map[string]string{"boundary": "abc"})
	if err == nil {
		t.Fatal("expected error for invalid part Content-Type, got nil")
	}
}

func TestParseMultipart_NestedMultipartMissingBoundary(t *testing.T) {
	// A nested part declares multipart/alternative but omits the boundary param.
	body := []byte("" +
		"--outer\r\n" +
		"Content-Type: multipart/alternative\r\n" +
		"\r\n" +
		"inner content\r\n" +
		"--outer--\r\n")
	_, err := ParseMultipart(body, "multipart/mixed", map[string]string{"boundary": "outer"})
	if err == nil {
		t.Fatal("expected error for nested multipart missing boundary, got nil")
	}
}

// ---- Parse: multipart routing through ParseMultipart ------------------------

func TestParse_MultipartSinglePart(t *testing.T) {
	body := []byte("--bnd\r\nContent-Type: text/plain\r\n\r\nHello\r\n--bnd--\r\n")
	headers := testHeaders{"Content-Type": `multipart/mixed; boundary="bnd"`}
	part, err := Parse(headers, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !part.IsMultipart() {
		t.Error("IsMultipart() = false, want true")
	}
	if len(part.Parts) != 1 {
		t.Fatalf("expected 1 part, got %d", len(part.Parts))
	}
}

func TestParse_MultipartMissingBoundaryInHeader(t *testing.T) {
	// Content-Type is "multipart/mixed" with no boundary param → error.
	_, err := Parse(testHeaders{"Content-Type": "multipart/mixed"}, []byte("body"))
	if err == nil {
		t.Fatal("expected error for multipart without boundary, got nil")
	}
}

func TestParse_NestedMultipart(t *testing.T) {
	// outer/mixed → one part of type multipart/alternative → two text parts.
	outerBody := "" +
		"--outer\r\n" +
		`Content-Type: multipart/alternative; boundary="inner"` + "\r\n" +
		"\r\n" +
		"--inner\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Plain text version" +
		"\r\n--inner\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<b>HTML version</b>" +
		"\r\n--inner--\r\n" +
		"\r\n--outer--\r\n"

	headers := testHeaders{"Content-Type": `multipart/mixed; boundary="outer"`}
	part, err := Parse(headers, []byte(outerBody))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !part.IsMultipart() {
		t.Error("outer IsMultipart() = false, want true")
	}
	if len(part.Parts) == 0 {
		t.Fatal("outer has no parts")
	}
	nested := part.Parts[0]
	if !strings.HasPrefix(nested.ContentType, "multipart/") {
		t.Errorf("nested ContentType = %q, want multipart/...", nested.ContentType)
	}
	if len(nested.Parts) != 2 {
		t.Errorf("nested has %d parts, want 2", len(nested.Parts))
	}
}

// ---- ToBytes ----------------------------------------------------------------

func TestToBytes_NonMultipart_ReturnsBodyDirectly(t *testing.T) {
	body := []byte("Hello, World!")
	part := &Part{Body: body}
	b, err := part.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(b, body) {
		t.Errorf("ToBytes() = %q, want %q", b, body)
	}
}

func TestToBytes_NilBody(t *testing.T) {
	part := &Part{ContentType: "text/plain"}
	b, err := part.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) != 0 {
		t.Errorf("ToBytes() = %q, want empty", b)
	}
}

func TestToBytes_MultipartBasic(t *testing.T) {
	part := &Part{
		ContentType: `multipart/mixed; boundary="xyz"`,
		Parts: []*Part{
			{ContentType: "text/plain", Body: []byte("Hello")},
		},
	}
	b, err := part.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, "--xyz") {
		t.Errorf("result missing boundary: %q", s)
	}
	if !strings.Contains(s, "Hello") {
		t.Errorf("result missing body: %q", s)
	}
	if !strings.Contains(s, "--xyz--") {
		t.Errorf("result missing closing boundary: %q", s)
	}
}

func TestToBytes_MultipartMissingBoundaryInContentType(t *testing.T) {
	part := &Part{
		ContentType: "multipart/mixed", // no boundary param
		Parts: []*Part{
			{ContentType: "text/plain", Body: []byte("body")},
		},
	}
	_, err := part.ToBytes()
	if err == nil {
		t.Fatal("expected error for multipart missing boundary in ContentType, got nil")
	}
}

func TestToBytes_WritePartHeaders_AllFields(t *testing.T) {
	// Exercises all branches of writePartHeaders (ContentType, charset, CTE,
	// Content-ID, Content-Description, Content-Disposition / filename).
	part := &Part{
		ContentType: `multipart/mixed; boundary="fence"`,
		Parts: []*Part{
			{
				ContentType:             "text/plain",
				Charset:                 "utf-8",
				ContentTransferEncoding: EncodingBase64,
				ContentID:               "myid",
				ContentDescription:      "A description",
				Filename:                "file.txt",
				Body:                    []byte("dGVzdA=="),
			},
		},
	}
	b, err := part.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `charset="utf-8"`) {
		t.Errorf("missing charset in output: %q", s)
	}
	if !strings.Contains(s, "Content-Transfer-Encoding: base64") {
		t.Errorf("missing CTE in output: %q", s)
	}
	if !strings.Contains(s, "Content-ID: <myid>") {
		t.Errorf("missing Content-ID in output: %q", s)
	}
	if !strings.Contains(s, "Content-Description: A description") {
		t.Errorf("missing Content-Description in output: %q", s)
	}
	if !strings.Contains(s, `Content-Disposition: attachment; filename="file.txt"`) {
		t.Errorf("missing Content-Disposition in output: %q", s)
	}
}

func TestToBytes_WritePartHeaders_ExplicitHeaders(t *testing.T) {
	// When a sub-part carries explicit Headers, writePartHeaders emits those
	// directly instead of reconstructing from individual fields.
	part := &Part{
		ContentType: `multipart/mixed; boundary="sep"`,
		Parts: []*Part{
			{
				Headers: []Header{
					{Name: "Content-Type", Value: "application/json"},
					{Name: "X-Custom", Value: "val123"},
				},
				Body: []byte(`{"k":"v"}`),
			},
		},
	}
	b, err := part.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, "Content-Type: application/json") {
		t.Errorf("missing explicit Content-Type header: %q", s)
	}
	if !strings.Contains(s, "X-Custom: val123") {
		t.Errorf("missing X-Custom header: %q", s)
	}
}

func TestToBytes_WritePartHeaders_MultipartContentType(t *testing.T) {
	// A sub-part whose ContentType starts with "multipart/" should have its
	// boundary re-emitted in the Content-Type header by writePartHeaders.
	part := &Part{
		ContentType: `multipart/mixed; boundary="outer"`,
		Parts: []*Part{
			{
				// Sub-part with multipart ContentType but no nested Parts,
				// so IsMultipart()=false and ToBytes() returns Body directly.
				ContentType: `multipart/alternative; boundary="alt"`,
				Body:        []byte(""),
			},
		},
	}
	b, err := part.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `boundary="alt"`) {
		t.Errorf("nested boundary not present in header output: %q", s)
	}
}

func TestToBytes_RecursiveMultipart(t *testing.T) {
	// Two-level nesting: outer/mixed → inner/alternative → two text parts.
	inner := &Part{
		ContentType: `multipart/alternative; boundary="inner"`,
		Parts: []*Part{
			{ContentType: "text/plain", Body: []byte("plain text")},
			{ContentType: "text/html", Body: []byte("<b>html</b>")},
		},
	}
	outer := &Part{
		ContentType: `multipart/mixed; boundary="outer"`,
		Parts:       []*Part{inner},
	}
	b, err := outer.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, "--outer") {
		t.Errorf("outer boundary missing: %q", s)
	}
	if !strings.Contains(s, "--inner") {
		t.Errorf("inner boundary missing: %q", s)
	}
	if !strings.Contains(s, "plain text") {
		t.Errorf("inner plain text missing: %q", s)
	}
	if !strings.Contains(s, "<b>html</b>") {
		t.Errorf("inner HTML content missing: %q", s)
	}
}

// ---- Fuzz tests -------------------------------------------------------------

// ---- msgp: ContentTransferEncoding -----------------------------------------

// TestContentTransferEncoding_MsgpRoundTrip exercises all five generated msgp
// methods for ContentTransferEncoding (DecodeMsg, EncodeMsg, MarshalMsg,
// UnmarshalMsg, Msgsize).
func TestContentTransferEncoding_MsgpRoundTrip(t *testing.T) {
	encodings := []ContentTransferEncoding{
		Encoding7Bit,
		Encoding8Bit,
		EncodingBinary,
		EncodingQuotedPrintable,
		EncodingBase64,
		"", // zero value
		ContentTransferEncoding("x-custom"),
	}

	for _, enc := range encodings {
		enc := enc
		t.Run(string(enc), func(t *testing.T) {
			// MarshalMsg / UnmarshalMsg round-trip.
			bts, err := enc.MarshalMsg(nil)
			if err != nil {
				t.Fatalf("MarshalMsg(%q): %v", enc, err)
			}
			if sz := enc.Msgsize(); sz <= 0 {
				t.Errorf("Msgsize(%q) = %d, want > 0", enc, sz)
			}
			var dec ContentTransferEncoding
			left, err := dec.UnmarshalMsg(bts)
			if err != nil {
				t.Fatalf("UnmarshalMsg(%q): %v", enc, err)
			}
			if len(left) > 0 {
				t.Errorf("UnmarshalMsg(%q): %d bytes left over", enc, len(left))
			}
			if dec != enc {
				t.Errorf("round-trip: got %q, want %q", dec, enc)
			}

			// EncodeMsg / DecodeMsg round-trip.
			var buf bytes.Buffer
			wr := msgp.NewWriter(&buf)
			if err := enc.EncodeMsg(wr); err != nil {
				t.Fatalf("EncodeMsg(%q): %v", enc, err)
			}
			if err := wr.Flush(); err != nil {
				t.Fatalf("Flush(%q): %v", enc, err)
			}
			var dec2 ContentTransferEncoding
			if err := dec2.DecodeMsg(msgp.NewReader(&buf)); err != nil {
				t.Fatalf("DecodeMsg(%q): %v", enc, err)
			}
			if dec2 != enc {
				t.Errorf("encode/decode round-trip: got %q, want %q", dec2, enc)
			}
		})
	}
}

// ---- msgp: Part with all fields populated -----------------------------------

// populatedPart returns a Part with every field set, maximising the code paths
// exercised by the msgp-generated serialisation routines.
func populatedPart() Part {
	return Part{
		Headers: []Header{
			{Name: "Content-Type", Value: "text/plain; charset=utf-8"},
			{Name: "X-Custom", Value: "test-value"},
		},
		ContentType:             "text/plain",
		ContentTransferEncoding: EncodingBase64,
		Charset:                 "utf-8",
		Filename:                "attachment.txt",
		ContentID:               "unique-content-id-001",
		ContentDescription:      "A test attachment",
		Body:                    []byte("SGVsbG8sIFdvcmxkIQ=="),
		Parts: []*Part{
			{
				ContentType:             "text/html",
				ContentTransferEncoding: EncodingQuotedPrintable,
				Charset:                 "utf-8",
				Body:                    []byte("<b>Hello</b>"),
			},
		},
	}
}

func TestPart_MsgpMarshalUnmarshal_Populated(t *testing.T) {
	orig := populatedPart()
	bts, err := orig.MarshalMsg(nil)
	if err != nil {
		t.Fatalf("MarshalMsg: %v", err)
	}
	sz := orig.Msgsize()
	if sz <= 0 {
		t.Errorf("Msgsize() = %d, want > 0", sz)
	}

	var decoded Part
	left, err := decoded.UnmarshalMsg(bts)
	if err != nil {
		t.Fatalf("UnmarshalMsg: %v", err)
	}
	if len(left) > 0 {
		t.Errorf("%d bytes left over after UnmarshalMsg", len(left))
	}

	// Spot-check key fields.
	if decoded.ContentType != orig.ContentType {
		t.Errorf("ContentType: got %q, want %q", decoded.ContentType, orig.ContentType)
	}
	if decoded.ContentTransferEncoding != orig.ContentTransferEncoding {
		t.Errorf("CTE: got %q, want %q", decoded.ContentTransferEncoding, orig.ContentTransferEncoding)
	}
	if decoded.Charset != orig.Charset {
		t.Errorf("Charset: got %q, want %q", decoded.Charset, orig.Charset)
	}
	if decoded.Filename != orig.Filename {
		t.Errorf("Filename: got %q, want %q", decoded.Filename, orig.Filename)
	}
	if decoded.ContentID != orig.ContentID {
		t.Errorf("ContentID: got %q, want %q", decoded.ContentID, orig.ContentID)
	}
	if decoded.ContentDescription != orig.ContentDescription {
		t.Errorf("ContentDescription: got %q, want %q", decoded.ContentDescription, orig.ContentDescription)
	}
	if !bytes.Equal(decoded.Body, orig.Body) {
		t.Errorf("Body mismatch")
	}
	if len(decoded.Parts) != len(orig.Parts) {
		t.Errorf("Parts length: got %d, want %d", len(decoded.Parts), len(orig.Parts))
	}
	if len(decoded.Headers) != len(orig.Headers) {
		t.Errorf("Headers length: got %d, want %d", len(decoded.Headers), len(orig.Headers))
	}
}

func TestPart_MsgpEncodeDecodeMsg_Populated(t *testing.T) {
	orig := populatedPart()

	var buf bytes.Buffer
	wr := msgp.NewWriter(&buf)
	if err := orig.EncodeMsg(wr); err != nil {
		t.Fatalf("EncodeMsg: %v", err)
	}
	if err := wr.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	var decoded Part
	if err := decoded.DecodeMsg(msgp.NewReader(&buf)); err != nil {
		t.Fatalf("DecodeMsg: %v", err)
	}

	if decoded.ContentType != orig.ContentType {
		t.Errorf("ContentType: got %q, want %q", decoded.ContentType, orig.ContentType)
	}
	if !bytes.Equal(decoded.Body, orig.Body) {
		t.Errorf("Body mismatch")
	}
	if len(decoded.Parts) != len(orig.Parts) {
		t.Errorf("Parts length: got %d, want %d", len(decoded.Parts), len(orig.Parts))
	}
}

// TestPart_MsgpMultipleNestedParts checks Marshal/Unmarshal with several
// nested parts to exercise the array-encoding loops in the generated code.
func TestPart_MsgpMultipleNestedParts(t *testing.T) {
	orig := Part{
		ContentType: "multipart/mixed",
		Parts: []*Part{
			{ContentType: "text/plain", Body: []byte("one")},
			{ContentType: "text/html", Body: []byte("<b>two</b>")},
			{
				ContentType:             "image/jpeg",
				ContentTransferEncoding: EncodingBase64,
				Filename:                "photo.jpg",
				ContentID:               "photo001",
				Body:                    []byte("/9j/data"),
			},
		},
	}

	bts, err := orig.MarshalMsg(nil)
	if err != nil {
		t.Fatalf("MarshalMsg: %v", err)
	}

	var decoded Part
	if _, err := decoded.UnmarshalMsg(bts); err != nil {
		t.Fatalf("UnmarshalMsg: %v", err)
	}
	if len(decoded.Parts) != 3 {
		t.Fatalf("Parts length: got %d, want 3", len(decoded.Parts))
	}
	if decoded.Parts[2].Filename != "photo.jpg" {
		t.Errorf("nested Filename: got %q, want photo.jpg", decoded.Parts[2].Filename)
	}
}

// TestPart_MsgpMultipleHeaders verifies that the Headers slice (which is a
// []Header, itself msgp-serialised) round-trips faithfully with many entries.
func TestPart_MsgpMultipleHeaders(t *testing.T) {
	orig := Part{
		ContentType: "text/plain",
		Headers: []Header{
			{Name: "From", Value: "sender@example.com"},
			{Name: "To", Value: "recipient@example.com"},
			{Name: "Subject", Value: "Test message"},
			{Name: "MIME-Version", Value: "1.0"},
			{Name: "Content-Type", Value: "text/plain; charset=utf-8"},
		},
		Body: []byte("body text"),
	}

	bts, err := orig.MarshalMsg(nil)
	if err != nil {
		t.Fatalf("MarshalMsg: %v", err)
	}
	var decoded Part
	if _, err := decoded.UnmarshalMsg(bts); err != nil {
		t.Fatalf("UnmarshalMsg: %v", err)
	}
	if len(decoded.Headers) != len(orig.Headers) {
		t.Errorf("Headers length: got %d, want %d", len(decoded.Headers), len(orig.Headers))
	}
	for i, h := range orig.Headers {
		if decoded.Headers[i].Name != h.Name || decoded.Headers[i].Value != h.Value {
			t.Errorf("Header[%d]: got {%q,%q}, want {%q,%q}",
				i, decoded.Headers[i].Name, decoded.Headers[i].Value, h.Name, h.Value)
		}
	}
}

// checks structural invariants on success (no panic, non-nil Part, ToJSON works).
func FuzzParse(f *testing.F) {
	f.Add("text/plain; charset=utf-8", "Hello, World!")
	f.Add("text/html", "<html><body>Hello</body></html>")
	f.Add(`multipart/mixed; boundary="abc"`,
		"--abc\r\nContent-Type: text/plain\r\n\r\nHello\r\n--abc--\r\n")
	f.Add("", "No content type")
	f.Add("invalid-content-type", "invalid ct body")
	f.Add("application/octet-stream", "\x00\x01\x02\x03")
	f.Add(`multipart/alternative; boundary="bnd"`,
		"--bnd\r\nContent-Type: text/plain\r\n\r\nfirst\r\n--bnd\r\nContent-Type: text/html\r\n\r\nsecond\r\n--bnd--\r\n")
	f.Add("message/rfc822", "Subject: test\r\n\r\nBody")

	f.Fuzz(func(t *testing.T, contentType, body string) {
		headers := testHeaders{}
		if contentType != "" {
			headers["Content-Type"] = contentType
		}
		part, err := Parse(headers, []byte(body))
		if err != nil {
			return
		}
		// Invariant: Part must not be nil on success.
		if part == nil {
			t.Error("Parse() returned nil Part with nil error")
			return
		}
		// Invariant: ContentType must not be empty on success.
		if part.ContentType == "" {
			t.Error("Parse() returned Part with empty ContentType")
		}
		// Invariant: ToJSON must succeed after a successful Parse.
		if _, jsonErr := part.ToJSON(); jsonErr != nil {
			t.Errorf("ToJSON() failed after successful Parse: %v", jsonErr)
		}
	})
}

// FuzzParseMultipart feeds arbitrary boundary strings and raw bodies into
// ParseMultipart and checks invariants on success.
func FuzzParseMultipart(f *testing.F) {
	f.Add("abc", "--abc\r\nContent-Type: text/plain\r\n\r\nHello\r\n--abc--\r\n")
	f.Add("bnd", "--bnd\r\n\r\nbody\r\n--bnd--\r\n")
	f.Add("x", "")
	f.Add("boundary123",
		"--boundary123\r\nContent-Type: text/plain\r\n\r\nfirst\r\n"+
			"--boundary123\r\nContent-Type: text/html\r\n\r\nsecond\r\n"+
			"--boundary123--\r\n")

	f.Fuzz(func(t *testing.T, boundary, body string) {
		if boundary == "" {
			return
		}
		part, err := ParseMultipart([]byte(body), "multipart/mixed", map[string]string{"boundary": boundary})
		if err != nil {
			return
		}
		if part == nil {
			t.Error("ParseMultipart() returned nil Part with nil error")
			return
		}
		// Invariant: a successful parse must yield at least one part.
		if len(part.Parts) == 0 {
			t.Error("ParseMultipart() returned Part with zero parts on success")
		}
		// Invariant: ToJSON must succeed.
		if _, jsonErr := part.ToJSON(); jsonErr != nil {
			t.Errorf("ToJSON() failed after ParseMultipart: %v", jsonErr)
		}
	})
}

// FuzzParseRoundTrip parses a multipart body, serializes it, re-parses the
// output, and verifies that the part count is preserved.
func FuzzParseRoundTrip(f *testing.F) {
	f.Add("sep", "--sep\r\nContent-Type: text/plain\r\n\r\nHello\r\n--sep--\r\n")
	f.Add("fence", "--fence\r\nContent-Type: text/html\r\n\r\n<b>Hi</b>\r\n--fence--\r\n")
	f.Add("b",
		"--b\r\nContent-Type: text/plain\r\n\r\nA\r\n"+
			"--b\r\nContent-Type: text/plain\r\n\r\nB\r\n"+
			"--b--\r\n")

	f.Fuzz(func(t *testing.T, boundary, body string) {
		// Boundaries with quotes would break the fmt.Sprintf below.
		if boundary == "" || strings.Contains(boundary, `"`) {
			return
		}
		params := map[string]string{"boundary": boundary}
		part, err := ParseMultipart([]byte(body), "multipart/mixed", params)
		if err != nil {
			return
		}
		// Give the Part a ContentType that includes the boundary so ToBytes works.
		part.ContentType = fmt.Sprintf(`multipart/mixed; boundary="%s"`, boundary)
		serialized, err := part.ToBytes()
		if err != nil {
			return
		}
		// Re-parse the serialized output; part count must be preserved.
		reparsed, err := ParseMultipart(serialized, "multipart/mixed", params)
		if err != nil {
			// Re-parse failure is permitted (e.g. boundary chars that are
			// not legal in quoted strings), but must not panic.
			return
		}
		if len(reparsed.Parts) != len(part.Parts) {
			t.Errorf("round-trip part count mismatch: got %d, want %d",
				len(reparsed.Parts), len(part.Parts))
		}
	})
}
