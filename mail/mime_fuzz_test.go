package mail

import (
	"bytes"
	stdmime "mime"
	"testing"
)

func FuzzContentToMIME_RoundTrip(f *testing.F) {
	f.Add("text/plain; charset=utf-8", []byte("hello"))
	f.Add("text/plain; charset=utf-8", []byte("SGVsbG8="))
	f.Add(`multipart/mixed; boundary="b1"`, []byte("--b1\r\nContent-Type: text/plain\r\n\r\nHello\r\n--b1--\r\n"))
	f.Add(`multipart/mixed; boundary="b2"`, []byte("--b2\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nHi=0D=0Athere\r\n--b2--\r\n"))
	f.Add(`multipart/mixed; boundary="outer"`, []byte("--outer\r\nContent-Type: multipart/alternative; boundary=inner\r\n\r\n--inner\r\nContent-Type: text/plain\r\n\r\na\r\n--inner--\r\n--outer--\r\n"))

	f.Fuzz(func(t *testing.T, contentType string, body []byte) {
		headers := Headers{}
		if contentType != "" {
			headers = append(headers, Header{Name: "Content-Type", Value: contentType})
		}

		part, err := parseMIME(&headers, body)
		if err != nil {
			return
		}
		if part == nil {
			t.Fatal("parseMIME returned nil part with nil error")
		}

		if !part.IsMultipart() {
			if !bytes.Equal(part.Body, body) {
				t.Fatalf("single-part body changed during parse")
			}
			serialized, err := part.ToBytes()
			if err != nil {
				t.Fatalf("ToBytes: %v", err)
			}
			if !bytes.Equal(serialized, body) {
				t.Fatalf("single-part body changed during serialize")
			}
			return
		}

		serialized, err := part.ToBytes()
		if err != nil {
			t.Fatalf("ToBytes: %v", err)
		}

		rootContentType := contentType
		if rootContentType == "" {
			if contentTypeHeader, ok, err := part.effectiveContentTypeHeader(); err == nil && ok {
				rootContentType = contentTypeHeader
			}
		}
		if rootContentType == "" {
			return
		}
		if _, _, err := stdmime.ParseMediaType(rootContentType); err != nil {
			return
		}

		reparsed, err := parseMIME(&Headers{{Name: "Content-Type", Value: rootContentType}}, serialized)
		if err != nil {
			t.Fatalf("reparse serialized multipart: %v", err)
		}
		if reparsed == nil {
			t.Fatal("reparse returned nil part with nil error")
		}
		if countMIMEParts(reparsed) != countMIMEParts(part) {
			t.Fatalf("part count changed after round-trip: got %d, want %d", countMIMEParts(reparsed), countMIMEParts(part))
		}
	})
}
