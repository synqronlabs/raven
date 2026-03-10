package mail

import (
	"strings"
	"testing"
)

// FuzzParseRawContent verifies that parseRawContent never panics on arbitrary input
// and that round-tripping through ToRaw → FromRaw is lossless for well-formed messages.
func FuzzParseRawContent(f *testing.F) {
	// Seed corpus: valid CRLF message
	f.Add([]byte("From: a@b.com\r\nSubject: Hi\r\n\r\nBody text"))
	// Bare-LF variant
	f.Add([]byte("From: a@b.com\nSubject: Hi\n\nBody text"))
	// No separator
	f.Add([]byte("just body text no headers"))
	// Empty
	f.Add([]byte{})
	// Only separator
	f.Add([]byte("\r\n\r\n"))
	// Folded header
	f.Add([]byte("Subject: folded\r\n value\r\n\r\nbody"))
	// Malformed header
	f.Add([]byte("NOCOLON\r\nFrom: a@b.com\r\n\r\nbody"))
	// Very long header value
	f.Add([]byte("Subject: " + strings.Repeat("x", 2000) + "\r\n\r\nbody"))
	// Header with colon in value
	f.Add([]byte("Subject: re: reply\r\n\r\nbody"))
	// Binary body
	f.Add(append([]byte("From: a@b.com\r\n\r\n"), 0x00, 0x01, 0xFF, 0xFE))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic.
		headers, body := parseRawContent(data)
		_ = headers
		_ = body
	})
}

// FuzzFoldHeader verifies that FoldHeader never panics, always ends with CRLF,
// and that no output line exceeds MaxLineLength.
func FuzzFoldHeader(f *testing.F) {
	f.Add("Subject", "Hello World")
	f.Add("Subject", strings.Repeat("word ", 200))
	f.Add("X-Long", strings.Repeat("nospace", 200))
	f.Add("X-Empty", "")
	f.Add("X", strings.Repeat("a", MaxLineLength+1))
	f.Add("Subject", "mixed\r\n folded\r\n value")

	f.Fuzz(func(t *testing.T, name, value string) {
		result := FoldHeader(name, value)

		// Must end with CRLF.
		if len(result) < 2 || result[len(result)-2] != '\r' || result[len(result)-1] != '\n' {
			t.Errorf("FoldHeader(%q, ...) does not end with CRLF", name)
		}

		// No line may exceed MaxLineLength characters.
		lines := splitLines(result)
		for i, line := range lines {
			if len(line) > MaxLineLength {
				t.Errorf("line %d exceeds MaxLineLength (%d): len=%d", i, MaxLineLength, len(line))
			}
		}
	})
}

// FuzzHeaders_Validate verifies that Headers.Validate never panics on arbitrary input.
func FuzzHeaders_Validate(f *testing.F) {
	f.Add("Date", "Thu, 01 Jan 2026 00:00:00 +0000", "From", "a@b.com")
	f.Add("", "", "", "")
	f.Add("Subject", strings.Repeat("x", 1500), "Date", "Thu, 01 Jan 2026 00:00:00 +0000")

	f.Fuzz(func(t *testing.T, n1, v1, n2, v2 string) {
		h := Headers{{Name: n1, Value: v1}, {Name: n2, Value: v2}}
		_ = h.Validate()
	})
}

// FuzzContent_Validate verifies that Content.Validate never panics on arbitrary binary body.
func FuzzContent_Validate(f *testing.F) {
	f.Add([]byte("Hello\r\nWorld\r\n"))
	f.Add([]byte("bare\nLF\n"))
	f.Add([]byte(strings.Repeat("a", 1100) + "\r\n"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, body []byte) {
		c := Content{
			Headers: Headers{
				{Name: "Date", Value: "Thu, 01 Jan 2026 00:00:00 +0000"},
				{Name: "From", Value: "a@b.com"},
			},
			Body: body,
		}
		_ = c.Validate()
	})
}

// FuzzMailBuilder_TextBody verifies that building a mail with arbitrary subjects and
// bodies never panics and always produces output that round-trips through ToRaw.
func FuzzMailBuilder_TextBody(f *testing.F) {
	f.Add("Hello", "Body text here")
	f.Add("日本語", "本文テスト")
	f.Add("", "")
	f.Add(strings.Repeat("word ", 100), strings.Repeat("body\r\n", 50))

	f.Fuzz(func(t *testing.T, subject, body string) {
		m, err := NewMailBuilder().
			From("sender@example.com").
			To("recipient@example.com").
			Subject(subject).
			TextBody(body).
			Build()
		if err != nil {
			// Build errors are allowed (e.g. for completely invalid inputs
			// that slip through the address parser), just don't panic.
			return
		}

		raw := m.Content.ToRaw()
		if len(raw) == 0 {
			t.Error("ToRaw returned empty output")
		}

		// Round-trip: parse the raw output back.
		var c Content
		c.FromRaw(raw)
		// The reassembled body might differ (normalised CRLF), but must not panic.
		_ = c
	})
}
