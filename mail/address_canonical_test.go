package mail

import (
	"errors"
	"strings"
	"testing"
)

func TestObsLocalPartCanonicalSerialization(t *testing.T) {
	tests := []struct {
		input    string
		local    string
		wantWire string
	}{
		{`a."b c"@example.com`, `a.b c`, `"a.b c"@example.com`},
		{`"a b".c@example.com`, `a b.c`, `"a b.c"@example.com`},
		{`"a"."b"@example.com`, `a.b`, `a.b@example.com`},
		{`a."b"@example.com`, `a.b`, `a.b@example.com`},
	}
	for _, tt := range tests {
		parsed, err := ParseAddress(tt.input)
		if err != nil {
			t.Errorf("ParseAddress(%q) error: %v", tt.input, err)
			continue
		}
		if parsed.LocalPart != tt.local {
			t.Errorf("ParseAddress(%q).LocalPart = %q, want %q", tt.input, parsed.LocalPart, tt.local)
		}
		if got := parsed.String(); got != tt.wantWire {
			t.Errorf("ParseAddress(%q).String() = %q, want %q", tt.input, got, tt.wantWire)
		}
		if _, err := ParseAddrSpec(tt.wantWire, false); err != nil {
			t.Errorf("serialized local-part %q is not an RFC 5321 path: %v", tt.wantWire, err)
		}
	}
}

func TestQuotedLocalPartUnfoldsFWSAndRejectsControls(t *testing.T) {
	parsed, err := ParseAddress("\"a\r\n b\"@example.com")
	if err != nil {
		t.Fatalf("ParseAddress(folded quoted local-part) error: %v", err)
	}
	if parsed.LocalPart != "a b" {
		t.Errorf("LocalPart = %q, want %q", parsed.LocalPart, "a b")
	}
	if !validMailboxPart(parsed.LocalPart) {
		t.Errorf("parsed LocalPart %q is not wire-safe", parsed.LocalPart)
	}
	if got := parsed.String(); got != `"a b"@example.com` {
		t.Errorf("String() = %q, want %q", got, `"a b"@example.com`)
	}

	if _, err := ParseAddress("\"a\nb\"@example.com"); !errors.Is(err, ErrInvalidLineEnding) {
		t.Errorf("bare LF error = %v, want %v", err, ErrInvalidLineEnding)
	}
}

func TestValidDisplayNameRejectsUnicodeLineBreaksAndControls(t *testing.T) {
	invalid := []string{
		"J\u0085hn", // NEL, encoded as C2 85 in UTF-8
		"J\u2028hn", // LINE SEPARATOR
		"J\u2029hn", // PARAGRAPH SEPARATOR
		"J\u000bbn", // vertical tab
	}
	for _, name := range invalid {
		if validDisplayName(name) {
			t.Errorf("validDisplayName(%q) = true, want false", name)
		}
	}

	encoded := []string{
		"=?UTF-8?Q?J=C2=85hn?= <j@example.com>",
		"=?UTF-8?Q?J=E2=80=A8hn?= <j@example.com>",
		"=?UTF-8?Q?J=E2=80=A9hn?= <j@example.com>",
	}
	for _, input := range encoded {
		if _, err := ParseAddress(input); err == nil {
			t.Errorf("ParseAddress(%q) = nil error, want rejected display name", input)
		}
	}
}

func TestParseAddress_CharsetDecoding(t *testing.T) {
	tests := []struct {
		input   string
		display string
	}{
		{"=?ISO-8859-1?Q?=93Hi=94?= <a@b.com>", "\u201cHi\u201d"},
		{"=?windows-1252?Q?J=F6hn?= <j@example.com>", "Jöhn"},
		{"=?windows-1252?Q?=93Hi=94?= <a@b.com>", "\u201cHi\u201d"},
		{"=?ISO-8859-15?Q?=A4?= <a@b.com>", "€"},
	}
	for _, tt := range tests {
		parsed, err := ParseAddress(tt.input)
		if err != nil {
			t.Errorf("ParseAddress(%q) error: %v", tt.input, err)
			continue
		}
		if parsed.DisplayName != tt.display {
			t.Errorf("ParseAddress(%q).DisplayName = %q, want %q", tt.input, parsed.DisplayName, tt.display)
		}
	}
}

func TestParseAddress_DisplayNameReconstruction(t *testing.T) {
	tests := []struct {
		input   string
		display string
	}{
		{"John Q. Public <j@example.com>", "John Q. Public"},
		{"John.Doe <j@example.com>", "John.Doe"},
		{"John . Doe <j@example.com>", "John . Doe"},
		{`John" Q" Public <j@example.com>`, "John Q Public"},
		{"John  Doe <j@example.com>", "John Doe"},
		{"John (comment) Doe <j@example.com>", "John Doe"},
	}
	for _, tt := range tests {
		parsed, err := ParseAddress(tt.input)
		if err != nil {
			t.Errorf("ParseAddress(%q) error: %v", tt.input, err)
			continue
		}
		if parsed.DisplayName != tt.display {
			t.Errorf("ParseAddress(%q).DisplayName = %q, want %q", tt.input, parsed.DisplayName, tt.display)
		}
	}
}

func TestParseAddressList_ObsLeadingCommas(t *testing.T) {
	got, err := ParseAddressList(", , a@b.com, c@d.com")
	if err != nil {
		t.Fatalf("ParseAddressList(leading commas) error: %v", err)
	}
	if len(got) != 2 || got[0].String() != "a@b.com" || got[1].String() != "c@d.com" {
		t.Fatalf("ParseAddressList(leading commas) = %v", got)
	}

	for _, input := range []string{"a@b.com,", "a@b.com,,c@d.com", ","} {
		if _, err := ParseAddressList(input); err == nil {
			t.Errorf("ParseAddressList(%q) = nil error, want error", input)
		}
	}
}

func TestQuotedLocalPartCanonicalEquality(t *testing.T) {
	quoted, err := ParseAddress(`"john.doe"@example.com`)
	if err != nil {
		t.Fatalf("ParseAddress(quoted) error: %v", err)
	}
	plain, err := ParseAddress("john.doe@example.com")
	if err != nil {
		t.Fatalf("ParseAddress(plain) error: %v", err)
	}
	if quoted.LocalPart != plain.LocalPart {
		t.Errorf("LocalPart quoted=%q plain=%q, want equal", quoted.LocalPart, plain.LocalPart)
	}
	if quoted.String() != plain.String() {
		t.Errorf("String quoted=%q plain=%q, want equal", quoted.String(), plain.String())
	}

	spaced, err := ParseAddress(`"john doe"@example.com`)
	if err != nil {
		t.Fatalf("ParseAddress(spaced) error: %v", err)
	}
	if spaced.LocalPart != "john doe" {
		t.Errorf("LocalPart = %q, want %q", spaced.LocalPart, "john doe")
	}
	if spaced.String() != `"john doe"@example.com` {
		t.Errorf("String() = %q, want quoted form", spaced.String())
	}
	if err := (&MailboxAddress{LocalPart: spaced.LocalPart, Domain: spaced.Domain}).RequiresQuotedLocalPart(); !err {
		t.Error("RequiresQuotedLocalPart() = false, want true")
	}
}

func TestParsePath_QuotedLocalPartIsValidSMTP(t *testing.T) {
	parsed, _, err := ParsePath(`<"a b"@example.com>`, false)
	if err != nil {
		t.Fatalf("ParsePath(quoted local) error: %v", err)
	}
	if got := parsed.String(); got != `"a b"@example.com` {
		t.Errorf("ParsePath(quoted local).String() = %q", got)
	}
	path := Path{Mailbox: parsed}
	if !strings.Contains(path.String(), `"a b"@example.com`) {
		t.Errorf("Path.String() = %q, want quoted local-part", path.String())
	}
}

func TestParsePath_QuotedLocalPartWithGreaterThan(t *testing.T) {
	original := MailboxAddress{LocalPart: "a>b", Domain: "example.com"}
	envelopePath := Path{Mailbox: original}
	path := envelopePath.String()
	if path != `<"a>b"@example.com>` {
		t.Fatalf("Path.String() = %q, want quoted greater-than", path)
	}

	parsed, params, err := ParsePath(path, false)
	if err != nil {
		t.Fatalf("ParsePath(%q) error: %v", path, err)
	}
	if params != "" {
		t.Errorf("ParsePath(%q) params = %q, want empty", path, params)
	}
	if parsed.LocalPart != "a>b" || parsed.Domain != "example.com" {
		t.Errorf("ParsePath(%q) = %+v, want local=a>b domain=example.com", path, parsed)
	}
}
