package mail

import (
	"errors"
	"testing"
)

func TestParseAddrSpec_GeneralAddressLiteral(t *testing.T) {
	valid := []string{
		"user@[TAG:content]",
		"user@[x:y]",
		"user@[tag:1.2.3]",
	}
	for _, addr := range valid {
		if _, err := ParseAddrSpec(addr, false); err != nil {
			t.Errorf("ParseAddrSpec(%q) error = %v, want nil", addr, err)
		}
	}

	invalid := []string{
		"user@[TAG:]",          // empty dcontent
		"user@[-TAG:x]",        // tag starts with hyphen
		"user@[TAG-:x]",        // tag ends with hyphen
		"user@[TA G:x]",        // invalid tag char
		"user@[TAG:has space]", // space is not dcontent
	}
	for _, addr := range invalid {
		if _, err := ParseAddrSpec(addr, false); !errors.Is(err, ErrInvalidIPLiteral) {
			t.Errorf("ParseAddrSpec(%q) error = %v, want %v", addr, err, ErrInvalidIPLiteral)
		}
	}
}

func TestParseAddrSpec_InvalidUTF8(t *testing.T) {
	if _, err := ParseAddrSpec("user@\xff.com", false); !errors.Is(err, ErrInvalidUTF8) {
		t.Errorf("error = %v, want %v", err, ErrInvalidUTF8)
	}
}

func TestParseAddrSpec_QuotedStringErrors(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{"unterminated", `"unterminated@example.com`},
		{"control char", "\"a\tb\"@example.com"},
		{"escaped control", "\"a\\\x01b\"@example.com"},
		{"bad escape end", "\"a\\"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseAddrSpec(tt.addr, false); err == nil {
				t.Errorf("ParseAddrSpec(%q) = nil error, want error", tt.addr)
			}
		})
	}

	// Escaped non-ASCII requires SMTPUTF8.
	if _, err := ParseAddrSpec("\"a\\é\"@example.com", false); !errors.Is(err, ErrNonASCIIWithoutUTF8) {
		t.Errorf("escaped non-ASCII error = %v, want %v", err, ErrNonASCIIWithoutUTF8)
	}
	if _, err := ParseAddrSpec("\"a\\é\"@example.com", true); err != nil {
		t.Errorf("escaped non-ASCII with UTF8 error = %v, want nil", err)
	}
}

func TestParseAddrSpec_IDNDomainErrors(t *testing.T) {
	if _, err := ParseAddrSpec("user@例え-.jp", true); !errors.Is(err, ErrInvalidDomain) {
		t.Errorf("trailing hyphen IDN error = %v, want %v", err, ErrInvalidDomain)
	}
}

func TestParseAddress_HeaderIDNDomain(t *testing.T) {
	parsed, err := ParseAddress("user@例え.jp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.Domain != "xn--r8jz45g.jp" {
		t.Errorf("Domain = %q, want xn--r8jz45g.jp", parsed.Domain)
	}

	if _, err := ParseAddress("user@例え-.jp"); !errors.Is(err, ErrInvalidDomain) {
		t.Errorf("invalid IDN error = %v, want %v", err, ErrInvalidDomain)
	}
}

func TestParseAddress_DomainLiteral(t *testing.T) {
	// Folding white space inside a domain literal is permitted by RFC 5322.
	parsed, err := ParseAddress("user@[ 192.0.2.1 ]")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.Domain != "[192.0.2.1]" {
		t.Errorf("Domain = %q", parsed.Domain)
	}

	for _, addr := range []string{"user@[abc", `user@[a\b]`} {
		if _, err := ParseAddress(addr); err == nil {
			t.Errorf("ParseAddress(%q) = nil error, want error", addr)
		}
	}
}

func TestParseAddress_ObsLocalPart(t *testing.T) {
	valid := []struct {
		addr  string
		local string
	}{
		{`"a"."b"@example.com`, `a.b`},
		{`a."b".c@example.com`, `a.b.c`},
		{`"a".b@example.com`, `a.b`},
	}
	for _, tt := range valid {
		parsed, err := ParseAddress(tt.addr)
		if err != nil {
			t.Fatalf("ParseAddress(%q) error: %v", tt.addr, err)
		}
		if parsed.LocalPart != tt.local {
			t.Errorf("LocalPart = %q, want %q", parsed.LocalPart, tt.local)
		}
	}

	invalid := []string{`a..b@example.com`, `.a@example.com`, `a.@example.com`, `a."b@example.com`}
	for _, addr := range invalid {
		if _, err := ParseAddress(addr); err == nil {
			t.Errorf("ParseAddress(%q) = nil error, want error", addr)
		}
	}
}

func TestParseAddress_DisplayName(t *testing.T) {
	tests := []struct {
		input   string
		display string
	}{
		{`"A\"B" <a@b.com>`, `A"B`},
		{`"A\\B" <a@b.com>`, `A\B`},
		{"=?UTF-8?B?SsO2aG4=?= <j@x.com>", "Jöhn"},
		{"John.Doe <j@x.com>", "John.Doe"},
		{"John  Doe <j@x.com>", "John Doe"},
		{"(comment) Jane <j@x.com>", "Jane"},
	}
	for _, tt := range tests {
		parsed, err := ParseAddress(tt.input)
		if err != nil {
			t.Fatalf("ParseAddress(%q) error: %v", tt.input, err)
		}
		if parsed.DisplayName != tt.display {
			t.Errorf("ParseAddress(%q).DisplayName = %q, want %q", tt.input, parsed.DisplayName, tt.display)
		}
	}
}

func TestParseAddress_Errors(t *testing.T) {
	tests := []string{
		"<a@b.com",            // missing >
		"<a@b.com> trailing",  // trailing junk
		"a@b.com, c@d.com",    // multiple addresses
		"Group: a@b.com;",     // group not allowed for single mailbox
		"<a@b.com>>",          // trailing bracket
		"(unclosed <a@b.com>", // bad comment
		"<@relay:user@b.com>", // source route not valid in header
	}
	for _, addr := range tests {
		if _, err := ParseAddress(addr); err == nil {
			t.Errorf("ParseAddress(%q) = nil error, want error", addr)
		}
	}
}

func TestParseAddressList_More(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"two groups", "G1: a@b.com;, G2: c@d.com;", []string{"a@b.com", "c@d.com"}},
		{"group then mailbox", "G: a@b.com;, c@d.com", []string{"a@b.com", "c@d.com"}},
		{"comments", "(a) a@b.com (b), (c) c@d.com", []string{"a@b.com", "c@d.com"}},
		{"bare angle", "<a@b.com>, <c@d.com>", []string{"a@b.com", "c@d.com"}},
		{"obs phrase dot", "John.Doe <j@x.com>", []string{"j@x.com"}},
		{"leading comma", ", a@b.com", []string{"a@b.com"}},
		{"leading commas", ", , a@b.com, b@c.com", []string{"a@b.com", "b@c.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAddressList(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i].String() != tt.want[i] {
					t.Errorf("address[%d] = %q, want %q", i, got[i].String(), tt.want[i])
				}
			}
		})
	}

	invalid := []string{
		"a@b.com b@c.com",     // missing comma
		"a@b.com,",            // trailing empty element
		"a@b.com,,c@d.com",    // interior empty element
		",",                   // no address after leading comma
		"G: a@b.com b@c.com;", // missing comma in group
		"G: a@b.com",          // missing group terminator
		"G: a@b.com, ;",       // empty element in group
		"(unclosed a@b.com",   // bad comment
	}
	for _, input := range invalid {
		if _, err := ParseAddressList(input); err == nil {
			t.Errorf("ParseAddressList(%q) = nil error, want error", input)
		}
	}
}

func TestParsePath_SourceRoutes(t *testing.T) {
	tests := []struct {
		path   string
		want   string
		params string
	}{
		{"<@relay.example.com:user@example.com>", "user@example.com", ""},
		{"<@a.example.com,@b.example.com:user@example.com> SIZE=1", "user@example.com", "SIZE=1"},
		{"<@[192.0.2.1]:user@example.com>", "user@example.com", ""},
		{"<@relay.example.com:user@[IPv6:2001:db8::1]>", "user@[IPv6:2001:db8::1]", ""},
	}
	for _, tt := range tests {
		parsed, params, err := ParsePath(tt.path, false)
		if err != nil {
			t.Fatalf("ParsePath(%q) error: %v", tt.path, err)
		}
		if parsed.String() != tt.want || params != tt.params {
			t.Errorf("ParsePath(%q) = (%q, %q), want (%q, %q)", tt.path, parsed.String(), params, tt.want, tt.params)
		}
	}

	invalid := []string{
		"<@relay user@example.com>", // route without ':'
		"<@:user@example.com>",      // empty route domain
		"<@relay:not-an-address>",   // bad mailbox
	}
	for _, path := range invalid {
		if _, _, err := ParsePath(path, false); err == nil {
			t.Errorf("ParsePath(%q) = nil error, want error", path)
		}
	}
}

func TestParseAddrSpec_IPv4EmbeddedIPv6(t *testing.T) {
	if _, err := ParseAddrSpec("user@[IPv6:::ffff:192.0.2.1]", false); err != nil {
		t.Errorf("valid IPv4-embedded IPv6 error = %v", err)
	}
	if _, err := ParseAddrSpec("user@[IPv6:::ffff:999.0.0.1]", false); !errors.Is(err, ErrInvalidIPLiteral) {
		t.Errorf("invalid IPv4-embedded IPv6 error = %v, want %v", err, ErrInvalidIPLiteral)
	}
}

func TestParseAddressList_EmptyAndComments(t *testing.T) {
	for _, input := range []string{"", "   ", "(only comment)"} {
		got, err := ParseAddressList(input)
		if err != nil {
			t.Errorf("ParseAddressList(%q) error: %v", input, err)
		}
		if len(got) != 0 {
			t.Errorf("ParseAddressList(%q) = %v, want empty", input, got)
		}
	}
}

func TestParseAddress_MalformedComments(t *testing.T) {
	inputs := []string{
		"(unclosed",
		"(unclosed <a@b.com>",
		"a@ (unclosed",
		"a@b (unclosed",
		"a (unclosed@b.com",
		"a@b (unclosed.c",
		"< (unclosed",
		"<a@b.com> (unclosed",
	}
	for _, input := range inputs {
		if _, err := ParseAddress(input); err == nil {
			t.Errorf("ParseAddress(%q) = nil error, want error", input)
		}
	}
}

func TestParseAddressList_MalformedCommentsAndGroups(t *testing.T) {
	inputs := []string{
		"(unclosed",
		"G:(unclosed",
		"G:; (unclosed",
		"G: a@b.com, (unclosed",
		"G: a@b.com, ",
		"G: a@b.com; (unclosed",
		"Name <bad>",
		"=?x-unknown?B?SsO2aG4=?= <a@b.com>",
	}
	for _, input := range inputs {
		if _, err := ParseAddressList(input); err == nil {
			t.Errorf("ParseAddressList(%q) = nil error, want error", input)
		}
	}
}

func TestParseAddress_DomainAndLocalErrors(t *testing.T) {
	inputs := []string{
		"a@",     // empty domain
		"a@.",    // leading dot in domain
		"a@b..c", // consecutive dots
		"a.",     // trailing dot, no domain
	}
	for _, input := range inputs {
		if _, err := ParseAddress(input); err == nil {
			t.Errorf("ParseAddress(%q) = nil error, want error", input)
		}
	}
}

func TestParseAddress_InvalidEncodedWord(t *testing.T) {
	if _, err := ParseAddress("=?x-unknown?B?SsO2aG4=?= <a@b.com>"); err == nil {
		t.Error("ParseAddress(invalid encoded-word) = nil error, want error")
	}
}

func TestParseAddress_MoreErrorBranches(t *testing.T) {
	inputs := []string{
		"a.(unclosed@b.com",     // malformed comment after obs dot in local-part
		"<user@例え-.jp>",         // IDN error inside angle-addr
		"A.(unclosed <x@y.com>", // malformed comment after obs dot in phrase
	}
	for _, input := range inputs {
		if _, err := ParseAddress(input); err == nil {
			t.Errorf("ParseAddress(%q) = nil error, want error", input)
		}
	}
}

func TestParseAddressList_MoreErrorBranches(t *testing.T) {
	inputs := []string{
		"a@b.com, (unclosed",
		"A.(unclosed <x@y.com>",
	}
	for _, input := range inputs {
		if _, err := ParseAddressList(input); err == nil {
			t.Errorf("ParseAddressList(%q) = nil error, want error", input)
		}
	}
}

func TestParsePath_MoreErrorBranches(t *testing.T) {
	inputs := []struct {
		path      string
		allowUTF8 bool
	}{
		{"<@a,b:user@x.com>", false},         // route segment missing '@'
		{"<@例え.jp:user@example.com>", false}, // non-ASCII route without SMTPUTF8
	}
	for _, tt := range inputs {
		if _, _, err := ParsePath(tt.path, tt.allowUTF8); err == nil {
			t.Errorf("ParsePath(%q) = nil error, want error", tt.path)
		}
	}
}

func TestParseAddrSpec_IPv6EdgeCases(t *testing.T) {
	invalid := []string{
		"user@[IPv6:1:2:3:4:5:6:7:8::]", // too many colons with ::
		"user@[IPv6:12345::]",           // group longer than 4 hex digits
	}
	for _, addr := range invalid {
		if _, err := ParseAddrSpec(addr, false); !errors.Is(err, ErrInvalidIPLiteral) {
			t.Errorf("ParseAddrSpec(%q) error = %v, want %v", addr, err, ErrInvalidIPLiteral)
		}
	}
}
