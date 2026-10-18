package provider

import (
	"errors"
	"strings"
	"testing"

	"github.com/synqronlabs/raven/mail"
)

func TestGmailEquivalence(t *testing.T) {
	gmail := Gmail()

	same := [][2]string{
		{"first.last@gmail.com", "firstlast@gmail.com"},
		{"first.last+tag@gmail.com", "firstlast@gmail.com"},
		{"First.Last@GMAIL.com", "firstlast@gmail.com"},
		{"firstlast@googlemail.com", "firstlast@gmail.com"},
		{"first.last+tag@googlemail.com", "firstlast@gmail.com"},
		{"John <first.last@gmail.com>", "firstlast@gmail.com"},
	}
	for _, pair := range same {
		ok, err := gmail.Equivalent(pair[0], pair[1])
		if err != nil {
			t.Fatalf("Equivalent(%q, %q) error: %v", pair[0], pair[1], err)
		}
		if !ok {
			t.Errorf("Equivalent(%q, %q) = false, want true", pair[0], pair[1])
		}
	}

	different := [][2]string{
		{"firstlast@gmail.com", "firstlast2@gmail.com"},
		{"first.last@gmail.com", "firstlast@yahoo.com"},
	}
	for _, pair := range different {
		ok, err := gmail.Equivalent(pair[0], pair[1])
		if err != nil {
			t.Fatalf("Equivalent(%q, %q) error: %v", pair[0], pair[1], err)
		}
		if ok {
			t.Errorf("Equivalent(%q, %q) = true, want false", pair[0], pair[1])
		}
	}
}

func TestProviderEquivalence(t *testing.T) {
	tests := []struct {
		name    string
		profile *Profile
		a, b    string
		want    bool
	}{
		{"outlook keeps dots", Outlook(), "first.last@outlook.com", "firstlast@outlook.com", false},
		{"outlook strips plus", Outlook(), "first.last+tag@outlook.com", "first.last@outlook.com", true},
		{"outlook domains differ", Outlook(), "user@outlook.com", "user@hotmail.com", false},
		{"yahoo strips dash", Yahoo(), "user-tag@yahoo.com", "user@yahoo.com", true},
		{"yahoo keeps dots", Yahoo(), "first.last@yahoo.com", "firstlast@yahoo.com", false},
		{"icloud me alias", ICloud(), "user@me.com", "user@icloud.com", true},
		{"icloud mac alias", ICloud(), "user@mac.com", "user@icloud.com", true},
		{"proton alias", Proton(), "user@proton.me", "user@protonmail.com", true},
		{"fastmail alias", Fastmail(), "user@fastmail.fm", "user@fastmail.com", true},
		{"gmx plus", GMX(), "user+tag@gmx.net", "user@gmx.com", false},
		{"zoho plus", Zoho(), "user+tag@zoho.com", "user@zoho.com", true},
		{"generic case-insensitive", Default(), "User@Example.com", "user@example.com", true},
		{"generic keeps dots", Default(), "first.last@example.com", "firstlast@example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.profile.Equivalent(tt.a, tt.b)
			if err != nil {
				t.Fatalf("Equivalent error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Equivalent(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCanonical(t *testing.T) {
	tests := []struct {
		profile *Profile
		input   string
		want    string
	}{
		{Gmail(), "First.Last+tag@googlemail.com", "firstlast@gmail.com"},
		{Outlook(), "First.Last+tag@outlook.com", "first.last@outlook.com"},
		{Yahoo(), "User-Tag@Yahoo.com", "user@yahoo.com"},
		{ICloud(), "user@me.com", "user@icloud.com"},
		{Default(), "User.Name@Example.COM", "user.name@example.com"},
		{nil, "User.Name@Example.COM", "user.name@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := tt.profile.CanonicalString(tt.input)
			if err != nil {
				t.Fatalf("CanonicalString error: %v", err)
			}
			if got != tt.want {
				t.Errorf("CanonicalString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}

	if _, err := Gmail().CanonicalString("not-an-address"); err == nil {
		t.Error("CanonicalString(invalid) = nil error, want error")
	}
}

func TestSplitSubaddress(t *testing.T) {
	tests := []struct {
		profile  *Profile
		input    string
		wantBase string
		wantTag  string
	}{
		{Gmail(), "user+tag@gmail.com", "user", "tag"},
		{Gmail(), "user@gmail.com", "user", ""},
		{Yahoo(), "user-tag@yahoo.com", "user", "tag"},
		{Outlook(), "user+tag+more@outlook.com", "user", "tag+more"},
		{Default(), "user+tag@example.com", "user+tag", ""},
	}
	for _, tt := range tests {
		m, err := mail.ParseAddress(tt.input)
		if err != nil {
			t.Fatalf("ParseAddress(%q): %v", tt.input, err)
		}
		base, tag := tt.profile.SplitSubaddress(m)
		if base != tt.wantBase || tag != tt.wantTag {
			t.Errorf("SplitSubaddress(%q) = (%q, %q), want (%q, %q)", tt.input, base, tag, tt.wantBase, tt.wantTag)
		}
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		profile *Profile
		addr    string
		wantErr error
	}{
		{"gmail accepts normal", Gmail(), "user@gmail.com", nil},
		{"gmail rejects ip literal", Gmail(), "user@[192.0.2.1]", ErrIPLiteralDomain},
		{"gmail rejects ipv6 literal", Gmail(), "user@[IPv6:2001:db8::1]", ErrIPLiteralDomain},
		{"gmail rejects quoted local", Gmail(), `"user name"@gmail.com`, ErrQuotedLocalPart},
		{"gmail rejects utf8 local", Gmail(), "用户@gmail.com", ErrSMTPUTF8},
		{"gmail rejects idn domain", Gmail(), "user@例え.jp", ErrSMTPUTF8},
		{"gmail allows utf8 display name", Gmail(), "Jöhn <john@gmail.com>", nil},
		{"invalid address", Gmail(), "not-an-address", mail.ErrAddressMissingAt},
		{"nil profile accepts", nil, "user@example.com", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.profile.Validate(tt.addr)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate(%q) = %v, want nil", tt.addr, err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate(%q) = %v, want %v", tt.addr, err, tt.wantErr)
			}
		})
	}
}

func TestValidateCustomLimits(t *testing.T) {
	profile := &Profile{
		Name:                 "Custom",
		AllowIPLiteralDomain: true,
		AllowQuotedLocalPart: true,
		AllowSMTPUTF8:        true,
		MaxLocalPart:         5,
		MaxAddressLength:     20,
	}

	if err := profile.Validate("username@example.com"); !errors.Is(err, ErrLocalPartTooLong) {
		t.Errorf("Validate = %v, want ErrLocalPartTooLong", err)
	}
	if err := profile.Validate("user@[192.0.2.1]"); err != nil {
		t.Errorf("Validate IP literal = %v, want nil", err)
	}
	if err := profile.Validate(`"a b"@x.com`); err != nil {
		t.Errorf("Validate quoted = %v, want nil", err)
	}
	if err := profile.Validate("abc@verylongdomainname.example"); !errors.Is(err, ErrAddressTooLong) {
		t.Errorf("Validate = %v, want ErrAddressTooLong", err)
	}
	if !profile.Accepts("abc@x.co") {
		t.Error("Accepts(valid) = false, want true")
	}
	if profile.Accepts("username@example.com") {
		t.Error("Accepts(too long) = true, want false")
	}
}

func TestServes(t *testing.T) {
	gmail := Gmail()
	for _, domain := range []string{"gmail.com", "GMAIL.COM", "googlemail.com", "gmail.com."} {
		if !gmail.Serves(domain) {
			t.Errorf("Gmail().Serves(%q) = false, want true", domain)
		}
	}
	if gmail.Serves("yahoo.com") {
		t.Error("Gmail().Serves(yahoo.com) = true, want false")
	}
}

func TestByDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"gmail.com", "Gmail"},
		{"GOOGLEMAIL.COM", "Gmail"},
		{"outlook.com", "Outlook"},
		{"hotmail.com", "Outlook"},
		{"me.com", "iCloud"},
		{"proton.me", "Proton Mail"},
		{"unknown.example", ""},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			p, ok := ByDomain(tt.domain)
			if tt.want == "" {
				if ok {
					t.Fatalf("ByDomain(%q) = %q, want not found", tt.domain, p.Name)
				}
				return
			}
			if !ok {
				t.Fatalf("ByDomain(%q) not found", tt.domain)
			}
			if p.Name != tt.want {
				t.Errorf("ByDomain(%q).Name = %q, want %q", tt.domain, p.Name, tt.want)
			}
		})
	}
}

func TestByDomainReturnsCopy(t *testing.T) {
	p, ok := ByDomain("gmail.com")
	if !ok {
		t.Fatal("gmail.com not found")
	}
	p.Name = "Mutated"
	p.Domains[0] = "mutated.example"

	again, _ := ByDomain("gmail.com")
	if again.Name != "Gmail" || again.Domains[0] != "gmail.com" {
		t.Errorf("mutation leaked: %+v", again)
	}
}

func TestProfiles(t *testing.T) {
	profiles := Profiles()
	if len(profiles) < 9 {
		t.Fatalf("Profiles() returned %d profiles, want at least 9", len(profiles))
	}
	names := make([]string, len(profiles))
	for i, p := range profiles {
		names[i] = p.Name
	}
	for _, want := range []string{"Gmail", "Outlook", "Yahoo", "iCloud", "Proton Mail", "Fastmail", "GMX", "Zoho Mail", "AOL"} {
		if !strings.Contains(strings.Join(names, ","), want) {
			t.Errorf("Profiles() missing %q", want)
		}
	}
}

func TestRegisterCustom(t *testing.T) {
	custom := &Profile{
		Name:                   "Example Corp",
		Domains:                []string{"example-corp.test"},
		SubaddressSeparator:    '+',
		CaseSensitiveLocalPart: false,
	}
	if err := Register(custom); err != nil {
		t.Fatalf("Register: %v", err)
	}

	p, ok := ByDomain("example-corp.test")
	if !ok || p.Name != "Example Corp" {
		t.Fatalf("ByDomain after Register = %+v, %v", p, ok)
	}

	// Re-registering the same profile is a no-op.
	if err := Register(custom); err != nil {
		t.Errorf("Register same profile = %v, want nil", err)
	}

	// A different profile claiming the same domain is rejected.
	conflict := &Profile{Name: "Conflict", Domains: []string{"example-corp.test"}}
	if err := Register(conflict); err == nil {
		t.Error("Register conflicting domain = nil error, want error")
	}
	if err := Register(nil); err == nil {
		t.Error("Register(nil) = nil error, want error")
	}
}

func TestPackageLevelCanonicalAndEquivalent(t *testing.T) {
	got, err := Canonical("First.Last+tag@googlemail.com")
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	if got != "firstlast@gmail.com" {
		t.Errorf("Canonical = %q, want firstlast@gmail.com", got)
	}

	ok, err := Equivalent("first.last+tag@gmail.com", "firstlast@googlemail.com")
	if err != nil || !ok {
		t.Errorf("Equivalent = %v, %v, want true, nil", ok, err)
	}

	// Unknown domains fall back to the generic profile.
	ok, err = Equivalent("User@unknown.test", "user@unknown.test")
	if err != nil || !ok {
		t.Errorf("Equivalent unknown = %v, %v, want true, nil", ok, err)
	}

	if _, err := Canonical("bad"); err == nil {
		t.Error("Canonical(bad) = nil error, want error")
	}
}

func TestClone(t *testing.T) {
	if got := (*Profile)(nil).Clone(); got != nil {
		t.Errorf("nil Clone = %+v, want nil", got)
	}

	original := &Profile{
		Name:          "Original",
		Domains:       []string{"a.test"},
		DomainAliases: map[string]string{"b.test": "a.test"},
	}
	clone := original.Clone()
	clone.Name = "Clone"
	clone.Domains[0] = "changed.test"
	clone.DomainAliases["b.test"] = "changed.test"

	if original.Name != "Original" || original.Domains[0] != "a.test" || original.DomainAliases["b.test"] != "a.test" {
		t.Errorf("Clone mutated original: %+v", original)
	}
}

func TestZeroValueProfile(t *testing.T) {
	var p Profile
	if p.Serves("example.com") {
		t.Error("zero-value Serves(example.com) = true, want false")
	}
	ok, err := p.Equivalent("User@Example.com", "user@example.com")
	if err != nil || !ok {
		t.Errorf("zero-value Equivalent = %v, %v, want true, nil", ok, err)
	}
	if err := p.Validate("user@example.com"); err != nil {
		t.Errorf("zero-value Validate = %v, want nil", err)
	}
}

func TestNilProfile(t *testing.T) {
	var p *Profile
	if p.Serves("gmail.com") {
		t.Error("nil Serves = true, want false")
	}
	if _, tag := p.SplitSubaddress(mail.MailboxAddress{LocalPart: "a+b"}); tag != "" {
		t.Errorf("nil SplitSubaddress tag = %q, want empty", tag)
	}
	if err := p.Validate("user@example.com"); err != nil {
		t.Errorf("nil Validate = %v, want nil", err)
	}
}

func TestProfileEquivalentErrors(t *testing.T) {
	gmail := Gmail()
	if _, err := gmail.Equivalent("not-an-address", "user@gmail.com"); err == nil {
		t.Error("Equivalent(invalid, valid) = nil error, want error")
	}
	if _, err := gmail.Equivalent("user@gmail.com", "not-an-address"); err == nil {
		t.Error("Equivalent(valid, invalid) = nil error, want error")
	}
}

func TestPackageLevelEquivalentCrossProvider(t *testing.T) {
	// Different known providers fall back to the generic profile.
	ok, err := Equivalent("User@gmail.com", "user@yahoo.com")
	if err != nil || ok {
		t.Errorf("Equivalent(gmail, yahoo) = %v, %v, want false, nil", ok, err)
	}

	// One known, one unknown also falls back to generic.
	ok, err = Equivalent("User@gmail.com", "user@unknown.test")
	if err != nil || ok {
		t.Errorf("Equivalent(gmail, unknown) = %v, %v, want false, nil", ok, err)
	}
	ok, err = Equivalent("User@unknown.test", "user@gmail.com")
	if err != nil || ok {
		t.Errorf("Equivalent(unknown, gmail) = %v, %v, want false, nil", ok, err)
	}

	if _, err := Canonical("User@Unknown.Test"); err != nil {
		t.Errorf("Canonical(unknown) error: %v", err)
	}
}

func TestAOLProfile(t *testing.T) {
	aol := AOL()
	if aol.Name != "AOL" {
		t.Errorf("AOL().Name = %q", aol.Name)
	}
	ok, err := aol.Equivalent("user+tag@aol.com", "user@aol.com")
	if err != nil || !ok {
		t.Errorf("AOL Equivalent = %v, %v, want true, nil", ok, err)
	}
}

func TestAllDomainsDeduplicates(t *testing.T) {
	p := &Profile{
		Domains:       []string{"a.test", "a.test", "B.TEST"},
		DomainAliases: map[string]string{"a.test": "a.test"},
	}
	domains := p.allDomains()
	seen := map[string]int{}
	for _, d := range domains {
		seen[d]++
	}
	if seen["a.test"] != 1 {
		t.Errorf("allDomains() = %v, want a.test once", domains)
	}
	if seen["b.test"] != 1 {
		t.Errorf("allDomains() = %v, want b.test once", domains)
	}
}

func FuzzProviderAddress(f *testing.F) {
	f.Add("First.Last+tag@googlemail.com")
	f.Add("user@[IPv6:2001:db8::1]")
	f.Add("Jane Doe <jane@example.com>")
	f.Add("not-an-address")

	f.Fuzz(func(t *testing.T, s string) {
		for _, p := range Profiles() {
			_, _ = p.CanonicalString(s)
			_ = p.Validate(s)
			_, _ = p.Equivalent(s, s)
		}
		_, _ = Canonical(s)
		_, _ = Equivalent(s, s)
	})
}
