package smtppath

import (
	"errors"
	"testing"
)

func TestSplit(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantPath   string
		wantParams string
	}{
		{"simple", "<user@example.com>", "user@example.com", ""},
		{"params", "<user@example.com> SIZE=100 BODY=8BITMIME", "user@example.com", "SIZE=100 BODY=8BITMIME"},
		{"null", "<>", "", ""},
		{"null with params", "<> SIZE=1", "", "SIZE=1"},
		{"quoted greater-than", `<"a>b"@example.com>`, `"a>b"@example.com`, ""},
		{"quoted escaped quote then greater-than", `<"a\">b"@example.com>`, `"a\">b"@example.com`, ""},
		{"general literal greater-than", `<user@[TAG:a>b]>`, `user@[TAG:a>b]`, ""},
		{"source route", "<@relay:user@example.com>", "@relay:user@example.com", ""},
		{"source route with params", "<@a,@b:user@example.com> SIZE=5", "@a,@b:user@example.com", "SIZE=5"},
		{"source route IPv6 literal", "<@relay:user@[IPv6:2001:db8::1]>", "@relay:user@[IPv6:2001:db8::1]", ""},
		{"quoted colon after route", `<@relay:"a:b"@example.com>`, `@relay:"a:b"@example.com`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, params, err := Split(tt.input)
			if err != nil {
				t.Fatalf("Split(%q) error: %v", tt.input, err)
			}
			if path != tt.wantPath {
				t.Errorf("path = %q, want %q", path, tt.wantPath)
			}
			if params != tt.wantParams {
				t.Errorf("params = %q, want %q", params, tt.wantParams)
			}
		})
	}
}

func TestSplitErrors(t *testing.T) {
	tests := []struct {
		input   string
		wantErr error
	}{
		{"", ErrEmpty},
		{"   ", ErrEmpty},
		{"user@example.com", ErrMissingBrackets},
		{"<user@example.com", ErrMissingBrackets},
		{`<"unterminated>`, ErrMissingBrackets},
		{"<user@[IPv6:2001:db8::1>", ErrMissingBrackets},
	}
	for _, tt := range tests {
		if _, _, err := Split(tt.input); !errors.Is(err, tt.wantErr) {
			t.Errorf("Split(%q) error = %v, want %v", tt.input, err, tt.wantErr)
		}
	}
}

func TestSplitSourceRoute(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantRout string
		wantRest string
		wantOK   bool
	}{
		{"none", "user@example.com", "", "user@example.com", false},
		{"single", "@relay:user@example.com", "@relay", "user@example.com", true},
		{"multiple", "@a,@b:user@example.com", "@a,@b", "user@example.com", true},
		{"IPv6 route literal", "@[IPv6:2001:db8::1]:user@example.com", "@[IPv6:2001:db8::1]", "user@example.com", true},
		{"general literal route", "@[TAG:a:b]:user@example.com", "@[TAG:a:b]", "user@example.com", true},
		{"quoted colon in address", `@relay:"a:b"@example.com`, "@relay", `"a:b"@example.com`, true},
		{"missing terminator", "@relay", "", "@relay", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route, rest, ok := SplitSourceRoute(tt.path)
			if route != tt.wantRout || rest != tt.wantRest || ok != tt.wantOK {
				t.Errorf("SplitSourceRoute(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.path, route, rest, ok, tt.wantRout, tt.wantRest, tt.wantOK)
			}
		})
	}
}
