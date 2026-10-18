package server

import (
	"testing"
)

func TestExtractPathAndParams_SourceRoutes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantPath string
		wantParm string
	}{
		{"no source route", "<user@example.com>", "user@example.com", ""},
		{"single relay", "<@relay:user@example.com>", "user@example.com", ""},
		{"multiple relays", "<@a,@b:user@example.com>", "user@example.com", ""},
		{"source route with params", "<@relay:user@example.com> SIZE=100", "user@example.com", "SIZE=100"},
		{"null path", "<>", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, params, err := extractPathAndParams(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if path != tt.wantPath {
				t.Errorf("path = %q, want %q", path, tt.wantPath)
			}
			if params != tt.wantParm {
				t.Errorf("params = %q, want %q", params, tt.wantParm)
			}
		})
	}
}
