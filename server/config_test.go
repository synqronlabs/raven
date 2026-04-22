package server

import "testing"

func TestServerConfig_DefaultLineLimits(t *testing.T) {
	srv := NewServer(nil, ServerConfig{Domain: "test.example.com"})

	if got := srv.config.MaxLineLength; got != 512 {
		t.Fatalf("MaxLineLength = %d, want 512", got)
	}
	if got := srv.config.MaxAuthLineLength; got != 12288 {
		t.Fatalf("MaxAuthLineLength = %d, want 12288", got)
	}
}
