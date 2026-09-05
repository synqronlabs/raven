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
	if srv.config.EnableSMTPUTF8 {
		t.Fatal("EnableSMTPUTF8 = true, want false by default")
	}
}

func TestServerConfig_DSNMinimumLineLength(t *testing.T) {
	for _, configured := range []int{0, 512, 1035} {
		srv := NewServer(nil, ServerConfig{Domain: "test.example.com", EnableDSN: true, MaxLineLength: configured})
		if got := srv.config.MaxLineLength; got != 1036 {
			t.Fatalf("MaxLineLength with DSN = %d, want 1036", got)
		}
	}

	srv := NewServer(nil, ServerConfig{Domain: "test.example.com", EnableDSN: true, MaxLineLength: 2048})
	if got := srv.config.MaxLineLength; got != 2048 {
		t.Fatalf("explicit larger MaxLineLength = %d, want 2048", got)
	}
}
