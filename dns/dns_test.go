package dns

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestErrorHelpers(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		isNotFound bool
		isTimeout  bool
		isServFail bool
		isTemp     bool
	}{
		{
			name:       "not found error",
			err:        ErrDNSNotFound,
			isNotFound: true,
		},
		{
			name:      "timeout error",
			err:       ErrDNSTimeout,
			isTimeout: true,
			isTemp:    true,
		},
		{
			name:       "server failure",
			err:        ErrDNSServFail,
			isServFail: true,
			isTemp:     true,
		},
		{
			name: "wrapped not found",
			err:  errors.New("wrapper: " + ErrDNSNotFound.Error()),
		},
		{
			name: "nil error",
			err:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotFound(tt.err); got != tt.isNotFound {
				t.Errorf("IsNotFound() = %v, want %v", got, tt.isNotFound)
			}
			if got := IsTimeout(tt.err); got != tt.isTimeout {
				t.Errorf("IsTimeout() = %v, want %v", got, tt.isTimeout)
			}
			if got := IsServFail(tt.err); got != tt.isServFail {
				t.Errorf("IsServFail() = %v, want %v", got, tt.isServFail)
			}
			if got := IsTemporary(tt.err); got != tt.isTemp {
				t.Errorf("IsTemporary() = %v, want %v", got, tt.isTemp)
			}
		})
	}
}

func TestResultGeneric(t *testing.T) {
	// Test string result
	strResult := Result[string]{
		Records:   []string{"txt1", "txt2"},
		Authentic: true,
	}
	if len(strResult.Records) != 2 {
		t.Errorf("expected 2 records, got %d", len(strResult.Records))
	}
	if !strResult.Authentic {
		t.Error("expected authentic to be true")
	}

	// Test IP result
	ipResult := Result[net.IP]{
		Records:   []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")},
		Authentic: false,
	}
	if len(ipResult.Records) != 2 {
		t.Errorf("expected 2 IPs, got %d", len(ipResult.Records))
	}
	if ipResult.Authentic {
		t.Error("expected authentic to be false")
	}
}

// TestResolverInterface verifies that our types implement Resolver
func TestResolverInterface(t *testing.T) {
	var _ Resolver = (*DNSResolver)(nil)
	var _ Resolver = (*StdResolver)(nil)
}

func TestNewResolverDefaults(t *testing.T) {
	r := NewResolver(ResolverConfig{})

	// Should have default timeout
	if r.config.Timeout == 0 {
		t.Error("expected default timeout to be set")
	}

	// Should have default retries
	if r.config.Retries == 0 {
		t.Error("expected default retries to be set")
	}

	// Should have nameservers (either from system or fallback)
	if len(r.config.Nameservers) == 0 {
		t.Error("expected nameservers to be set")
	}
}

func TestNewStdResolver(t *testing.T) {
	r := NewStdResolver()
	if r == nil {
		t.Error("expected non-nil resolver")
	}
	if r.resolver == nil {
		t.Error("expected non-nil internal resolver")
	}
}

// Integration test - skip if no network
func TestDNSResolverIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	r := NewResolver(ResolverConfig{
		Nameservers: []string{"8.8.8.8:53"},
		DNSSEC:      false,
	})

	ctx := context.Background()

	// Test TXT lookup for a well-known domain
	txtResult, err := r.LookupTXT(ctx, "google.com")
	if err != nil {
		t.Logf("TXT lookup failed (may be expected): %v", err)
	} else if len(txtResult.Records) == 0 {
		t.Log("No TXT records found for google.com")
	}

	// Test A lookup
	ipResult, err := r.LookupIP(ctx, "google.com")
	if err != nil {
		t.Errorf("IP lookup failed: %v", err)
	} else if len(ipResult.Records) == 0 {
		t.Error("Expected IP records for google.com")
	}

	// Test MX lookup
	mxResult, err := r.LookupMX(ctx, "google.com")
	if err != nil {
		t.Errorf("MX lookup failed: %v", err)
	} else if len(mxResult.Records) == 0 {
		t.Error("Expected MX records for google.com")
	}
}

func TestStdResolverIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	r := NewStdResolver()
	ctx := context.Background()

	// Test A lookup
	ipResult, err := r.LookupIP(ctx, "google.com")
	if err != nil {
		t.Errorf("IP lookup failed: %v", err)
	} else if len(ipResult.Records) == 0 {
		t.Error("Expected IP records for google.com")
	}
	if ipResult.Authentic {
		t.Error("StdResolver should never return Authentic=true")
	}
}
