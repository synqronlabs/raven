package client

import (
	"testing"
	"time"
)

func TestClientConfig_Defaults(t *testing.T) {
	config := DefaultClientConfig()

	if config.LocalName != "localhost" {
		t.Errorf("Expected LocalName 'localhost', got %q", config.LocalName)
	}

	if config.ConnectTimeout != 30*time.Second {
		t.Errorf("Expected ConnectTimeout 30s, got %v", config.ConnectTimeout)
	}
}

func TestNewDialer(t *testing.T) {
	dialer := NewDialer("smtp.example.com", 587)

	if dialer.Host != "smtp.example.com" {
		t.Errorf("Expected host 'smtp.example.com', got %q", dialer.Host)
	}

	if dialer.Port != 587 {
		t.Errorf("Expected port 587, got %d", dialer.Port)
	}

	if dialer.ConnectTimeout != 30*time.Second {
		t.Errorf("Expected 30s timeout, got %v", dialer.ConnectTimeout)
	}
}

func TestDialerWithLocalAddr(t *testing.T) {
	dialer := NewDialer("smtp.example.com", 587)
	dialer.LocalAddr = "192.168.1.100"

	if dialer.LocalAddr != "192.168.1.100" {
		t.Errorf("Expected LocalAddr '192.168.1.100', got %q", dialer.LocalAddr)
	}
}

func TestClientResponse_Status(t *testing.T) {
	tests := []struct {
		code           int
		isSuccess      bool
		isIntermediate bool
		isTransient    bool
		isPermanent    bool
	}{
		{220, true, false, false, false},
		{250, true, false, false, false},
		{354, false, true, false, false},
		{421, false, false, true, false},
		{450, false, false, true, false},
		{550, false, false, false, true},
		{554, false, false, false, true},
	}

	for _, tt := range tests {
		resp := &ClientResponse{Code: tt.code}

		if resp.IsSuccess() != tt.isSuccess {
			t.Errorf("Code %d: IsSuccess() = %v, want %v", tt.code, resp.IsSuccess(), tt.isSuccess)
		}
		if resp.IsIntermediate() != tt.isIntermediate {
			t.Errorf("Code %d: IsIntermediate() = %v, want %v", tt.code, resp.IsIntermediate(), tt.isIntermediate)
		}
		if resp.IsTransientError() != tt.isTransient {
			t.Errorf("Code %d: IsTransientError() = %v, want %v", tt.code, resp.IsTransientError(), tt.isTransient)
		}
		if resp.IsPermanentError() != tt.isPermanent {
			t.Errorf("Code %d: IsPermanentError() = %v, want %v", tt.code, resp.IsPermanentError(), tt.isPermanent)
		}
	}
}

func TestSMTPError(t *testing.T) {
	err := &SMTPError{
		Code:         550,
		EnhancedCode: "5.1.1",
		Message:      "Mailbox not found",
	}

	if !err.IsPermanent() {
		t.Error("Expected permanent error")
	}

	if err.IsTransient() {
		t.Error("Expected not transient")
	}

	errStr := err.Error()
	if errStr == "" {
		t.Error("Expected non-empty error string")
	}
}

func TestDotStuff(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Hello\r\n", "Hello\r\n"},
		{".hidden\r\n", "..hidden\r\n"},
		{"Hello\r\n.World\r\n", "Hello\r\n..World\r\n"},
		{"..already\r\n", "...already\r\n"},
		{"No dots here\r\n", "No dots here\r\n"},
		{".line1\r\n.line2\r\n", "..line1\r\n..line2\r\n"},
	}

	for _, tt := range tests {
		result := dotStuff([]byte(tt.input))
		if string(result) != tt.expected {
			t.Errorf("dotStuff(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestExtractMessageID(t *testing.T) {
	tests := []struct {
		msg      string
		expected string
	}{
		{"queued as ABC123", "ABC123"},
		{"250 Ok: queued as DEF456", "DEF456"},
		{"Message accepted <123@server.com>", "<123@server.com>"},
		{"id=XYZ789 accepted", "XYZ789"},
		{"", ""},
		{"No id here", ""},
	}

	for _, tt := range tests {
		result := extractMessageID(tt.msg)
		if result != tt.expected {
			t.Errorf("extractMessageID(%q) = %q, want %q", tt.msg, result, tt.expected)
		}
	}
}

func TestResolveLocalAddr(t *testing.T) {
	tests := []struct {
		input   string
		wantIP  string
		wantErr bool
	}{
		{"", "", false},
		{"192.168.1.100", "192.168.1.100", false},
		{"10.0.0.1:0", "10.0.0.1", false},
		{"192.168.1.100:25", "192.168.1.100", false},
		{":25", "", false},
		{"::1", "::1", false},
		{"[::1]:25", "::1", false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		addr, err := resolveLocalAddr(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("resolveLocalAddr(%q): expected error, got nil", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("resolveLocalAddr(%q): unexpected error: %v", tt.input, err)
			continue
		}
		if tt.input == "" {
			if addr != nil {
				t.Errorf("resolveLocalAddr(%q): expected nil, got %v", tt.input, addr)
			}
			continue
		}
		if tt.wantIP != "" && addr.IP.String() != tt.wantIP {
			t.Errorf("resolveLocalAddr(%q): IP = %s, want %s", tt.input, addr.IP.String(), tt.wantIP)
		}
	}
}

func TestClient_SelectAuthMechanism_PrefersPLAIN(t *testing.T) {
	config := DefaultClientConfig()
	config.Auth = &ClientAuth{
		Username: "user",
		Password: "pass",
	}

	client := &Client{config: config}

	tests := []struct {
		name         string
		serverMechs  []string
		expectedMech string
	}{
		{
			name:         "PLAIN and LOGIN offered, PLAIN first",
			serverMechs:  []string{"PLAIN", "LOGIN"},
			expectedMech: "PLAIN",
		},
		{
			name:         "LOGIN and PLAIN offered, LOGIN first (but PLAIN preferred)",
			serverMechs:  []string{"LOGIN", "PLAIN"},
			expectedMech: "PLAIN",
		},
		{
			name:         "Only LOGIN offered",
			serverMechs:  []string{"LOGIN"},
			expectedMech: "LOGIN",
		},
		{
			name:         "Only PLAIN offered",
			serverMechs:  []string{"PLAIN"},
			expectedMech: "PLAIN",
		},
		{
			name:         "Neither supported",
			serverMechs:  []string{"XOAUTH2", "CRAM-MD5"},
			expectedMech: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selected := client.selectAuthMechanism(tt.serverMechs)
			if selected != tt.expectedMech {
				t.Errorf("Expected %q, got %q", tt.expectedMech, selected)
			}
		})
	}
}

func TestClient_SelectAuthMechanism_RespectsClientPreference(t *testing.T) {
	config := DefaultClientConfig()
	config.Auth = &ClientAuth{
		Username:   "user",
		Password:   "pass",
		Mechanisms: []string{"LOGIN", "PLAIN"},
	}

	client := &Client{config: config}

	selected := client.selectAuthMechanism([]string{"PLAIN", "LOGIN"})
	if selected != "LOGIN" {
		t.Errorf("Expected LOGIN (client preference), got %q", selected)
	}
}
