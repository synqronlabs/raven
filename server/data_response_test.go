package server

import (
	"strings"
	"testing"
)

func TestValidDataSuccessResponse(t *testing.T) {
	maxResponseLength := maxSMTPReplyLineOctets - len("250 ") - len(customDataSuccessPrefix) - len("\r\n")
	tests := []struct {
		name     string
		response string
		want     bool
	}{
		{name: "printable ASCII", response: "message_ref=abc-123", want: true},
		{name: "horizontal tab", response: "message_ref=abc\tqueued", want: true},
		{name: "empty", response: "", want: false},
		{name: "carriage return", response: "message_ref=abc\r", want: false},
		{name: "line feed", response: "message_ref=abc\n", want: false},
		{name: "nul", response: "message_ref=abc\x00", want: false},
		{name: "delete", response: "message_ref=abc\x7f", want: false},
		{name: "non-ASCII", response: "message_ref=caf\u00e9", want: false},
		{name: "maximum length", response: strings.Repeat("a", maxResponseLength), want: true},
		{name: "too long", response: strings.Repeat("a", maxResponseLength+1), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validDataSuccessResponse(tt.response); got != tt.want {
				t.Fatalf("validDataSuccessResponse(%q) = %v, want %v", tt.response, got, tt.want)
			}
		})
	}
}
