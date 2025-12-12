package mime

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestIsCompositeType(t *testing.T) {
	tests := []struct {
		name      string
		mediaType string
		expected  bool
	}{
		{
			name:      "multipart/mixed",
			mediaType: "multipart/mixed",
			expected:  true,
		},
		{
			name:      "multipart/alternative",
			mediaType: "multipart/alternative",
			expected:  true,
		},
		{
			name:      "multipart/related",
			mediaType: "multipart/related",
			expected:  true,
		},
		{
			name:      "message/rfc822",
			mediaType: "message/rfc822",
			expected:  true,
		},
		{
			name:      "message/partial",
			mediaType: "message/partial",
			expected:  true,
		},
		{
			name:      "text/plain",
			mediaType: "text/plain",
			expected:  false,
		},
		{
			name:      "text/html",
			mediaType: "text/html",
			expected:  false,
		},
		{
			name:      "application/octet-stream",
			mediaType: "application/octet-stream",
			expected:  false,
		},
		{
			name:      "image/png",
			mediaType: "image/png",
			expected:  false,
		},
		{
			name:      "empty string",
			mediaType: "",
			expected:  false,
		},
		{
			name:      "multipart without slash",
			mediaType: "multipart",
			expected:  false,
		},
		{
			name:      "partial match at end",
			mediaType: "text/multipart/mixed",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsCompositeType(tt.mediaType)
			if result != tt.expected {
				t.Errorf("IsCompositeType(%q) = %v, want %v", tt.mediaType, result, tt.expected)
			}
		})
	}
}

func TestValidateCompositeEncoding(t *testing.T) {
	tests := []struct {
		name        string
		mediaType   string
		encoding    ContentTransferEncoding
		expectError bool
	}{
		// Non-composite types - any encoding allowed
		{
			name:        "text/plain with base64",
			mediaType:   "text/plain",
			encoding:    EncodingBase64,
			expectError: false,
		},
		{
			name:        "text/plain with quoted-printable",
			mediaType:   "text/plain",
			encoding:    EncodingQuotedPrintable,
			expectError: false,
		},
		{
			name:        "application/pdf with binary",
			mediaType:   "application/pdf",
			encoding:    EncodingBinary,
			expectError: false,
		},
		// Composite types - only 7bit, 8bit, binary allowed
		{
			name:        "multipart/mixed with 7bit",
			mediaType:   "multipart/mixed",
			encoding:    Encoding7Bit,
			expectError: false,
		},
		{
			name:        "multipart/mixed with 8bit",
			mediaType:   "multipart/mixed",
			encoding:    Encoding8Bit,
			expectError: false,
		},
		{
			name:        "multipart/mixed with binary",
			mediaType:   "multipart/mixed",
			encoding:    EncodingBinary,
			expectError: false,
		},
		{
			name:        "multipart/mixed with empty encoding",
			mediaType:   "multipart/mixed",
			encoding:    "",
			expectError: false, // defaults to 7bit
		},
		{
			name:        "multipart/mixed with base64 (invalid)",
			mediaType:   "multipart/mixed",
			encoding:    EncodingBase64,
			expectError: true,
		},
		{
			name:        "multipart/alternative with quoted-printable (invalid)",
			mediaType:   "multipart/alternative",
			encoding:    EncodingQuotedPrintable,
			expectError: true,
		},
		{
			name:        "message/rfc822 with base64 (invalid)",
			mediaType:   "message/rfc822",
			encoding:    EncodingBase64,
			expectError: true,
		},
		{
			name:        "message/rfc822 with 7bit",
			mediaType:   "message/rfc822",
			encoding:    Encoding7Bit,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCompositeEncoding(tt.mediaType, tt.encoding)
			if tt.expectError && err == nil {
				t.Errorf("ValidateCompositeEncoding(%q, %q) expected error, got nil", tt.mediaType, tt.encoding)
			}
			if !tt.expectError && err != nil {
				t.Errorf("ValidateCompositeEncoding(%q, %q) unexpected error: %v", tt.mediaType, tt.encoding, err)
			}
			if tt.expectError && err != ErrInvalidCompositeEncoding {
				t.Errorf("ValidateCompositeEncoding(%q, %q) error = %v, want %v", tt.mediaType, tt.encoding, err, ErrInvalidCompositeEncoding)
			}
		})
	}
}

func TestPart_IsMultipart(t *testing.T) {
	tests := []struct {
		name     string
		part     Part
		expected bool
	}{
		{
			name: "multipart/mixed with parts",
			part: Part{
				ContentType: "multipart/mixed",
				Parts:       []*Part{{ContentType: "text/plain"}},
			},
			expected: true,
		},
		{
			name: "multipart/alternative with parts",
			part: Part{
				ContentType: "multipart/alternative",
				Parts:       []*Part{{ContentType: "text/plain"}, {ContentType: "text/html"}},
			},
			expected: true,
		},
		{
			name: "multipart/mixed without parts",
			part: Part{
				ContentType: "multipart/mixed",
				Parts:       nil,
			},
			expected: false,
		},
		{
			name: "multipart/mixed with empty parts slice",
			part: Part{
				ContentType: "multipart/mixed",
				Parts:       []*Part{},
			},
			expected: false,
		},
		{
			name: "text/plain (non-multipart)",
			part: Part{
				ContentType: "text/plain",
				Body:        []byte("Hello"),
			},
			expected: false,
		},
		{
			name: "text/plain with parts (unusual but should be false)",
			part: Part{
				ContentType: "text/plain",
				Parts:       []*Part{{ContentType: "text/plain"}},
			},
			expected: false,
		},
		{
			name:     "empty part",
			part:     Part{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.part.IsMultipart()
			if result != tt.expected {
				t.Errorf("Part.IsMultipart() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestPart_ToJSON(t *testing.T) {
	tests := []struct {
		name    string
		part    Part
		wantErr bool
	}{
		{
			name: "simple text part",
			part: Part{
				ContentType:             "text/plain",
				Charset:                 "utf-8",
				ContentTransferEncoding: Encoding7Bit,
				Body:                    []byte("Hello, World!"),
			},
			wantErr: false,
		},
		{
			name: "part with headers",
			part: Part{
				ContentType: "text/plain",
				Headers: []Header{
					{Name: "From", Value: "sender@example.com"},
					{Name: "To", Value: "recipient@example.com"},
				},
				Body: []byte("Test message"),
			},
			wantErr: false,
		},
		{
			name: "attachment part",
			part: Part{
				ContentType:             "application/pdf",
				ContentTransferEncoding: EncodingBase64,
				Filename:                "document.pdf",
				Body:                    []byte("PDF content"),
			},
			wantErr: false,
		},
		{
			name: "part with content ID",
			part: Part{
				ContentType: "image/png",
				ContentID:   "image001",
				Body:        []byte("PNG data"),
			},
			wantErr: false,
		},
		{
			name:    "empty part",
			part:    Part{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.part.ToJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("Part.ToJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				// Verify it's valid JSON by unmarshaling
				var decoded Part
				if err := json.Unmarshal(data, &decoded); err != nil {
					t.Errorf("Part.ToJSON() produced invalid JSON: %v", err)
				}
			}
		})
	}
}

func TestPart_ToJSONIndent(t *testing.T) {
	part := Part{
		ContentType:             "text/plain",
		Charset:                 "utf-8",
		ContentTransferEncoding: Encoding7Bit,
		Body:                    []byte("Test"),
	}

	data, err := part.ToJSONIndent()
	if err != nil {
		t.Errorf("Part.ToJSONIndent() unexpected error: %v", err)
		return
	}

	// Verify it's valid JSON
	var decoded Part
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Errorf("Part.ToJSONIndent() produced invalid JSON: %v", err)
	}

	// Verify it's indented (should contain newlines)
	if len(data) > 0 && !containsNewline(data) {
		t.Errorf("Part.ToJSONIndent() should produce indented output with newlines")
	}
}

func containsNewline(data []byte) bool {
	return slices.Contains(data, '\n')
}

func TestHeader(t *testing.T) {
	// Test Header struct JSON serialization
	header := Header{
		Name:  "Content-Type",
		Value: "text/plain; charset=utf-8",
	}

	data, err := json.Marshal(header)
	if err != nil {
		t.Errorf("Header JSON marshal error: %v", err)
		return
	}

	var decoded Header
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Errorf("Header JSON unmarshal error: %v", err)
		return
	}

	if decoded.Name != header.Name {
		t.Errorf("Header.Name = %q, want %q", decoded.Name, header.Name)
	}
	if decoded.Value != header.Value {
		t.Errorf("Header.Value = %q, want %q", decoded.Value, header.Value)
	}
}

func TestContentTransferEncodingConstants(t *testing.T) {
	// Verify encoding constants have expected values
	tests := []struct {
		encoding ContentTransferEncoding
		expected string
	}{
		{Encoding7Bit, "7bit"},
		{Encoding8Bit, "8bit"},
		{EncodingBinary, "binary"},
		{EncodingQuotedPrintable, "quoted-printable"},
		{EncodingBase64, "base64"},
	}

	for _, tt := range tests {
		if string(tt.encoding) != tt.expected {
			t.Errorf("ContentTransferEncoding %v = %q, want %q", tt.encoding, string(tt.encoding), tt.expected)
		}
	}
}

func TestValidCompositeEncodings(t *testing.T) {
	// Verify the valid composite encodings map
	validEncodings := []ContentTransferEncoding{Encoding7Bit, Encoding8Bit, EncodingBinary}
	invalidEncodings := []ContentTransferEncoding{EncodingQuotedPrintable, EncodingBase64}

	for _, enc := range validEncodings {
		if !ValidCompositeEncodings[enc] {
			t.Errorf("ValidCompositeEncodings[%q] = false, want true", enc)
		}
	}

	for _, enc := range invalidEncodings {
		if ValidCompositeEncodings[enc] {
			t.Errorf("ValidCompositeEncodings[%q] = true, want false", enc)
		}
	}
}
