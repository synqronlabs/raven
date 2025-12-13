package raven

import (
	"fmt"
)

// ExtensionType categorizes SMTP extensions by their nature.
type ExtensionType int

const (
	// ExtTypeIntrinsic extensions are always enabled and fundamental to modern SMTP.
	// These include: ENHANCEDSTATUSCODES, PIPELINING, 8BITMIME, SMTPUTF8.
	ExtTypeIntrinsic ExtensionType = iota

	// ExtTypeOptIn extensions must be explicitly enabled.
	// These include: DSN, CHUNKING/BINARYMIME, AUTH, STARTTLS.
	ExtTypeOptIn
)

// ExtensionInfo provides metadata about an SMTP extension.
type ExtensionInfo struct {
	Name         Extension
	Type         ExtensionType
	RFC          string
	Description  string
	Dependencies []Extension
}

// IntrinsicExtensions are always enabled.
var IntrinsicExtensions = []ExtensionInfo{
	{ExtEnhancedStatusCodes, ExtTypeIntrinsic, "RFC 2034", "Enhanced status codes", nil},
	{Ext8BitMIME, ExtTypeIntrinsic, "RFC 6152", "8-bit MIME transport", nil},
	{ExtSMTPUTF8, ExtTypeIntrinsic, "RFC 6531", "Internationalized email", []Extension{Ext8BitMIME}},
	{ExtPipelining, ExtTypeIntrinsic, "RFC 2920", "Command pipelining", nil},
	{ExtRequireTLS, ExtTypeIntrinsic, "RFC 8689", "Require TLS for transmission", []Extension{ExtSTARTTLS}},
}

// OptInExtensions require explicit configuration.
var OptInExtensions = []ExtensionInfo{
	{ExtSTARTTLS, ExtTypeOptIn, "RFC 3207", "TLS encryption upgrade", nil},
	{ExtAuth, ExtTypeOptIn, "RFC 4954", "SMTP authentication", nil},
	{ExtSize, ExtTypeOptIn, "RFC 1870", "Message size declaration", nil},
	{ExtDSN, ExtTypeOptIn, "RFC 3461", "Delivery Status Notifications", nil},
	{ExtChunking, ExtTypeOptIn, "RFC 3030", "Chunked message transfer", nil},
	{ExtBinaryMIME, ExtTypeOptIn, "RFC 3030", "Binary MIME transfer", []Extension{ExtChunking}},
}

// DSN enables Delivery Status Notifications (RFC 3461).
func DSN() ExtensionConfig {
	return ExtensionConfig{
		Name:    ExtDSN,
		Enabled: true,
	}
}

// Chunking enables CHUNKING/BDAT (RFC 3030).
func Chunking() ExtensionConfig {
	return ExtensionConfig{
		Name:    ExtChunking,
		Enabled: true,
	}
}

// ChunkingWithOptions enables CHUNKING with custom options.
func ChunkingWithOptions(opts ChunkingOptions) ExtensionConfig {
	return ExtensionConfig{
		Name:    ExtChunking,
		Enabled: true,
		Params: map[string]any{
			"maxChunkSize": opts.MaxChunkSize,
		},
	}
}

// ChunkingOptions holds configuration for CHUNKING.
type ChunkingOptions struct {
	MaxChunkSize int64 // Maximum BDAT chunk size (0 = no limit)
}

// Size enables SIZE (RFC 1870). If maxSize is 0, no limit is advertised.
func Size(maxSize int64) ExtensionConfig {
	return ExtensionConfig{
		Name:    ExtSize,
		Enabled: true,
		Params: map[string]any{
			"maxSize": maxSize,
		},
	}
}

// WithAllExtensions returns all opt-in extensions.
func WithAllExtensions() []ExtensionConfig {
	return []ExtensionConfig{
		DSN(),
		Chunking(),
	}
}

// WithSubmissionExtensions returns extensions suitable for a mail submission agent (MSA).
func WithSubmissionExtensions() []ExtensionConfig {
	return []ExtensionConfig{
		// DSN is useful for submission
		DSN(),
	}
}

// ValidateExtensions checks that all extension dependencies are met.
func ValidateExtensions(extensions []ExtensionConfig) error {
	enabled := make(map[Extension]bool)
	for _, ext := range extensions {
		if ext.Enabled {
			enabled[ext.Name] = true
		}
	}

	for _, ext := range IntrinsicExtensions {
		enabled[ext.Name] = true
	}

	for _, ext := range OptInExtensions {
		if enabled[ext.Name] {
			for _, dep := range ext.Dependencies {
				if !enabled[dep] {
					return fmt.Errorf("extension %s requires %s", ext.Name, dep)
				}
			}
		}
	}

	return nil
}
