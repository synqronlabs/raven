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
	// Name is the extension keyword (e.g., "DSN", "CHUNKING").
	Name Extension

	// Type indicates whether the extension is intrinsic or opt-in.
	Type ExtensionType

	// RFC is the defining RFC number(s).
	RFC string

	// Description provides a brief explanation of the extension.
	Description string

	// Dependencies lists other extensions this one requires.
	Dependencies []Extension
}

// IntrinsicExtensions are always enabled on any Raven server.
// These represent fundamental modern SMTP capabilities.
var IntrinsicExtensions = []ExtensionInfo{
	{
		Name:        ExtEnhancedStatusCodes,
		Type:        ExtTypeIntrinsic,
		RFC:         "RFC 2034",
		Description: "Enhanced status codes for more descriptive error messages",
	},
	{
		Name:        Ext8BitMIME,
		Type:        ExtTypeIntrinsic,
		RFC:         "RFC 6152",
		Description: "8-bit MIME transport support",
	},
	{
		Name:         ExtSMTPUTF8,
		Type:         ExtTypeIntrinsic,
		RFC:          "RFC 6531",
		Description:  "Internationalized email addresses (UTF-8 support)",
		Dependencies: []Extension{Ext8BitMIME}, // RFC 6531 requires 8BITMIME
	},
	{
		Name:        ExtPipelining,
		Type:        ExtTypeIntrinsic,
		RFC:         "RFC 2920",
		Description: "Command pipelining for improved performance",
	},
}

// OptInExtensions require explicit configuration.
var OptInExtensions = []ExtensionInfo{
	{
		Name:        ExtSTARTTLS,
		Type:        ExtTypeOptIn,
		RFC:         "RFC 3207",
		Description: "TLS encryption upgrade via STARTTLS command",
	},
	{
		Name:        ExtAuth,
		Type:        ExtTypeOptIn,
		RFC:         "RFC 4954",
		Description: "SMTP authentication (SASL)",
	},
	{
		Name:        ExtSize,
		Type:        ExtTypeOptIn,
		RFC:         "RFC 1870",
		Description: "Message size declaration",
	},
	{
		Name:        ExtDSN,
		Type:        ExtTypeOptIn,
		RFC:         "RFC 3461",
		Description: "Delivery Status Notifications",
	},
	{
		Name:        ExtChunking,
		Type:        ExtTypeOptIn,
		RFC:         "RFC 3030",
		Description: "Chunked message transfer via BDAT command",
	},
	{
		Name:         ExtBinaryMIME,
		Type:         ExtTypeOptIn,
		RFC:          "RFC 3030",
		Description:  "Binary MIME content transfer",
		Dependencies: []Extension{ExtChunking}, // BINARYMIME requires CHUNKING
	},
}

// ---- Extension Configuration Helpers ----

// DSN enables Delivery Status Notifications (RFC 3461).
// DSN allows senders to request delivery notifications.
//
// Example:
//
//	server := raven.New("mail.example.com").
//	    Extension(raven.DSN()).
//	    Build()
func DSN() ExtensionConfig {
	return ExtensionConfig{
		Name:    ExtDSN,
		Enabled: true,
	}
}

// Chunking enables the CHUNKING/BDAT extension (RFC 3030).
// This allows large messages to be sent in chunks and enables
// binary content transfer (BINARYMIME).
//
// Example:
//
//	server := raven.New("mail.example.com").
//	    Extension(raven.Chunking()).
//	    Build()
func Chunking() ExtensionConfig {
	return ExtensionConfig{
		Name:    ExtChunking,
		Enabled: true,
	}
}

// ChunkingWithOptions enables CHUNKING with custom options.
//
// Example:
//
//	server := raven.New("mail.example.com").
//	    Extension(raven.ChunkingWithOptions(ChunkingOptions{
//	        MaxChunkSize: 10 * 1024 * 1024, // 10MB max chunk
//	    })).
//	    Build()
func ChunkingWithOptions(opts ChunkingOptions) ExtensionConfig {
	return ExtensionConfig{
		Name:    ExtChunking,
		Enabled: true,
		Params: map[string]any{
			"maxChunkSize": opts.MaxChunkSize,
		},
	}
}

// ChunkingOptions holds configuration for the CHUNKING extension.
type ChunkingOptions struct {
	// MaxChunkSize is the maximum size of a single BDAT chunk.
	// 0 means no limit (uses MaxMessageSize).
	MaxChunkSize int64
}

// Size enables the SIZE extension (RFC 1870) with a specific limit.
// If maxSize is 0, no size limit is advertised.
//
// Example:
//
//	server := raven.New("mail.example.com").
//	    Extension(raven.Size(25 * 1024 * 1024)). // 25MB
//	    Build()
func Size(maxSize int64) ExtensionConfig {
	return ExtensionConfig{
		Name:    ExtSize,
		Enabled: true,
		Params: map[string]any{
			"maxSize": maxSize,
		},
	}
}

// ---- Extension Group Helpers ----

// WithAllExtensions returns all opt-in extensions.
// Use this for maximum compatibility with clients.
func WithAllExtensions() []ExtensionConfig {
	return []ExtensionConfig{
		DSN(),
		Chunking(),
	}
}

// WithSubmissionExtensions returns extensions suitable for a mail submission agent (MSA).
// This includes extensions useful for authenticated submission on port 587.
func WithSubmissionExtensions() []ExtensionConfig {
	return []ExtensionConfig{
		// DSN is useful for submission
		DSN(),
	}
}

// ---- Extension Validation ----

// ValidateExtensions checks that all extension dependencies are met.
func ValidateExtensions(extensions []ExtensionConfig) error {
	enabled := make(map[Extension]bool)
	for _, ext := range extensions {
		if ext.Enabled {
			enabled[ext.Name] = true
		}
	}

	// Add intrinsic extensions
	for _, ext := range IntrinsicExtensions {
		enabled[ext.Name] = true
	}

	// Check dependencies
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

// ---- Extension Registry ----

// ExtensionRegistry holds the enabled extensions for a server.
type ExtensionRegistry struct {
	extensions map[Extension]*ExtensionInfo
	params     map[Extension]map[string]any
}

// NewExtensionRegistry creates a new extension registry with intrinsic extensions.
func NewExtensionRegistry() *ExtensionRegistry {
	r := &ExtensionRegistry{
		extensions: make(map[Extension]*ExtensionInfo),
		params:     make(map[Extension]map[string]any),
	}

	// Always enable intrinsic extensions
	for i := range IntrinsicExtensions {
		ext := &IntrinsicExtensions[i]
		r.extensions[ext.Name] = ext
	}

	return r
}

// Enable adds an extension to the registry.
func (r *ExtensionRegistry) Enable(config ExtensionConfig) error {
	// Find extension info
	var info *ExtensionInfo
	for i := range OptInExtensions {
		if OptInExtensions[i].Name == config.Name {
			info = &OptInExtensions[i]
			break
		}
	}

	if info == nil {
		// Check if it's intrinsic (already enabled)
		for i := range IntrinsicExtensions {
			if IntrinsicExtensions[i].Name == config.Name {
				return nil // Already enabled
			}
		}
		return fmt.Errorf("unknown extension: %s", config.Name)
	}

	// Check dependencies
	for _, dep := range info.Dependencies {
		if _, ok := r.extensions[dep]; !ok {
			return fmt.Errorf("extension %s requires %s to be enabled first", config.Name, dep)
		}
	}

	r.extensions[config.Name] = info
	if config.Params != nil {
		r.params[config.Name] = config.Params
	}

	return nil
}

// IsEnabled checks if an extension is enabled.
func (r *ExtensionRegistry) IsEnabled(ext Extension) bool {
	_, ok := r.extensions[ext]
	return ok
}

// GetParams returns the parameters for an extension.
func (r *ExtensionRegistry) GetParams(ext Extension) map[string]any {
	return r.params[ext]
}

// List returns all enabled extensions with their parameters.
func (r *ExtensionRegistry) List() map[Extension]string {
	result := make(map[Extension]string)
	for ext := range r.extensions {
		if params, ok := r.params[ext]; ok {
			// Format params for EHLO response
			if maxSize, ok := params["maxSize"].(int64); ok && maxSize > 0 {
				result[ext] = fmt.Sprintf("%d", maxSize)
			} else {
				result[ext] = ""
			}
		} else {
			result[ext] = ""
		}
	}
	return result
}
