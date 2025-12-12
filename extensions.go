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
