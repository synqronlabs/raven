package dkim

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
)

// Record represents a DKIM DNS TXT record (RFC 6376 Section 3.6.1).
// The record is retrieved from <selector>._domainkey.<domain>.
type Record struct {
	// Version is the record version, must be "DKIM1".
	Version string

	// Hashes is the list of acceptable hash algorithms (e.g., "sha256", "sha1").
	// Empty means all algorithms are acceptable.
	Hashes []string

	// Key is the key type: "rsa" (default) or "ed25519".
	Key string

	// Notes contains optional human-readable notes.
	Notes string

	// Pubkey is the raw public key data (base64-decoded).
	// Empty means the key has been revoked.
	Pubkey []byte

	// Services lists acceptable service types.
	// Empty or containing "*" means all services.
	Services []string

	// Flags contains key flags:
	//   "y" - Domain is testing DKIM
	//   "s" - i= domain must exactly match d= domain
	Flags []string

	// PublicKey is the parsed public key.
	// This is *rsa.PublicKey or ed25519.PublicKey.
	PublicKey any
}

// ServiceAllowed returns true if the given service is allowed by this key.
func (r *Record) ServiceAllowed(service string) bool {
	if len(r.Services) == 0 {
		return true
	}
	for _, s := range r.Services {
		if s == "*" || strings.EqualFold(s, service) {
			return true
		}
	}
	return false
}

// IsTesting returns true if the key is marked for testing (t=y).
func (r *Record) IsTesting() bool {
	for _, f := range r.Flags {
		if strings.EqualFold(f, "y") {
			return true
		}
	}
	return false
}

// RequireStrictAlignment returns true if strict alignment is required (t=s).
func (r *Record) RequireStrictAlignment() bool {
	for _, f := range r.Flags {
		if strings.EqualFold(f, "s") {
			return true
		}
	}
	return false
}

// HashAllowed returns true if the given hash algorithm is allowed.
func (r *Record) HashAllowed(hash string) bool {
	if len(r.Hashes) == 0 {
		return true
	}
	for _, h := range r.Hashes {
		if strings.EqualFold(h, hash) {
			return true
		}
	}
	return false
}

// ToTXT generates a DNS TXT record string from this Record.
func (r *Record) ToTXT() (string, error) {
	var parts []string

	// Version (required)
	if r.Version != "DKIM1" {
		return "", fmt.Errorf("invalid version: %s", r.Version)
	}
	parts = append(parts, "v=DKIM1")

	// Hash algorithms (optional)
	if len(r.Hashes) > 0 {
		parts = append(parts, "h="+strings.Join(r.Hashes, ":"))
	}

	// Key type (optional, default is "rsa")
	if r.Key != "" && !strings.EqualFold(r.Key, "rsa") {
		parts = append(parts, "k="+r.Key)
	}

	// Notes (optional)
	if r.Notes != "" {
		parts = append(parts, "n="+encodeQPSection(r.Notes))
	}

	// Services (optional)
	if len(r.Services) > 0 && !(len(r.Services) == 1 && r.Services[0] == "*") {
		parts = append(parts, "s="+strings.Join(r.Services, ":"))
	}

	// Flags (optional)
	if len(r.Flags) > 0 {
		parts = append(parts, "t="+strings.Join(r.Flags, ":"))
	}

	// Public key (required, empty means revoked)
	pk := r.Pubkey
	if len(pk) == 0 && r.PublicKey != nil {
		var err error
		pk, err = marshalPublicKey(r.PublicKey)
		if err != nil {
			return "", err
		}
	}
	parts = append(parts, "p="+base64.StdEncoding.EncodeToString(pk))

	return strings.Join(parts, "; "), nil
}

// marshalPublicKey converts a public key to bytes for the p= tag.
func marshalPublicKey(key any) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return x509.MarshalPKIXPublicKey(k)
	case ed25519.PublicKey:
		return []byte(k), nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", key)
	}
}

// encodeQPSection encodes a string for use in DKIM record notes.
func encodeQPSection(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i, c := range []byte(s) {
		// First character cannot be whitespace
		if (i == 0 && (c == ' ' || c == '\t')) || c > ' ' && c < 0x7f && c != '=' {
			b.WriteByte(c)
		} else {
			b.WriteByte('=')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		}
	}
	return b.String()
}

// ParseRecord parses a DKIM DNS TXT record.
// Returns the parsed record and a boolean indicating if it's a DKIM record.
func ParseRecord(txt string) (*Record, bool, error) {
	record := &Record{
		Version:  "DKIM1",
		Key:      "rsa",
		Services: []string{"*"},
	}

	seen := make(map[string]bool)
	isDKIM := false

	// Parse tag=value pairs
	parts := strings.Split(txt, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		idx := strings.Index(part, "=")
		if idx == -1 {
			continue
		}

		tag := strings.TrimSpace(part[:idx])
		value := strings.TrimSpace(part[idx+1:])

		// Check for duplicate tags
		if seen[tag] {
			if isDKIM {
				return nil, true, fmt.Errorf("%w: duplicate tag %s", ErrSyntax, tag)
			}
			continue
		}
		seen[tag] = true

		switch tag {
		case "v":
			if value != "DKIM1" {
				return nil, false, fmt.Errorf("not a DKIM1 record")
			}
			record.Version = value
			isDKIM = true

		case "h":
			// Hash algorithms (colon-separated)
			hashes := strings.Split(value, ":")
			for _, h := range hashes {
				h = strings.TrimSpace(h)
				if h != "" {
					record.Hashes = append(record.Hashes, h)
				}
			}
			isDKIM = true

		case "k":
			record.Key = strings.ToLower(value)
			isDKIM = true

		case "n":
			record.Notes = decodeQPSection(value)
			isDKIM = true

		case "p":
			// Public key (base64)
			// Remove all whitespace
			cleaned := strings.Map(func(r rune) rune {
				if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
					return -1
				}
				return r
			}, value)
			if cleaned != "" {
				decoded, err := base64.StdEncoding.DecodeString(cleaned)
				if err != nil {
					return nil, isDKIM, fmt.Errorf("%w: invalid public key encoding: %v", ErrSyntax, err)
				}
				record.Pubkey = decoded
			}
			isDKIM = true

		case "s":
			// Services (colon-separated)
			services := strings.Split(value, ":")
			record.Services = nil
			for _, s := range services {
				s = strings.TrimSpace(s)
				if s != "" {
					record.Services = append(record.Services, s)
				}
			}
			isDKIM = true

		case "t":
			// Flags (colon-separated)
			flags := strings.Split(value, ":")
			for _, f := range flags {
				f = strings.TrimSpace(f)
				if f != "" {
					record.Flags = append(record.Flags, f)
				}
			}
			isDKIM = true
		}
	}

	if !isDKIM {
		return nil, false, fmt.Errorf("not a DKIM record")
	}

	// Public key is required (but can be empty for revoked keys)
	if !seen["p"] {
		return nil, true, fmt.Errorf("%w: missing public key (p=)", ErrSyntax)
	}

	// Parse the public key if present
	if len(record.Pubkey) > 0 {
		pk, err := parsePublicKey(record.Key, record.Pubkey)
		if err != nil {
			return nil, true, fmt.Errorf("%w: %v", ErrSyntax, err)
		}
		record.PublicKey = pk
	}

	return record, true, nil
}

// parsePublicKey parses a public key based on the key type.
func parsePublicKey(keyType string, data []byte) (any, error) {
	switch strings.ToLower(keyType) {
	case "", "rsa":
		// RSA key in PKIX format
		pk, err := x509.ParsePKIXPublicKey(data)
		if err != nil {
			return nil, fmt.Errorf("invalid RSA public key: %w", err)
		}
		rsaPK, ok := pk.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected RSA public key, got %T", pk)
		}
		return rsaPK, nil

	case "ed25519":
		// Ed25519 key is raw bytes
		if len(data) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 public key size: %d", len(data))
		}
		return ed25519.PublicKey(data), nil

	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// decodeQPSection decodes a quoted-printable encoded section.
func decodeQPSection(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '=' && i+2 < len(s) {
			hi := hexVal(s[i+1])
			lo := hexVal(s[i+2])
			if hi >= 0 && lo >= 0 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
