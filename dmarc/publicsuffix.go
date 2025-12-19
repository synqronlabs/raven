package dmarc

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// OrganizationalDomain returns the organizational domain for the given domain.
//
// The organizational domain is the domain directly under the public suffix.
// For example:
//   - example.com -> example.com
//   - sub.example.com -> example.com
//   - sub.example.co.uk -> example.co.uk
//
// This uses the ICANN section of the Public Suffix List, as required by
// RFC 7489 for DMARC alignment checks.
func OrganizationalDomain(domain string) string {
	// Normalize: remove trailing dot and convert to lowercase
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")

	if domain == "" {
		return ""
	}

	// Get the eTLD+1 (effective TLD plus one label)
	// This is the organizational domain per the Public Suffix List
	etld1, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		// If we can't determine the eTLD+1, return the domain as-is
		// This handles cases like "localhost" or invalid domains
		return domain
	}

	return etld1
}

// DomainsAligned checks if two domains are aligned according to the given
// alignment mode.
//
// In strict mode, the domains must match exactly.
// In relaxed mode, the organizational domains must match.
func DomainsAligned(domain1, domain2 string, alignment Align) bool {
	// Normalize domains
	d1 := strings.TrimSuffix(strings.ToLower(domain1), ".")
	d2 := strings.TrimSuffix(strings.ToLower(domain2), ".")

	if alignment == AlignStrict {
		return d1 == d2
	}

	// Relaxed alignment: organizational domains must match
	return OrganizationalDomain(d1) == OrganizationalDomain(d2)
}

// IsSubdomain returns true if domain is a subdomain of the given parent.
// Both domain.example.com and example.com return true for parent example.com.
func IsSubdomain(domain, parent string) bool {
	d := strings.TrimSuffix(strings.ToLower(domain), ".")
	p := strings.TrimSuffix(strings.ToLower(parent), ".")

	if d == p {
		return true
	}

	return strings.HasSuffix(d, "."+p)
}

// IsOrganizationalDomain returns true if the domain is an organizational domain
// (i.e., directly below the public suffix).
func IsOrganizationalDomain(domain string) bool {
	d := strings.TrimSuffix(strings.ToLower(domain), ".")
	return OrganizationalDomain(d) == d
}

// PublicSuffix returns the public suffix of the domain.
// For example, "co.uk" for "example.co.uk".
func PublicSuffix(domain string) string {
	d := strings.TrimSuffix(strings.ToLower(domain), ".")
	suffix, _ := publicsuffix.PublicSuffix(d)
	return suffix
}
