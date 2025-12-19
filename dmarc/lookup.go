package dmarc

import (
	"context"
	"fmt"
	"strings"

	ravendns "github.com/synqronlabs/raven/dns"
)

// Lookup looks up the DMARC TXT record for the given domain.
//
// It first queries "_dmarc.<domain>". If no record is found, it falls back to
// the organizational domain (determined using the Public Suffix List) and
// queries "_dmarc.<orgdomain>".
//
// Returns:
//   - status: The lookup status
//   - domain: The domain where the record was found
//   - record: The parsed DMARC record (nil if not found or invalid)
//   - txt: The raw TXT record text
//   - authentic: Whether the DNS response was DNSSEC-validated
//   - err: Any error that occurred
func Lookup(ctx context.Context, resolver ravendns.Resolver, domain string) (status Status, dmarcDomain string, record *Record, txt string, authentic bool, err error) {
	// First, try the exact domain
	dmarcDomain = domain
	status, record, txt, authentic, err = lookupRecord(ctx, resolver, dmarcDomain)
	if status != StatusNone {
		return status, dmarcDomain, record, txt, authentic, err
	}
	if record != nil {
		return status, dmarcDomain, record, txt, authentic, err
	}

	// If no record at the exact domain, try the organizational domain
	orgDomain := OrganizationalDomain(domain)
	if orgDomain == domain {
		// Already at the organizational domain, no fallback
		return StatusNone, domain, nil, txt, authentic, err
	}

	dmarcDomain = orgDomain
	var orgAuthentic bool
	status, record, txt, orgAuthentic, err = lookupRecord(ctx, resolver, dmarcDomain)
	// Combine authentic status - only authentic if both lookups were authentic
	authentic = authentic && orgAuthentic

	return status, dmarcDomain, record, txt, authentic, err
}

// lookupRecord performs the actual DNS lookup for a DMARC record.
func lookupRecord(ctx context.Context, resolver ravendns.Resolver, domain string) (Status, *Record, string, bool, error) {
	name := "_dmarc." + domain
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	result, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		if ravendns.IsNotFound(err) {
			return StatusNone, nil, "", result.Authentic, ErrNoRecord
		}
		return StatusTemperror, nil, "", result.Authentic, fmt.Errorf("%w: %v", ErrDNS, err)
	}

	var record *Record
	var text string
	var rerr error = ErrNoRecord

	for _, txt := range result.Records {
		r, isDMARC, parseErr := ParseRecord(txt)
		if !isDMARC {
			// Not a DMARC record, skip
			continue
		}
		if parseErr != nil {
			return StatusPermerror, nil, text, result.Authentic, fmt.Errorf("%w: %v", ErrSyntax, parseErr)
		}
		if record != nil {
			// Multiple DMARC records - per RFC 7489 Section 6.6.3, this is an error
			return StatusNone, nil, "", result.Authentic, ErrMultipleRecords
		}
		text = txt
		record = r
		rerr = nil
	}

	return StatusNone, record, text, result.Authentic, rerr
}

// LookupExternalReportsAccepted checks whether an external domain has opted in
// to receiving DMARC reports for another domain.
//
// This is checked via a DNS lookup for:
//
//	<dmarc-domain>._report._dmarc.<external-domain>
//
// Returns true if the external domain accepts reports for the DMARC domain.
func LookupExternalReportsAccepted(ctx context.Context, resolver ravendns.Resolver, dmarcDomain, extDestDomain string) (accepts bool, status Status, records []*Record, txts []string, authentic bool, err error) {
	status, records, txts, authentic, err = lookupReportsRecord(ctx, resolver, dmarcDomain, extDestDomain)
	accepts = err == nil
	return accepts, status, records, txts, authentic, err
}

// lookupReportsRecord performs the DNS lookup for external report authorization.
func lookupReportsRecord(ctx context.Context, resolver ravendns.Resolver, dmarcDomain, extDestDomain string) (Status, []*Record, []string, bool, error) {
	// Per RFC 7489 Section 7.1
	name := dmarcDomain + "._report._dmarc." + extDestDomain
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	result, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		if ravendns.IsNotFound(err) {
			return StatusNone, nil, nil, result.Authentic, ErrNoRecord
		}
		return StatusTemperror, nil, nil, result.Authentic, fmt.Errorf("%w: %v", ErrDNS, err)
	}

	var records []*Record
	var texts []string
	var rerr error = ErrNoRecord

	for _, txt := range result.Records {
		r, isDMARC, parseErr := ParseRecordNoRequired(txt)

		// Accept "v=DMARC1" even though it's not technically valid
		// (RFC examples use this form)
		if !isDMARC && txt == "v=DMARC1" {
			xr := DefaultRecord
			r, isDMARC, parseErr = &xr, true, nil
		}

		if !isDMARC {
			continue
		}

		texts = append(texts, txt)
		records = append(records, r)

		if parseErr != nil {
			return StatusPermerror, records, texts, result.Authentic, fmt.Errorf("%w: %v", ErrSyntax, parseErr)
		}

		// Multiple records are allowed for _report records, unlike for policies
		rerr = nil
	}

	return StatusNone, records, texts, result.Authentic, rerr
}
