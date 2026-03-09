package dmarc

import (
	"context"
	"fmt"
	"strings"

	ravendns "github.com/synqronlabs/raven/dns"
)

// LookupResult contains the outcome of a DMARC policy lookup.
type LookupResult struct {
	Status    Status
	Domain    string
	Record    *Record
	TXT       string
	Authentic bool
}

// ExternalReportsLookupResult contains the outcome of an external reports lookup.
type ExternalReportsLookupResult struct {
	Accepts   bool
	Status    Status
	Records   []*Record
	TXTs      []string
	Authentic bool
}

// Lookup looks up the DMARC TXT record for the given domain.
//
// It first queries "_dmarc.<domain>". If no record is found, it falls back to
// the organizational domain (determined using the Public Suffix List) and
// queries "_dmarc.<orgdomain>".
//
// Returns:
//   - result: The lookup result.
//   - err: Any lookup or parse error.
func Lookup(ctx context.Context, resolver ravendns.Resolver, domain string) (result LookupResult, err error) {
	// First, try the exact domain
	result.Domain = domain
	result.Status, result.Record, result.TXT, result.Authentic, err = lookupRecord(ctx, resolver, result.Domain)
	if result.Status != StatusNone {
		return result, err
	}
	if result.Record != nil {
		return result, err
	}

	// If no record at the exact domain, try the organizational domain
	orgDomain := OrganizationalDomain(domain)
	if orgDomain == domain {
		// Already at the organizational domain, no fallback
		return result, err
	}

	result.Domain = orgDomain
	var orgAuthentic bool
	result.Status, result.Record, result.TXT, orgAuthentic, err = lookupRecord(ctx, resolver, result.Domain)
	// Combine authentic status - only authentic if both lookups were authentic
	result.Authentic = result.Authentic && orgAuthentic

	return result, err
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
		return StatusTemperror, nil, "", result.Authentic, fmt.Errorf("%w: lookup TXT %s: %w", ErrDNS, name, err)
	}

	var record *Record
	var text string
	var rerr = ErrNoRecord

	for _, txt := range result.Records {
		r, isDMARC, parseErr := ParseRecord(txt, ParseModeStrict)
		if !isDMARC {
			// Not a DMARC record, skip
			continue
		}
		if parseErr != nil {
			return StatusPermerror, nil, text, result.Authentic, fmt.Errorf("%w: parsing DMARC record %q: %w", ErrSyntax, txt, parseErr)
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
func LookupExternalReportsAccepted(ctx context.Context, resolver ravendns.Resolver, dmarcDomain, extDestDomain string) (ExternalReportsLookupResult, error) {
	status, records, txts, authentic, err := lookupReportsRecord(ctx, resolver, dmarcDomain, extDestDomain)
	return ExternalReportsLookupResult{
		Accepts:   err == nil,
		Status:    status,
		Records:   records,
		TXTs:      txts,
		Authentic: authentic,
	}, err
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
		return StatusTemperror, nil, nil, result.Authentic, fmt.Errorf("%w: lookup TXT %s: %w", ErrDNS, name, err)
	}

	var records []*Record
	var texts []string
	var rerr = ErrNoRecord

	for _, txt := range result.Records {
		r, isDMARC, parseErr := ParseRecord(txt, ParseModeRelaxed)

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
			return StatusPermerror, records, texts, result.Authentic, fmt.Errorf("%w: parsing DMARC external report record %q: %w", ErrSyntax, txt, parseErr)
		}

		// Multiple records are allowed for _report records, unlike for policies
		rerr = nil
	}

	return StatusNone, records, texts, result.Authentic, rerr
}
