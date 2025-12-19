package dmarc

import (
	"context"

	"github.com/synqronlabs/raven"
	"github.com/synqronlabs/raven/dkim"
	ravendns "github.com/synqronlabs/raven/dns"
	"github.com/synqronlabs/raven/spf"
)

// MailVerifyArgs contains the parameters for verifying DMARC on a Mail object.
type MailVerifyArgs struct {
	// SPFResult is the result of SPF verification.
	SPFResult spf.Status

	// SPFDomain is the domain that was checked by SPF (from MAIL FROM).
	SPFDomain string

	// DKIMResults contains the results of DKIM verification.
	DKIMResults []dkim.Result

	// ApplyRandomPercentage honors the pct= field in DMARC records.
	ApplyRandomPercentage bool
}

// VerifyMailObject performs DMARC verification on a raven.Mail object.
//
// This is a convenience function that:
//  1. Extracts the From header from the mail
//  2. Performs DMARC lookup and verification
//  3. Returns the result
//
// Usage:
//
//	result, useResult, err := dmarc.VerifyMailObject(ctx, resolver, mail, dmarc.MailVerifyArgs{
//	    SPFResult:   spfResult,
//	    SPFDomain:   spfDomain,
//	    DKIMResults: dkimResults,
//	})
func VerifyMailObject(ctx context.Context, resolver ravendns.Resolver, mail *raven.Mail, args MailVerifyArgs) (Result, bool, error) {
	// Get From header
	fromHeader := mail.Content.Headers.Get("From")
	if fromHeader == "" {
		return Result{Status: StatusPermerror, Err: ErrNoFromHeader}, false, ErrNoFromHeader
	}

	// Extract From domain
	fromDomain, err := ExtractFromDomain(fromHeader)
	if err != nil {
		return Result{Status: StatusPermerror, Err: err}, false, err
	}

	verifyArgs := VerifyArgs{
		FromDomain:  fromDomain,
		SPFResult:   args.SPFResult,
		SPFDomain:   args.SPFDomain,
		DKIMResults: args.DKIMResults,
	}

	useResult, result := Verify(ctx, resolver, verifyArgs, args.ApplyRandomPercentage)
	return result, useResult, nil
}

// AddAuthenticationResults adds a DMARC Authentication-Results header to the mail.
// This should be called after DMARC verification to record the result.
func AddAuthenticationResults(mail *raven.Mail, hostname string, result Result) {
	fromHeader := mail.Content.Headers.Get("From")
	fromDomain, _ := ExtractFromDomain(fromHeader)

	authResults := generateAuthResults(hostname, result, fromDomain)
	mail.Content.Headers = append(raven.Headers{{
		Name:  "Authentication-Results",
		Value: authResults,
	}}, mail.Content.Headers...)
}

// CheckAlignment checks if SPF and/or DKIM results align with the From domain.
// This is useful for implementing custom DMARC-like policies.
//
// Returns:
//   - spfAligned: true if SPF passed with proper alignment
//   - dkimAligned: true if at least one DKIM signature passed with proper alignment
func CheckAlignment(fromDomain string, spfResult spf.Status, spfDomain string, dkimResults []dkim.Result, adkim, aspf Align) (spfAligned, dkimAligned bool) {
	// Check SPF alignment
	if spfResult == spf.StatusPass && spfDomain != "" {
		spfAligned = DomainsAligned(fromDomain, spfDomain, aspf)
	}

	// Check DKIM alignment
	fromOrgDomain := OrganizationalDomain(fromDomain)
	for _, result := range dkimResults {
		if result.Status == dkim.StatusPass && result.Signature != nil {
			sigDomain := result.Signature.Domain
			if DomainsAligned(fromDomain, sigDomain, adkim) {
				sigOrgDomain := OrganizationalDomain(sigDomain)
				if sigOrgDomain == fromOrgDomain {
					dkimAligned = true
					break
				}
			}
		}
	}

	return spfAligned, dkimAligned
}
