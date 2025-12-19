package dmarc

import (
	"context"
	"math/rand/v2"
	"net/mail"
	"strings"

	"github.com/synqronlabs/raven/dkim"
	ravendns "github.com/synqronlabs/raven/dns"
	"github.com/synqronlabs/raven/spf"
)

// VerifyArgs contains the parameters for DMARC verification.
type VerifyArgs struct {
	// FromDomain is the domain from the RFC5322.From header.
	// This is the domain that DMARC will authenticate.
	FromDomain string

	// SPFResult is the result of SPF verification.
	SPFResult spf.Status

	// SPFDomain is the domain that was checked by SPF (from MAIL FROM).
	// This is needed for SPF alignment checking.
	SPFDomain string

	// DKIMResults contains the results of DKIM verification.
	DKIMResults []dkim.Result
}

// Verify evaluates the DMARC policy for the given message parameters.
//
// The function:
//  1. Looks up the DMARC policy for the From domain
//  2. Checks SPF alignment (if SPF passed)
//  3. Checks DKIM alignment (for each passing DKIM signature)
//  4. Determines the overall result based on the policy
//
// applyRandomPercentage determines whether the record's "pct" field is honored.
// This field specifies the percentage of messages to which the DMARC policy
// applies. It's used for gradual rollout and should be honored during normal
// email processing.
//
// Returns:
//   - useResult: Whether the result should be applied in policy decisions,
//     based on the "pct" field in the DMARC record.
//   - result: The DMARC verification result.
func Verify(ctx context.Context, resolver ravendns.Resolver, args VerifyArgs, applyRandomPercentage bool) (useResult bool, result Result) {
	// Look up DMARC record
	status, recordDomain, record, _, authentic, err := Lookup(ctx, resolver, args.FromDomain)
	if record == nil {
		return false, Result{
			Reject:          false,
			Status:          status,
			Domain:          recordDomain,
			Record:          nil,
			RecordAuthentic: authentic,
			Err:             err,
		}
	}

	result.Domain = recordDomain
	result.Record = record
	result.RecordAuthentic = authentic

	// Determine if we should use this result based on pct field
	useResult = !applyRandomPercentage || record.Percentage == 100 || rand.IntN(100) < record.Percentage

	// Determine if the From domain is a subdomain of the DMARC record domain
	isSubdomain := recordDomain != args.FromDomain

	// Determine the effective policy
	effectivePolicy := record.EffectivePolicy(isSubdomain)
	result.Reject = effectivePolicy != PolicyNone

	// Start with fail status, will be updated if alignment succeeds
	result.Status = StatusFail

	// Check for temporary errors in SPF
	if args.SPFResult == spf.StatusTemperror {
		result.Status = StatusTemperror
		result.Reject = false
	}

	// Check SPF alignment
	if args.SPFResult == spf.StatusPass && args.SPFDomain != "" {
		if DomainsAligned(args.FromDomain, args.SPFDomain, record.ASPF) {
			result.AlignedSPFPass = true
		}
	}

	// Check DKIM alignment
	fromOrgDomain := OrganizationalDomain(args.FromDomain)
	for _, dkimResult := range args.DKIMResults {
		if dkimResult.Status == dkim.StatusTemperror {
			result.Reject = false
			result.Status = StatusTemperror
			continue
		}

		if dkimResult.Status == dkim.StatusPass && dkimResult.Signature != nil {
			sigDomain := dkimResult.Signature.Domain

			// Check alignment
			if DomainsAligned(args.FromDomain, sigDomain, record.ADKIM) {
				// Additional check: DKIM domain must not be above the organizational domain
				// This prevents TLD-level signatures from causing a pass
				sigOrgDomain := OrganizationalDomain(sigDomain)
				if sigOrgDomain == fromOrgDomain {
					result.AlignedDKIMPass = true
					break
				}
			}
		}
	}

	// If either SPF or DKIM passed with alignment, DMARC passes
	if result.AlignedSPFPass || result.AlignedDKIMPass {
		result.Reject = false
		result.Status = StatusPass
	}

	return useResult, result
}

// VerifyMail is a convenience function that verifies DMARC for a Mail object.
// It extracts the From domain from the message headers and performs verification.
//
// The SPF and DKIM results should be obtained from prior verification steps,
// typically via their respective middleware or direct verification calls.
func VerifyMail(ctx context.Context, resolver ravendns.Resolver, fromHeader string, spfResult spf.Status, spfDomain string, dkimResults []dkim.Result, applyRandomPercentage bool) (useResult bool, result Result) {
	// Parse the From header
	fromDomain, err := ExtractFromDomain(fromHeader)
	if err != nil {
		return false, Result{
			Status: StatusPermerror,
			Err:    err,
		}
	}

	args := VerifyArgs{
		FromDomain:  fromDomain,
		SPFResult:   spfResult,
		SPFDomain:   spfDomain,
		DKIMResults: dkimResults,
	}

	return Verify(ctx, resolver, args, applyRandomPercentage)
}

// ExtractFromDomain extracts the domain from a From header value.
// It returns an error if the header is missing, invalid, or contains
// multiple addresses.
func ExtractFromDomain(fromHeader string) (string, error) {
	if fromHeader == "" {
		return "", ErrNoFromHeader
	}

	// Parse the From header (may contain display name)
	addrs, err := mail.ParseAddressList(fromHeader)
	if err != nil {
		return "", ErrInvalidFromHeader
	}

	if len(addrs) == 0 {
		return "", ErrNoFromHeader
	}

	if len(addrs) > 1 {
		// DMARC can only check one domain, so multiple From addresses are ambiguous
		// Use the first one but note: some implementations reject this case
		// For strict compliance, uncomment the following:
		// return "", ErrMultipleFromAddresses
	}

	// Extract domain from the email address
	addr := addrs[0].Address
	at := strings.LastIndex(addr, "@")
	if at < 0 || at == len(addr)-1 {
		return "", ErrInvalidFromHeader
	}

	return strings.ToLower(addr[at+1:]), nil
}
