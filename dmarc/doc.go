// Package dmarc implements Domain-based Message Authentication, Reporting,
// and Conformance (DMARC) per RFC 7489.
//
// DMARC is a mechanism for verifying ("authenticating") the address in the "From"
// message header, since users will look at that header to identify the sender of a
// message. DMARC compares the "From" domain against the SPF and/or DKIM-validated
// domains, based on the DMARC policy that a domain has published in DNS as a TXT
// record under "_dmarc.<domain>".
//
// This package provides:
//   - Full DMARC record parsing with all standard tags
//   - DMARC policy evaluation with SPF and DKIM alignment
//   - Organizational domain detection using the Public Suffix List
//   - Middleware integration for Raven SMTP server
//   - Authentication-Results header generation
//
// # Basic Usage
//
// Looking up a DMARC policy:
//
//	resolver := dns.NewResolver(dns.ResolverConfig{
//	    DNSSEC: true,
//	})
//
//	status, domain, record, err := dmarc.Lookup(ctx, resolver, "example.com")
//	if err != nil {
//	    // Handle error
//	}
//
// Verifying DMARC alignment:
//
//	result := dmarc.Verify(ctx, resolver, dmarc.VerifyArgs{
//	    FromDomain:  "example.com",
//	    SPFResult:   spf.StatusPass,
//	    SPFDomain:   "example.com",
//	    DKIMResults: dkimResults,
//	})
//
//	if result.Status == dmarc.StatusPass {
//	    // Message passed DMARC
//	}
//
// # Middleware Usage
//
//	server := raven.New("mx.example.com").
//	    Use(spf.Middleware(spf.MiddlewareConfig{...})).
//	    Use(dkim.Middleware(dkim.MiddlewareConfig{...})).
//	    Use(dmarc.Middleware(dmarc.MiddlewareConfig{
//	        Resolver: resolver,
//	        Policy:   dmarc.PolicyMark,
//	    }))
//
// # DMARC Alignment
//
// DMARC requires "alignment" between the domain in the From header and the domains
// authenticated by SPF and/or DKIM:
//
//   - SPF alignment: The RFC5321.MailFrom domain (envelope sender) must match
//     the RFC5322.From domain (message header).
//
//   - DKIM alignment: At least one passing DKIM signature must have a d= domain
//     that matches the RFC5322.From domain.
//
// Alignment can be "strict" (exact match) or "relaxed" (organizational domain match).
// The default is relaxed alignment for both SPF and DKIM.
//
// # Organizational Domain
//
// The organizational domain is determined using the Public Suffix List. For example:
//   - example.com has organizational domain example.com
//   - sub.example.com has organizational domain example.com
//   - sub.example.co.uk has organizational domain example.co.uk
//
// # References
//
//   - RFC 7489: Domain-based Message Authentication, Reporting, and Conformance (DMARC)
//   - RFC 8601: Message Header Field for Indicating Message Authentication Status
//   - RFC 6376: DomainKeys Identified Mail (DKIM) Signatures
//   - RFC 7208: Sender Policy Framework (SPF)
package dmarc
