package raven

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// DMARC Errors (RFC 7489)
var (
	ErrDMARCNoRecord          = errors.New("dmarc: no DMARC record found")
	ErrDMARCMultipleRecords   = errors.New("dmarc: multiple DMARC records found")
	ErrDMARCInvalidRecord     = errors.New("dmarc: invalid DMARC record syntax")
	ErrDMARCInvalidVersion    = errors.New("dmarc: invalid version (must be DMARC1)")
	ErrDMARCMissingPolicy     = errors.New("dmarc: missing required p= tag")
	ErrDMARCInvalidPolicy     = errors.New("dmarc: invalid policy value")
	ErrDMARCDNSError          = errors.New("dmarc: DNS lookup error")
	ErrDMARCNoFromDomain      = errors.New("dmarc: no From domain found in message")
	ErrDMARCInvalidFromDomain = errors.New("dmarc: invalid From domain")
)

// Pre-computed public suffix maps for performance optimization.
// These maps are used by isPublicSuffix and were previously created on every call.
var (
	// commonTLDs contains common generic TLDs
	commonTLDs = map[string]bool{
		"com": true, "net": true, "org": true, "edu": true, "gov": true,
		"mil": true, "int": true, "info": true, "biz": true, "name": true,
		"pro": true, "aero": true, "coop": true, "museum": true,
	}

	// ccTLDs contains country code TLDs
	ccTLDs = map[string]bool{
		"ac": true, "ad": true, "ae": true, "af": true, "ag": true, "ai": true,
		"al": true, "am": true, "an": true, "ao": true, "aq": true, "ar": true,
		"as": true, "at": true, "au": true, "aw": true, "ax": true, "az": true,
		"ba": true, "bb": true, "bd": true, "be": true, "bf": true, "bg": true,
		"bh": true, "bi": true, "bj": true, "bm": true, "bn": true, "bo": true,
		"br": true, "bs": true, "bt": true, "bv": true, "bw": true, "by": true,
		"bz": true, "ca": true, "cc": true, "cd": true, "cf": true, "cg": true,
		"ch": true, "ci": true, "ck": true, "cl": true, "cm": true, "cn": true,
		"co": true, "cr": true, "cu": true, "cv": true, "cx": true, "cy": true,
		"cz": true, "de": true, "dj": true, "dk": true, "dm": true, "do": true,
		"dz": true, "ec": true, "ee": true, "eg": true, "eh": true, "er": true,
		"es": true, "et": true, "eu": true, "fi": true, "fj": true, "fk": true,
		"fm": true, "fo": true, "fr": true, "ga": true, "gb": true, "gd": true,
		"ge": true, "gf": true, "gg": true, "gh": true, "gi": true, "gl": true,
		"gm": true, "gn": true, "gp": true, "gq": true, "gr": true, "gs": true,
		"gt": true, "gu": true, "gw": true, "gy": true, "hk": true, "hm": true,
		"hn": true, "hr": true, "ht": true, "hu": true, "id": true, "ie": true,
		"il": true, "im": true, "in": true, "io": true, "iq": true, "ir": true,
		"is": true, "it": true, "je": true, "jm": true, "jo": true, "jp": true,
		"ke": true, "kg": true, "kh": true, "ki": true, "km": true, "kn": true,
		"kp": true, "kr": true, "kw": true, "ky": true, "kz": true, "la": true,
		"lb": true, "lc": true, "li": true, "lk": true, "lr": true, "ls": true,
		"lt": true, "lu": true, "lv": true, "ly": true, "ma": true, "mc": true,
		"md": true, "me": true, "mg": true, "mh": true, "mk": true, "ml": true,
		"mm": true, "mn": true, "mo": true, "mp": true, "mq": true, "mr": true,
		"ms": true, "mt": true, "mu": true, "mv": true, "mw": true, "mx": true,
		"my": true, "mz": true, "na": true, "nc": true, "ne": true, "nf": true,
		"ng": true, "ni": true, "nl": true, "no": true, "np": true, "nr": true,
		"nu": true, "nz": true, "om": true, "pa": true, "pe": true, "pf": true,
		"pg": true, "ph": true, "pk": true, "pl": true, "pm": true, "pn": true,
		"pr": true, "ps": true, "pt": true, "pw": true, "py": true, "qa": true,
		"re": true, "ro": true, "rs": true, "ru": true, "rw": true, "sa": true,
		"sb": true, "sc": true, "sd": true, "se": true, "sg": true, "sh": true,
		"si": true, "sj": true, "sk": true, "sl": true, "sm": true, "sn": true,
		"so": true, "sr": true, "ss": true, "st": true, "su": true, "sv": true,
		"sx": true, "sy": true, "sz": true, "tc": true, "td": true, "tf": true,
		"tg": true, "th": true, "tj": true, "tk": true, "tl": true, "tm": true,
		"tn": true, "to": true, "tr": true, "tt": true, "tv": true, "tw": true,
		"tz": true, "ua": true, "ug": true, "uk": true, "us": true, "uy": true,
		"uz": true, "va": true, "vc": true, "ve": true, "vg": true, "vi": true,
		"vn": true, "vu": true, "wf": true, "ws": true, "ye": true, "yt": true,
		"za": true, "zm": true, "zw": true,
	}

	// secondLevelSuffixes contains common second-level public suffixes
	secondLevelSuffixes = map[string]bool{
		// UK
		"co.uk": true, "org.uk": true, "me.uk": true, "net.uk": true,
		"ac.uk": true, "gov.uk": true, "ltd.uk": true, "plc.uk": true,
		"sch.uk": true, "nhs.uk": true, "police.uk": true,
		// Australia
		"com.au": true, "net.au": true, "org.au": true, "edu.au": true,
		"gov.au": true, "asn.au": true, "id.au": true,
		// Japan
		"co.jp": true, "or.jp": true, "ne.jp": true, "ac.jp": true,
		"ad.jp": true, "ed.jp": true, "go.jp": true, "gr.jp": true,
		"lg.jp": true,
		// Brazil
		"com.br": true, "net.br": true, "org.br": true, "gov.br": true,
		"edu.br": true,
		// China
		"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true,
		"edu.cn": true,
		// Germany
		"co.de": true,
		// France
		"asso.fr": true, "com.fr": true, "gouv.fr": true,
		// India
		"co.in": true, "net.in": true, "org.in": true, "gov.in": true,
		"ac.in": true, "edu.in": true,
		// New Zealand
		"co.nz": true, "net.nz": true, "org.nz": true, "govt.nz": true,
		"ac.nz": true, "school.nz": true,
		// South Africa
		"co.za": true, "net.za": true, "org.za": true, "gov.za": true,
		"ac.za": true,
	}
)

// DMARCPolicy represents the requested policy for handling failed messages (RFC 7489).
type DMARCPolicy string

const (
	// DMARCPolicyNone requests no specific action be taken.
	DMARCPolicyNone DMARCPolicy = "none"

	// DMARCPolicyQuarantine requests that failing messages be treated as suspicious
	// (e.g., placed in spam folder).
	DMARCPolicyQuarantine DMARCPolicy = "quarantine"

	// DMARCPolicyReject requests that failing messages be rejected during SMTP.
	DMARCPolicyReject DMARCPolicy = "reject"
)

// DMARCAlignment represents the alignment mode for identifier matching (RFC 7489).
type DMARCAlignment string

const (
	// DMARCAlignmentRelaxed allows Organizational Domain matching.
	DMARCAlignmentRelaxed DMARCAlignment = "r"

	// DMARCAlignmentStrict requires exact domain matching.
	DMARCAlignmentStrict DMARCAlignment = "s"
)

// DMARCResult represents the result of DMARC evaluation.
type DMARCResult string

const (
	// DMARCResultPass indicates the message passed DMARC checks
	// (at least one authentication mechanism produced an aligned pass).
	DMARCResultPass DMARCResult = "pass"

	// DMARCResultFail indicates the message failed DMARC checks
	// (no authentication mechanism produced an aligned pass).
	DMARCResultFail DMARCResult = "fail"

	// DMARCResultNone indicates no DMARC policy was found for the domain.
	DMARCResultNone DMARCResult = "none"

	// DMARCResultTemperror indicates a temporary error during DMARC evaluation.
	DMARCResultTemperror DMARCResult = "temperror"

	// DMARCResultPermerror indicates a permanent error during DMARC evaluation
	// (e.g., syntactically incorrect DMARC record).
	DMARCResultPermerror DMARCResult = "permerror"
)

// DMARCFailureReportingOptions represents failure reporting preferences (RFC 7489 "fo" tag).
type DMARCFailureReportingOptions struct {
	// ReportOnAllFail generates a report if all underlying authentication mechanisms fail.
	ReportOnAllFail bool // "0" (default)

	// ReportOnAnyFail generates a report if any underlying authentication mechanism fails.
	ReportOnAnyFail bool // "1"

	// ReportOnDKIMFail generates a DKIM failure report if DKIM failed, regardless of alignment.
	ReportOnDKIMFail bool // "d"

	// ReportOnSPFFail generates an SPF failure report if SPF failed, regardless of alignment.
	ReportOnSPFFail bool // "s"
}

// DMARCRecord represents a parsed DMARC DNS record (RFC 7489).
type DMARCRecord struct {
	// Version (v=) - REQUIRED. Must be "DMARC1".
	Version string

	// Policy (p=) - REQUIRED. Requested handling policy.
	Policy DMARCPolicy

	// SubdomainPolicy (sp=) - OPTIONAL. Policy for subdomains.
	// If absent, the "p" tag policy applies to subdomains.
	SubdomainPolicy DMARCPolicy

	// DKIMAlignment (adkim=) - OPTIONAL. Default is "r" (relaxed).
	DKIMAlignment DMARCAlignment

	// SPFAlignment (aspf=) - OPTIONAL. Default is "r" (relaxed).
	SPFAlignment DMARCAlignment

	// Percent (pct=) - OPTIONAL. Default is 100.
	// Percentage of messages to which the policy applies.
	Percent int

	// AggregateReportURIs (rua=) - OPTIONAL.
	// URIs to which aggregate reports should be sent.
	AggregateReportURIs []string

	// FailureReportURIs (ruf=) - OPTIONAL.
	// URIs to which failure reports should be sent.
	FailureReportURIs []string

	// ReportInterval (ri=) - OPTIONAL. Default is 86400 (24 hours).
	// Requested interval between aggregate reports in seconds.
	ReportInterval int

	// FailureReportingOptions (fo=) - OPTIONAL. Default is "0".
	FailureReportingOptions DMARCFailureReportingOptions

	// ReportFormat (rf=) - OPTIONAL. Default is "afrf".
	// Format for failure reports.
	ReportFormat string

	// Raw contains the original record string.
	Raw string
}

// DMARCCheckResult contains the full result of a DMARC check.
type DMARCCheckResult struct {
	// Result is the DMARC evaluation result.
	Result DMARCResult

	// Domain is the RFC5322.From domain that was evaluated.
	Domain string

	// OrganizationalDomain is the determined organizational domain.
	OrganizationalDomain string

	// Policy is the applicable DMARC policy (from p= or sp= tag).
	Policy DMARCPolicy

	// Record is the parsed DMARC record, if found.
	Record *DMARCRecord

	// SPFAligned indicates whether SPF produced an aligned pass.
	SPFAligned bool

	// DKIMAligned indicates whether DKIM produced an aligned pass.
	DKIMAligned bool

	// SPFResult contains the underlying SPF check result.
	SPFResult *SPFCheckResult

	// DKIMResults contains the underlying DKIM verification results.
	DKIMResults []DKIMResult

	// UsedOrgDomain indicates whether the organizational domain policy was used
	// (true when no policy was found at the RFC5322.From domain).
	UsedOrgDomain bool

	// Error contains details if an error occurred.
	Error error
}

// DMARCCheckOptions contains options for DMARC verification.
type DMARCCheckOptions struct {
	// DNSResolver is a custom DNS resolver function for TXT lookups.
	// If nil, net.LookupTXT is used.
	DNSResolver func(domain string) ([]string, error)

	// PublicSuffixList provides the public suffix list for organizational domain discovery.
	// If nil, a built-in minimal list is used.
	// The function should return true if the domain is a public suffix.
	PublicSuffixList func(domain string) bool

	// SPFOptions contains options for the underlying SPF check.
	// If nil, DefaultSPFCheckOptions() is used.
	SPFOptions *SPFCheckOptions

	// DKIMOptions contains options for the underlying DKIM verification.
	// If nil, DefaultDKIMVerifyOptions() is used.
	DKIMOptions *DKIMVerifyOptions

	// SkipSPF skips SPF evaluation.
	SkipSPF bool

	// SkipDKIM skips DKIM evaluation.
	SkipDKIM bool
}

// DefaultDMARCCheckOptions returns DMARCCheckOptions with secure defaults.
func DefaultDMARCCheckOptions() *DMARCCheckOptions {
	return &DMARCCheckOptions{
		DNSResolver:      net.LookupTXT,
		PublicSuffixList: isPublicSuffix,
		SPFOptions:       DefaultSPFCheckOptions(),
		DKIMOptions:      DefaultDKIMVerifyOptions(),
	}
}

// CheckDMARC performs a DMARC check on a mail message.
//
// Parameters:
//   - mail: The mail message to check (must have Content.Headers populated)
//   - clientIP: The IP address of the SMTP client (for SPF)
//   - mailFrom: The MAIL FROM domain (for SPF)
//   - opts: Optional configuration (nil uses defaults)
//
// Returns a DMARCCheckResult with the evaluation result.
//
// Per RFC 7489, the algorithm:
// 1. Extract the RFC5322.From domain
// 2. Query DNS for DMARC policy record
// 3. Perform DKIM signature verification
// 4. Perform SPF validation
// 5. Conduct identifier alignment checks
// 6. Determine the result
func CheckDMARC(mail *Mail, clientIP net.IP, mailFrom string, opts *DMARCCheckOptions) *DMARCCheckResult {
	if opts == nil {
		opts = DefaultDMARCCheckOptions()
	}

	if opts.DNSResolver == nil {
		opts.DNSResolver = net.LookupTXT
	}
	if opts.PublicSuffixList == nil {
		opts.PublicSuffixList = isPublicSuffix
	}

	result := &DMARCCheckResult{
		Result: DMARCResultNone,
	}

	// Step 1: Extract the RFC5322.From domain
	fromDomain, err := extractFromDomain(mail)
	if err != nil {
		result.Result = DMARCResultPermerror
		result.Error = err
		return result
	}
	result.Domain = fromDomain

	// Determine organizational domain
	result.OrganizationalDomain = getOrganizationalDomain(fromDomain, opts.PublicSuffixList)

	// Step 2: Query DNS for DMARC policy record
	record, usedOrgDomain, err := lookupDMARCRecord(fromDomain, result.OrganizationalDomain, opts.DNSResolver)
	if err != nil {
		if errors.Is(err, ErrDMARCNoRecord) {
			result.Result = DMARCResultNone
			return result
		}
		if isDMARCTempError(err) {
			result.Result = DMARCResultTemperror
		} else {
			result.Result = DMARCResultPermerror
		}
		result.Error = err
		return result
	}
	result.Record = record
	result.UsedOrgDomain = usedOrgDomain

	// Determine applicable policy
	if usedOrgDomain && record.SubdomainPolicy != "" {
		result.Policy = record.SubdomainPolicy
	} else {
		result.Policy = record.Policy
	}

	// Step 3: Perform DKIM verification (if not skipped)
	if !opts.SkipDKIM {
		dkimOpts := opts.DKIMOptions
		if dkimOpts == nil {
			dkimOpts = DefaultDKIMVerifyOptions()
		}
		result.DKIMResults = mail.VerifyDKIM(dkimOpts)

		// Check for DKIM alignment
		result.DKIMAligned = checkDKIMAlignment(result.DKIMResults, fromDomain, result.OrganizationalDomain, record.DKIMAlignment)
	}

	// Step 4: Perform SPF validation (if not skipped)
	if !opts.SkipSPF && clientIP != nil && mailFrom != "" {
		spfOpts := opts.SPFOptions
		if spfOpts == nil {
			spfOpts = DefaultSPFCheckOptions()
		}

		// Extract domain from mailFrom
		mailFromDomain := extractDomain(mailFrom)
		if mailFromDomain != "" {
			result.SPFResult = CheckSPF(clientIP, mailFromDomain, mailFrom, spfOpts)

			// Check for SPF alignment
			result.SPFAligned = checkSPFAlignment(result.SPFResult, fromDomain, result.OrganizationalDomain, record.SPFAlignment)
		}
	}

	// Step 5: Determine DMARC result
	// A message passes DMARC if at least one mechanism produces an aligned pass
	if result.DKIMAligned || result.SPFAligned {
		result.Result = DMARCResultPass
	} else {
		result.Result = DMARCResultFail
	}

	return result
}

// extractFromDomain extracts the domain from the RFC5322.From header.
func extractFromDomain(mail *Mail) (string, error) {
	if mail == nil || mail.Content.Headers == nil {
		return "", ErrDMARCNoFromDomain
	}

	fromHeader := mail.Content.Headers.Get("From")
	if fromHeader == "" {
		return "", ErrDMARCNoFromDomain
	}

	// Parse the From header to extract the domain
	// Handle formats like:
	//   sender@example.com
	//   <sender@example.com>
	//   "Display Name" <sender@example.com>
	//   Display Name <sender@example.com>

	domain := extractDomainFromHeader(fromHeader)
	if domain == "" {
		return "", ErrDMARCInvalidFromDomain
	}

	return strings.ToLower(domain), nil
}

// extractDomainFromHeader extracts the domain from an email address in a header.
func extractDomainFromHeader(header string) string {
	// Try to find email in angle brackets first
	if start := strings.LastIndex(header, "<"); start != -1 {
		if end := strings.Index(header[start:], ">"); end != -1 {
			header = header[start+1 : start+end]
		}
	}

	// Remove any surrounding whitespace
	header = strings.TrimSpace(header)

	// Extract domain from email address
	if at := strings.LastIndex(header, "@"); at != -1 {
		return strings.TrimSpace(header[at+1:])
	}

	return ""
}

// extractDomain extracts the domain from an email address.
func extractDomain(email string) string {
	// Handle angle brackets
	email = strings.TrimPrefix(email, "<")
	email = strings.TrimSuffix(email, ">")

	if at := strings.LastIndex(email, "@"); at != -1 {
		return strings.TrimSpace(email[at+1:])
	}
	return email
}

// lookupDMARCRecord looks up the DMARC record for a domain.
// Returns the record, whether the organizational domain was used, and any error.
func lookupDMARCRecord(fromDomain, orgDomain string, resolver func(string) ([]string, error)) (*DMARCRecord, bool, error) {
	// First, try the exact From domain
	record, err := lookupDMARCRecordAt(fromDomain, resolver)
	if err == nil {
		return record, false, nil
	}

	// If no record found at From domain and it differs from org domain, try org domain
	if errors.Is(err, ErrDMARCNoRecord) && !strings.EqualFold(fromDomain, orgDomain) {
		record, err = lookupDMARCRecordAt(orgDomain, resolver)
		if err == nil {
			return record, true, nil
		}
	}

	return nil, false, err
}

// lookupDMARCRecordAt looks up the DMARC record at a specific domain.
func lookupDMARCRecordAt(domain string, resolver func(string) ([]string, error)) (*DMARCRecord, error) {
	dmarcDomain := "_dmarc." + domain

	records, err := resolver(dmarcDomain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return nil, ErrDMARCNoRecord
		}
		return nil, fmt.Errorf("%w: %v", ErrDMARCDNSError, err)
	}

	// Find DMARC records (those starting with "v=DMARC1")
	var dmarcRecords []string
	for _, txt := range records {
		// Per RFC 7489, the version tag must be first and must be exact
		if after, ok := strings.CutPrefix(txt, "v=DMARC1"); ok {
			// Check that v=DMARC1 is followed by separator or end
			rest := after
			if rest == "" || rest[0] == ';' || rest[0] == ' ' {
				dmarcRecords = append(dmarcRecords, txt)
			}
		}
	}

	if len(dmarcRecords) == 0 {
		return nil, ErrDMARCNoRecord
	}

	if len(dmarcRecords) > 1 {
		return nil, ErrDMARCMultipleRecords
	}

	return parseDMARCRecord(dmarcRecords[0])
}

// parseDMARCRecord parses a DMARC DNS record string.
func parseDMARCRecord(raw string) (*DMARCRecord, error) {
	record := &DMARCRecord{
		Raw:            raw,
		DKIMAlignment:  DMARCAlignmentRelaxed, // Default
		SPFAlignment:   DMARCAlignmentRelaxed, // Default
		Percent:        100,                   // Default
		ReportInterval: 86400,                 // Default (24 hours)
		ReportFormat:   "afrf",                // Default
		FailureReportingOptions: DMARCFailureReportingOptions{
			ReportOnAllFail: true, // Default "0"
		},
	}

	// Split on semicolons
	parts := strings.Split(raw, ";")

	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Find the = separator
		before, after, ok := strings.Cut(part, "=")
		if !ok {
			continue // Skip malformed tags
		}

		tag := strings.TrimSpace(before)
		value := strings.TrimSpace(after)

		switch strings.ToLower(tag) {
		case "v":
			// Version must be first tag
			if i != 0 {
				return nil, ErrDMARCInvalidRecord
			}
			if value != "DMARC1" {
				return nil, ErrDMARCInvalidVersion
			}
			record.Version = value

		case "p":
			policy := DMARCPolicy(strings.ToLower(value))
			switch policy {
			case DMARCPolicyNone, DMARCPolicyQuarantine, DMARCPolicyReject:
				record.Policy = policy
			default:
				return nil, fmt.Errorf("%w: %s", ErrDMARCInvalidPolicy, value)
			}

		case "sp":
			policy := DMARCPolicy(strings.ToLower(value))
			switch policy {
			case DMARCPolicyNone, DMARCPolicyQuarantine, DMARCPolicyReject:
				record.SubdomainPolicy = policy
			default:
				// Invalid sp tag - per RFC 7489, ignore or use defaults
			}

		case "adkim":
			switch strings.ToLower(value) {
			case "r":
				record.DKIMAlignment = DMARCAlignmentRelaxed
			case "s":
				record.DKIMAlignment = DMARCAlignmentStrict
			}

		case "aspf":
			switch strings.ToLower(value) {
			case "r":
				record.SPFAlignment = DMARCAlignmentRelaxed
			case "s":
				record.SPFAlignment = DMARCAlignmentStrict
			}

		case "pct":
			pct, err := strconv.Atoi(value)
			if err == nil && pct >= 0 && pct <= 100 {
				record.Percent = pct
			}

		case "rua":
			record.AggregateReportURIs = parseDMARCURIs(value)

		case "ruf":
			record.FailureReportURIs = parseDMARCURIs(value)

		case "ri":
			ri, err := strconv.Atoi(value)
			if err == nil && ri > 0 {
				record.ReportInterval = ri
			}

		case "fo":
			record.FailureReportingOptions = parseFailureReportingOptions(value)

		case "rf":
			record.ReportFormat = value

		default:
			// Unknown tags are ignored per RFC 7489
		}
	}

	// Version must be present
	if record.Version == "" {
		return nil, ErrDMARCInvalidVersion
	}

	// Policy is required for policy records
	if record.Policy == "" {
		// Per RFC 7489, if "rua" is present, treat as p=none
		if len(record.AggregateReportURIs) > 0 {
			record.Policy = DMARCPolicyNone
		} else {
			return nil, ErrDMARCMissingPolicy
		}
	}

	return record, nil
}

// parseDMARCURIs parses a comma-separated list of DMARC URIs.
func parseDMARCURIs(value string) []string {
	var uris []string
	for uri := range strings.SplitSeq(value, ",") {
		uri = strings.TrimSpace(uri)
		if uri != "" {
			// Remove optional size limit (e.g., "mailto:reports@example.com!50m")
			if idx := strings.Index(uri, "!"); idx != -1 {
				uri = uri[:idx]
			}
			uris = append(uris, uri)
		}
	}
	return uris
}

// parseFailureReportingOptions parses the "fo" tag value.
func parseFailureReportingOptions(value string) DMARCFailureReportingOptions {
	opts := DMARCFailureReportingOptions{}

	for opt := range strings.SplitSeq(value, ":") {
		opt = strings.TrimSpace(opt)
		switch opt {
		case "0":
			opts.ReportOnAllFail = true
		case "1":
			opts.ReportOnAnyFail = true
		case "d":
			opts.ReportOnDKIMFail = true
		case "s":
			opts.ReportOnSPFFail = true
		}
	}

	// Default to "0" if nothing specified
	if !opts.ReportOnAllFail && !opts.ReportOnAnyFail && !opts.ReportOnDKIMFail && !opts.ReportOnSPFFail {
		opts.ReportOnAllFail = true
	}

	return opts
}

// checkDKIMAlignment checks if any DKIM result is aligned with the From domain.
func checkDKIMAlignment(results []DKIMResult, fromDomain, orgDomain string, alignment DMARCAlignment) bool {
	for _, r := range results {
		if r.Status != DKIMStatusPass {
			continue
		}

		sigDomain := strings.ToLower(r.Domain)

		if alignment == DMARCAlignmentStrict {
			// Strict mode: exact match required
			if strings.EqualFold(sigDomain, fromDomain) {
				return true
			}
		} else {
			// Relaxed mode: organizational domains must match
			sigOrgDomain := getOrganizationalDomain(sigDomain, isPublicSuffix)
			if strings.EqualFold(sigOrgDomain, orgDomain) {
				return true
			}
		}
	}
	return false
}

// checkSPFAlignment checks if the SPF result is aligned with the From domain.
func checkSPFAlignment(result *SPFCheckResult, fromDomain, orgDomain string, alignment DMARCAlignment) bool {
	if result == nil || result.Result != SPFResultPass {
		return false
	}

	spfDomain := strings.ToLower(result.Domain)

	if alignment == DMARCAlignmentStrict {
		// Strict mode: exact match required
		return strings.EqualFold(spfDomain, fromDomain)
	}

	// Relaxed mode: organizational domains must match
	spfOrgDomain := getOrganizationalDomain(spfDomain, isPublicSuffix)
	return strings.EqualFold(spfOrgDomain, orgDomain)
}

// getOrganizationalDomain determines the organizational domain per RFC 7489.
// The algorithm:
// 1. Get the public suffix for the domain
// 2. The organizational domain is the public suffix plus one label
// Optimized to reduce string allocations by using index-based approach.
func getOrganizationalDomain(domain string, isPS func(string) bool) string {
	if domain == "" {
		return ""
	}

	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")

	// Count labels and find their positions to avoid repeated Split calls
	labelCount := strings.Count(domain, ".") + 1
	if labelCount <= 1 {
		return domain
	}

	// Find the longest public suffix using index-based approach
	// Start from the rightmost position and work left
	searchStart := 0
	for i := 0; i < labelCount; i++ {
		candidate := domain[searchStart:]
		if isPS(candidate) {
			// The organizational domain is the public suffix plus one more label
			if searchStart > 0 {
				// Find the previous label boundary
				prevDot := strings.LastIndex(domain[:searchStart-1], ".")
				if prevDot == -1 {
					return domain // The label before is the first label
				}
				return domain[prevDot+1:]
			}
			// Domain itself is a public suffix (shouldn't be used for email)
			return domain
		}
		// Move to next label
		nextDot := strings.Index(domain[searchStart:], ".")
		if nextDot == -1 {
			break
		}
		searchStart += nextDot + 1
	}

	// No public suffix found; assume TLD is single label
	// Return last two labels
	lastDot := strings.LastIndex(domain, ".")
	if lastDot == -1 {
		return domain
	}
	secondLastDot := strings.LastIndex(domain[:lastDot], ".")
	if secondLastDot == -1 {
		return domain
	}
	return domain[secondLastDot+1:]
}

// isPublicSuffix checks if a domain is a public suffix.
// This is a minimal implementation; production systems should use a complete
// public suffix list from https://publicsuffix.org/
// Uses pre-computed package-level maps for performance.
func isPublicSuffix(domain string) bool {
	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")

	// Check if it's a known TLD (using package-level maps for performance)
	if commonTLDs[domain] || ccTLDs[domain] {
		return true
	}

	// Check if it's a known second-level suffix
	if secondLevelSuffixes[domain] {
		return true
	}

	return false
}

// isDMARCTempError checks if the error is a temporary error.
func isDMARCTempError(err error) bool {
	if err == nil {
		return false
	}

	// Check for DNS temporary errors
	if dnsErr, ok := err.(*net.DNSError); ok {
		return dnsErr.Temporary()
	}

	return errors.Is(err, ErrDMARCDNSError)
}

// DMARCVerifyOptions contains options for server-side DMARC verification.
type DMARCVerifyOptions struct {
	// Enabled enables DMARC checking.
	Enabled bool

	// FailAction specifies what to do when DMARC check returns fail
	// and the domain policy is "reject".
	// Default is to reject the message.
	FailAction DMARCAction

	// QuarantineAction specifies what to do when DMARC check returns fail
	// and the domain policy is "quarantine".
	// Default is to mark the message.
	QuarantineAction DMARCAction

	// CheckOptions contains the underlying DMARC check options.
	CheckOptions *DMARCCheckOptions
}

// DMARCAction specifies the action to take based on DMARC result.
type DMARCAction int

const (
	// DMARCActionNone takes no action (used with p=none).
	DMARCActionNone DMARCAction = iota

	// DMARCActionAccept accepts the message and adds an Authentication-Results header.
	DMARCActionAccept

	// DMARCActionReject rejects the message with a 550 response.
	DMARCActionReject

	// DMARCActionQuarantine marks the message as suspicious (e.g., adds header).
	DMARCActionQuarantine

	// DMARCActionMark accepts but marks the message with headers.
	DMARCActionMark
)

// DefaultDMARCVerifyOptions returns DMARCVerifyOptions with reasonable defaults.
func DefaultDMARCVerifyOptions() *DMARCVerifyOptions {
	return &DMARCVerifyOptions{
		Enabled:          true,
		FailAction:       DMARCActionReject, // Honor the domain owner's policy
		QuarantineAction: DMARCActionMark,
		CheckOptions:     DefaultDMARCCheckOptions(),
	}
}

// AuthenticationResultsHeader generates an Authentication-Results header field per RFC 7001.
func (r *DMARCCheckResult) AuthenticationResultsHeader(receiverDomain string) string {
	var sb strings.Builder

	sb.WriteString("Authentication-Results: ")
	sb.WriteString(receiverDomain)

	// DMARC result
	sb.WriteString(";\r\n\tdmarc=")
	sb.WriteString(string(r.Result))
	sb.WriteString(" (p=")
	if r.Record != nil {
		sb.WriteString(string(r.Record.Policy))
	} else {
		sb.WriteString("none")
	}
	sb.WriteString(" dis=")
	sb.WriteString(string(r.Result))
	sb.WriteString(")")
	sb.WriteString(" header.from=")
	sb.WriteString(r.Domain)

	// Add SPF result if available
	if r.SPFResult != nil {
		sb.WriteString(";\r\n\tspf=")
		sb.WriteString(string(r.SPFResult.Result))
		sb.WriteString(" smtp.mailfrom=")
		sb.WriteString(r.SPFResult.Sender)
	}

	// Add DKIM results if available
	for _, dkim := range r.DKIMResults {
		sb.WriteString(";\r\n\tdkim=")
		sb.WriteString(string(dkim.Status))
		if dkim.Domain != "" {
			sb.WriteString(" header.d=")
			sb.WriteString(dkim.Domain)
		}
		if dkim.Selector != "" {
			sb.WriteString(" header.s=")
			sb.WriteString(dkim.Selector)
		}
	}

	return sb.String()
}

// ValidateDMARC is a regex pattern for validating DMARC record format.
var ValidateDMARC = regexp.MustCompile(`^v=DMARC1(\s*;|$)`)
