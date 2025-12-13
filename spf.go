package raven

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SPF Errors per RFC 7208
var (
	ErrSPFNoRecord           = errors.New("spf: no SPF record found")
	ErrSPFMultipleRecords    = errors.New("spf: multiple SPF records found")
	ErrSPFInvalidRecord      = errors.New("spf: invalid SPF record syntax")
	ErrSPFTooManyDNSLookups  = errors.New("spf: too many DNS lookups (limit 10)")
	ErrSPFTooManyVoidLookups = errors.New("spf: too many void lookups (limit 2)")
	ErrSPFDNSError           = errors.New("spf: DNS lookup error")
	ErrSPFInvalidDomain      = errors.New("spf: invalid domain")
	ErrSPFInvalidMacro       = errors.New("spf: invalid macro")
)

// SPFResult represents the result of SPF verification per RFC 7208 Section 2.6.
type SPFResult string

const (
	// SPFResultNone means no syntactically valid DNS domain name was extracted
	// or no SPF records were retrieved from DNS.
	SPFResultNone SPFResult = "none"

	// SPFResultNeutral means the ADMD has explicitly stated that it is
	// not asserting whether the IP address is authorized.
	SPFResultNeutral SPFResult = "neutral"

	// SPFResultPass means the client is authorized to inject mail with the given identity.
	SPFResultPass SPFResult = "pass"

	// SPFResultFail means the client is NOT authorized to use the domain in the given identity.
	SPFResultFail SPFResult = "fail"

	// SPFResultSoftfail is a weak statement that the host is probably not authorized.
	SPFResultSoftfail SPFResult = "softfail"

	// SPFResultTemperror means the SPF verifier encountered a transient (DNS) error.
	SPFResultTemperror SPFResult = "temperror"

	// SPFResultPermerror means the domain's published records could not be correctly interpreted.
	SPFResultPermerror SPFResult = "permerror"
)

// SPFQualifier represents a mechanism qualifier per RFC 7208 Section 4.6.2.
type SPFQualifier string

const (
	SPFQualifierPass     SPFQualifier = "+"
	SPFQualifierFail     SPFQualifier = "-"
	SPFQualifierSoftfail SPFQualifier = "~"
	SPFQualifierNeutral  SPFQualifier = "?"
)

// SPFMechanismType represents the type of SPF mechanism.
type SPFMechanismType string

const (
	SPFMechanismAll     SPFMechanismType = "all"
	SPFMechanismInclude SPFMechanismType = "include"
	SPFMechanismA       SPFMechanismType = "a"
	SPFMechanismMX      SPFMechanismType = "mx"
	SPFMechanismPTR     SPFMechanismType = "ptr"
	SPFMechanismIP4     SPFMechanismType = "ip4"
	SPFMechanismIP6     SPFMechanismType = "ip6"
	SPFMechanismExists  SPFMechanismType = "exists"
)

// SPFMechanism represents a parsed SPF mechanism.
type SPFMechanism struct {
	Qualifier SPFQualifier
	Type      SPFMechanismType
	Value     string     // Domain spec or IP network
	CIDR      int        // CIDR prefix length (-1 if not specified)
	CIDR6     int        // IPv6 CIDR prefix length for dual-cidr (-1 if not specified)
	IPNet     *net.IPNet // Parsed IP network for ip4/ip6 mechanisms
}

// SPFModifier represents a parsed SPF modifier.
type SPFModifier struct {
	Name  string
	Value string
}

// SPFRecord represents a parsed SPF record per RFC 7208.
type SPFRecord struct {
	Version    string
	Mechanisms []SPFMechanism
	Redirect   string // redirect modifier value
	Exp        string // exp modifier value
	Raw        string
}

// SPFCheckResult contains the full result of an SPF check.
type SPFCheckResult struct {
	// Result is the SPF evaluation result.
	Result SPFResult

	// Domain is the domain that was checked.
	Domain string

	// Sender is the sender identity that was checked.
	Sender string

	// ClientIP is the IP address of the client.
	ClientIP net.IP

	// Mechanism is the mechanism that matched (or "default" if none matched).
	Mechanism string

	// Explanation is the explanation string from the exp modifier (for fail results).
	Explanation string

	// Error contains details if an error occurred.
	Error error
}

// SPFCheckOptions contains options for SPF verification.
type SPFCheckOptions struct {
	// DNSResolver is a custom DNS resolver for TXT lookups.
	// If nil, net.LookupTXT is used.
	DNSResolver func(domain string) ([]string, error)

	// DNSLookupA is a custom DNS resolver for A record lookups.
	// If nil, net.LookupIP is used.
	DNSLookupA func(domain string) ([]net.IP, error)

	// DNSLookupMX is a custom DNS resolver for MX record lookups.
	// If nil, net.LookupMX is used.
	DNSLookupMX func(domain string) ([]*net.MX, error)

	// DNSLookupPTR is a custom DNS resolver for PTR record lookups.
	// If nil, net.LookupAddr is used.
	DNSLookupPTR func(ip string) ([]string, error)

	// HeloDomain is the HELO/EHLO domain for macro expansion.
	// Required for the %{h} macro.
	HeloDomain string

	// ReceiverDomain is the domain of the receiving mail server.
	// Used for the %{r} macro in explanations.
	ReceiverDomain string

	// MaxDNSLookups is the maximum number of DNS lookups allowed.
	// Default is 10 per RFC 7208 Section 4.6.4.
	MaxDNSLookups int

	// MaxVoidLookups is the maximum number of void lookups allowed.
	// Default is 2 per RFC 7208 Section 4.6.4.
	MaxVoidLookups int

	// Timeout is the maximum time for the entire SPF check.
	// Default is 20 seconds per RFC 7208 Section 4.6.4.
	Timeout time.Duration
}

// DefaultSPFCheckOptions returns SPFCheckOptions with defaults per RFC 7208.
func DefaultSPFCheckOptions() *SPFCheckOptions {
	return &SPFCheckOptions{
		DNSResolver:    net.LookupTXT,
		DNSLookupA:     net.LookupIP,
		DNSLookupMX:    net.LookupMX,
		DNSLookupPTR:   net.LookupAddr,
		MaxDNSLookups:  10,
		MaxVoidLookups: 2,
		Timeout:        20 * time.Second,
	}
}

// spfChecker holds state during SPF evaluation.
type spfChecker struct {
	opts         *SPFCheckOptions
	ip           net.IP
	sender       string
	senderLocal  string
	senderDomain string
	heloDomain   string
	dnsLookups   int
	voidLookups  int
}

// CheckSPF performs an SPF check for the given parameters per RFC 7208.
//
// Parameters:
//   - ip: The IP address of the SMTP client
//   - domain: The domain to check (from MAIL FROM or HELO)
//   - sender: The full sender identity (e.g., "user@example.com")
//   - opts: Optional configuration (nil uses defaults)
//
// Returns an SPFCheckResult with the evaluation result.
func CheckSPF(ip net.IP, domain, sender string, opts *SPFCheckOptions) *SPFCheckResult {
	if opts == nil {
		opts = DefaultSPFCheckOptions()
	}

	result := &SPFCheckResult{
		Domain:   domain,
		Sender:   sender,
		ClientIP: ip,
	}

	// Initial processing per RFC 7208 Section 4.3
	// Check for malformed domain
	if !isValidDomain(domain) {
		result.Result = SPFResultNone
		result.Error = ErrSPFInvalidDomain
		return result
	}

	// If sender has no local-part, substitute "postmaster"
	senderLocal, senderDomain := parseSender(sender)
	if senderLocal == "" {
		senderLocal = "postmaster"
	}

	checker := &spfChecker{
		opts:         opts,
		ip:           ip,
		sender:       sender,
		senderLocal:  senderLocal,
		senderDomain: senderDomain,
		heloDomain:   opts.HeloDomain,
	}

	// Perform the check
	spfResult, mechanism, err := checker.checkHost(domain)
	result.Result = spfResult
	result.Mechanism = mechanism
	if err != nil {
		result.Error = err
	}

	return result
}

// checkHost implements the check_host() function per RFC 7208 Section 4.
func (c *spfChecker) checkHost(domain string) (SPFResult, string, error) {
	// Lookup SPF record
	record, err := c.lookupSPF(domain)
	if err != nil {
		if errors.Is(err, ErrSPFNoRecord) {
			return SPFResultNone, "default", nil
		}
		if errors.Is(err, ErrSPFMultipleRecords) || errors.Is(err, ErrSPFInvalidRecord) {
			return SPFResultPermerror, "default", err
		}
		// DNS errors return temperror
		return SPFResultTemperror, "default", err
	}

	// Evaluate the record
	return c.evaluateRecord(record, domain)
}

// lookupSPF retrieves and parses the SPF record for a domain.
func (c *spfChecker) lookupSPF(domain string) (*SPFRecord, error) {
	resolver := c.opts.DNSResolver
	if resolver == nil {
		resolver = net.LookupTXT
	}

	records, err := resolver(domain)
	if err != nil {
		// Check for NXDOMAIN (no such domain)
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return nil, ErrSPFNoRecord
		}
		return nil, fmt.Errorf("%w: %v", ErrSPFDNSError, err)
	}

	// Find SPF records (those starting with "v=spf1")
	var spfRecords []string
	for _, txt := range records {
		// Per RFC 7208 Section 4.5, records must begin with "v=spf1"
		// followed by SP or end of record
		if txt == "v=spf1" || strings.HasPrefix(txt, "v=spf1 ") {
			spfRecords = append(spfRecords, txt)
		}
	}

	if len(spfRecords) == 0 {
		return nil, ErrSPFNoRecord
	}

	// Per RFC 7208 Section 4.5, multiple records is permerror
	if len(spfRecords) > 1 {
		return nil, ErrSPFMultipleRecords
	}

	return parseSPFRecord(spfRecords[0])
}

// parseSPFRecord parses an SPF record string into an SPFRecord struct.
func parseSPFRecord(raw string) (*SPFRecord, error) {
	record := &SPFRecord{
		Raw:     raw,
		Version: "spf1",
	}

	// Remove the version prefix
	terms := strings.TrimPrefix(raw, "v=spf1")
	terms = strings.TrimSpace(terms)

	if terms == "" {
		return record, nil
	}

	// Split on whitespace
	parts := strings.FieldsSeq(terms)

	for part := range parts {
		// Check if it's a modifier (contains "=")
		if strings.Contains(part, "=") && !strings.HasPrefix(part, "+") &&
			!strings.HasPrefix(part, "-") && !strings.HasPrefix(part, "~") &&
			!strings.HasPrefix(part, "?") {
			// It's a modifier
			idx := strings.Index(part, "=")
			name := strings.ToLower(part[:idx])
			value := part[idx+1:]

			switch name {
			case "redirect":
				record.Redirect = value
			case "exp":
				record.Exp = value
			default:
				// Unknown modifiers are ignored per RFC 7208 Section 6
			}
			continue
		}

		// Parse mechanism
		mech, err := parseMechanism(part)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSPFInvalidRecord, err)
		}
		record.Mechanisms = append(record.Mechanisms, mech)
	}

	return record, nil
}

// parseMechanism parses a single SPF mechanism.
func parseMechanism(s string) (SPFMechanism, error) {
	mech := SPFMechanism{
		Qualifier: SPFQualifierPass, // Default is "+"
		CIDR:      -1,
		CIDR6:     -1,
	}

	// Extract qualifier
	if len(s) > 0 {
		switch s[0] {
		case '+':
			mech.Qualifier = SPFQualifierPass
			s = s[1:]
		case '-':
			mech.Qualifier = SPFQualifierFail
			s = s[1:]
		case '~':
			mech.Qualifier = SPFQualifierSoftfail
			s = s[1:]
		case '?':
			mech.Qualifier = SPFQualifierNeutral
			s = s[1:]
		}
	}

	// Extract mechanism type and value
	s = strings.ToLower(s)

	// Check for CIDR suffix
	cidrIdx := strings.LastIndex(s, "/")
	cidrStr := ""
	if cidrIdx != -1 {
		cidrStr = s[cidrIdx:]
		s = s[:cidrIdx]
	}

	// Parse mechanism type
	colonIdx := strings.Index(s, ":")
	var mechType, value string
	if colonIdx != -1 {
		mechType = s[:colonIdx]
		value = s[colonIdx+1:]
	} else {
		mechType = s
		value = ""
	}

	switch mechType {
	case "all":
		mech.Type = SPFMechanismAll
	case "include":
		mech.Type = SPFMechanismInclude
		if value == "" {
			return mech, errors.New("include requires domain-spec")
		}
		mech.Value = value
	case "a":
		mech.Type = SPFMechanismA
		mech.Value = value
	case "mx":
		mech.Type = SPFMechanismMX
		mech.Value = value
	case "ptr":
		mech.Type = SPFMechanismPTR
		mech.Value = value
	case "ip4":
		mech.Type = SPFMechanismIP4
		if value == "" {
			return mech, errors.New("ip4 requires network")
		}
		mech.Value = value
		// Parse IP network
		if cidrStr != "" {
			value = value + cidrStr
		} else {
			value = value + "/32"
		}
		_, ipNet, err := net.ParseCIDR(value)
		if err != nil {
			// Try as single IP
			ip := net.ParseIP(mech.Value)
			if ip == nil {
				return mech, fmt.Errorf("invalid ip4 address: %s", mech.Value)
			}
			mask := net.CIDRMask(32, 32)
			ipNet = &net.IPNet{IP: ip, Mask: mask}
		}
		mech.IPNet = ipNet
	case "ip6":
		mech.Type = SPFMechanismIP6
		if value == "" {
			return mech, errors.New("ip6 requires network")
		}
		mech.Value = value
		// Parse IP network
		if cidrStr != "" {
			value = value + cidrStr
		} else {
			value = value + "/128"
		}
		_, ipNet, err := net.ParseCIDR(value)
		if err != nil {
			// Try as single IP
			ip := net.ParseIP(mech.Value)
			if ip == nil {
				return mech, fmt.Errorf("invalid ip6 address: %s", mech.Value)
			}
			mask := net.CIDRMask(128, 128)
			ipNet = &net.IPNet{IP: ip, Mask: mask}
		}
		mech.IPNet = ipNet
	case "exists":
		mech.Type = SPFMechanismExists
		if value == "" {
			return mech, errors.New("exists requires domain-spec")
		}
		mech.Value = value
	default:
		return mech, fmt.Errorf("unknown mechanism: %s", mechType)
	}

	// Parse CIDR for non-ip mechanisms
	if cidrStr != "" && mech.Type != SPFMechanismIP4 && mech.Type != SPFMechanismIP6 {
		mech.CIDR, mech.CIDR6 = parseDualCIDR(cidrStr)
	}

	return mech, nil
}

// parseDualCIDR parses a dual-cidr-length string.
// Format: /cidr4 or /cidr4/cidr6 or //cidr6
func parseDualCIDR(s string) (int, int) {
	cidr4, cidr6 := -1, -1
	s = strings.TrimPrefix(s, "/")

	parts := strings.Split(s, "/")
	if len(parts) >= 1 && parts[0] != "" {
		if v, err := strconv.Atoi(parts[0]); err == nil && v >= 0 && v <= 32 {
			cidr4 = v
		}
	}
	if len(parts) >= 2 && parts[1] != "" {
		if v, err := strconv.Atoi(parts[1]); err == nil && v >= 0 && v <= 128 {
			cidr6 = v
		}
	}

	return cidr4, cidr6
}

// evaluateRecord evaluates an SPF record against the current check parameters.
func (c *spfChecker) evaluateRecord(record *SPFRecord, domain string) (SPFResult, string, error) {
	// Evaluate mechanisms from left to right
	for _, mech := range record.Mechanisms {
		match, err := c.evaluateMechanism(mech, domain)
		if err != nil {
			// Check for specific error types
			if errors.Is(err, ErrSPFTooManyDNSLookups) || errors.Is(err, ErrSPFTooManyVoidLookups) {
				return SPFResultPermerror, "default", err
			}
			// DNS errors during mechanism evaluation return temperror
			return SPFResultTemperror, "default", err
		}

		if match {
			return qualifierToResult(mech.Qualifier), mechToString(mech), nil
		}
	}

	// No mechanism matched
	// Check for redirect modifier per RFC 7208 Section 6.1
	if record.Redirect != "" {
		// redirect is only used if no mechanisms matched
		// and there is no "all" mechanism
		hasAll := false
		for _, m := range record.Mechanisms {
			if m.Type == SPFMechanismAll {
				hasAll = true
				break
			}
		}

		if !hasAll {
			redirectDomain := c.expandMacros(record.Redirect, domain)
			if !isValidDomain(redirectDomain) {
				return SPFResultPermerror, "default", ErrSPFInvalidDomain
			}

			c.dnsLookups++
			if c.dnsLookups > c.opts.MaxDNSLookups {
				return SPFResultPermerror, "default", ErrSPFTooManyDNSLookups
			}

			result, mech, err := c.checkHost(redirectDomain)
			// Per RFC 7208 Section 6.1, if redirect returns none, it becomes permerror
			if result == SPFResultNone {
				return SPFResultPermerror, mech, err
			}
			return result, mech, err
		}
	}

	// Default result is neutral per RFC 7208 Section 4.7
	return SPFResultNeutral, "default", nil
}

// evaluateMechanism evaluates a single mechanism against the current check parameters.
func (c *spfChecker) evaluateMechanism(mech SPFMechanism, domain string) (bool, error) {
	switch mech.Type {
	case SPFMechanismAll:
		return true, nil

	case SPFMechanismInclude:
		return c.evalInclude(mech, domain)

	case SPFMechanismA:
		return c.evalA(mech, domain)

	case SPFMechanismMX:
		return c.evalMX(mech, domain)

	case SPFMechanismPTR:
		return c.evalPTR(mech, domain)

	case SPFMechanismIP4:
		return c.evalIP4(mech), nil

	case SPFMechanismIP6:
		return c.evalIP6(mech), nil

	case SPFMechanismExists:
		return c.evalExists(mech, domain)
	}

	return false, nil
}

// evalInclude evaluates the "include" mechanism per RFC 7208 Section 5.2.
func (c *spfChecker) evalInclude(mech SPFMechanism, domain string) (bool, error) {
	targetDomain := mech.Value
	if targetDomain == "" {
		targetDomain = domain
	}
	targetDomain = c.expandMacros(targetDomain, domain)

	// Include causes a DNS lookup
	c.dnsLookups++
	if c.dnsLookups > c.opts.MaxDNSLookups {
		return false, ErrSPFTooManyDNSLookups
	}

	result, _, err := c.checkHost(targetDomain)

	// Per RFC 7208 Section 5.2:
	// pass -> match
	// fail -> not match
	// softfail -> not match
	// neutral -> not match
	// temperror -> return temperror
	// permerror -> return permerror
	// none -> return permerror

	switch result {
	case SPFResultPass:
		return true, nil
	case SPFResultFail, SPFResultSoftfail, SPFResultNeutral:
		return false, nil
	case SPFResultTemperror:
		return false, err
	case SPFResultPermerror:
		return false, err
	case SPFResultNone:
		return false, ErrSPFInvalidRecord
	}

	return false, nil
}

// evalA evaluates the "a" mechanism per RFC 7208 Section 5.3.
func (c *spfChecker) evalA(mech SPFMechanism, domain string) (bool, error) {
	targetDomain := mech.Value
	if targetDomain == "" {
		targetDomain = domain
	}
	targetDomain = c.expandMacros(targetDomain, domain)

	// a mechanism causes a DNS lookup
	c.dnsLookups++
	if c.dnsLookups > c.opts.MaxDNSLookups {
		return false, ErrSPFTooManyDNSLookups
	}

	ips, err := c.lookupA(targetDomain)
	if err != nil {
		c.voidLookups++
		if c.voidLookups > c.opts.MaxVoidLookups {
			return false, ErrSPFTooManyVoidLookups
		}
		// DNS errors for mechanisms that don't match return false, not error
		return false, nil
	}

	if len(ips) == 0 {
		c.voidLookups++
		if c.voidLookups > c.opts.MaxVoidLookups {
			return false, ErrSPFTooManyVoidLookups
		}
		return false, nil
	}

	// Get appropriate CIDR length
	cidr := mech.CIDR
	if c.ip.To4() == nil && mech.CIDR6 != -1 {
		cidr = mech.CIDR6
	}

	for _, ip := range ips {
		if c.ipMatches(ip, cidr) {
			return true, nil
		}
	}

	return false, nil
}

// evalMX evaluates the "mx" mechanism per RFC 7208 Section 5.4.
func (c *spfChecker) evalMX(mech SPFMechanism, domain string) (bool, error) {
	targetDomain := mech.Value
	if targetDomain == "" {
		targetDomain = domain
	}
	targetDomain = c.expandMacros(targetDomain, domain)

	// mx mechanism causes a DNS lookup
	c.dnsLookups++
	if c.dnsLookups > c.opts.MaxDNSLookups {
		return false, ErrSPFTooManyDNSLookups
	}

	resolver := c.opts.DNSLookupMX
	if resolver == nil {
		resolver = net.LookupMX
	}

	mxRecords, err := resolver(targetDomain)
	if err != nil {
		c.voidLookups++
		if c.voidLookups > c.opts.MaxVoidLookups {
			return false, ErrSPFTooManyVoidLookups
		}
		return false, nil
	}

	if len(mxRecords) == 0 {
		c.voidLookups++
		if c.voidLookups > c.opts.MaxVoidLookups {
			return false, ErrSPFTooManyVoidLookups
		}
		return false, nil
	}

	// Per RFC 7208 Section 4.6.4, limit to 10 MX records
	if len(mxRecords) > 10 {
		return false, ErrSPFTooManyDNSLookups
	}

	// Get appropriate CIDR length
	cidr := mech.CIDR
	if c.ip.To4() == nil && mech.CIDR6 != -1 {
		cidr = mech.CIDR6
	}

	// Look up A/AAAA records for each MX
	for _, mx := range mxRecords {
		// Each MX lookup counts toward the DNS limit
		c.dnsLookups++
		if c.dnsLookups > c.opts.MaxDNSLookups {
			return false, ErrSPFTooManyDNSLookups
		}

		ips, err := c.lookupA(mx.Host)
		if err != nil {
			continue
		}

		for _, ip := range ips {
			if c.ipMatches(ip, cidr) {
				return true, nil
			}
		}
	}

	return false, nil
}

// evalPTR evaluates the "ptr" mechanism per RFC 7208 Section 5.5.
// Note: This mechanism is deprecated and SHOULD NOT be used.
func (c *spfChecker) evalPTR(mech SPFMechanism, domain string) (bool, error) {
	targetDomain := mech.Value
	if targetDomain == "" {
		targetDomain = domain
	}
	targetDomain = c.expandMacros(targetDomain, domain)
	targetDomain = strings.ToLower(targetDomain)

	// ptr mechanism causes a DNS lookup
	c.dnsLookups++
	if c.dnsLookups > c.opts.MaxDNSLookups {
		return false, ErrSPFTooManyDNSLookups
	}

	resolver := c.opts.DNSLookupPTR
	if resolver == nil {
		resolver = net.LookupAddr
	}

	names, err := resolver(c.ip.String())
	if err != nil {
		c.voidLookups++
		if c.voidLookups > c.opts.MaxVoidLookups {
			return false, ErrSPFTooManyVoidLookups
		}
		return false, nil
	}

	if len(names) == 0 {
		c.voidLookups++
		if c.voidLookups > c.opts.MaxVoidLookups {
			return false, ErrSPFTooManyVoidLookups
		}
		return false, nil
	}

	// Per RFC 7208 Section 4.6.4, limit PTR processing
	if len(names) > 10 {
		names = names[:10]
	}

	// Validate each PTR name
	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		name = strings.ToLower(name)

		// Validate by looking up A/AAAA records
		c.dnsLookups++
		if c.dnsLookups > c.opts.MaxDNSLookups {
			return false, ErrSPFTooManyDNSLookups
		}

		ips, err := c.lookupA(name)
		if err != nil {
			continue
		}

		// Check if our IP is among the returned addresses
		validated := false
		for _, ip := range ips {
			if ip.Equal(c.ip) {
				validated = true
				break
			}
		}

		if validated {
			// Check if the validated name matches the target domain
			if name == targetDomain || strings.HasSuffix(name, "."+targetDomain) {
				return true, nil
			}
		}
	}

	return false, nil
}

// evalIP4 evaluates the "ip4" mechanism per RFC 7208 Section 5.6.
func (c *spfChecker) evalIP4(mech SPFMechanism) bool {
	// Only match IPv4 addresses
	if c.ip.To4() == nil {
		return false
	}

	if mech.IPNet == nil {
		return false
	}

	return mech.IPNet.Contains(c.ip)
}

// evalIP6 evaluates the "ip6" mechanism per RFC 7208 Section 5.6.
func (c *spfChecker) evalIP6(mech SPFMechanism) bool {
	if mech.IPNet == nil {
		return false
	}

	return mech.IPNet.Contains(c.ip)
}

// evalExists evaluates the "exists" mechanism per RFC 7208 Section 5.7.
func (c *spfChecker) evalExists(mech SPFMechanism, domain string) (bool, error) {
	targetDomain := c.expandMacros(mech.Value, domain)

	// exists mechanism causes a DNS lookup
	c.dnsLookups++
	if c.dnsLookups > c.opts.MaxDNSLookups {
		return false, ErrSPFTooManyDNSLookups
	}

	// Per RFC 7208 Section 5.7, only A records are checked (even for IPv6)
	ips, err := c.lookupA(targetDomain)
	if err != nil {
		c.voidLookups++
		if c.voidLookups > c.opts.MaxVoidLookups {
			return false, ErrSPFTooManyVoidLookups
		}
		return false, nil
	}

	// If any A record exists, the mechanism matches
	return len(ips) > 0, nil
}

// lookupA performs an A/AAAA record lookup.
func (c *spfChecker) lookupA(domain string) ([]net.IP, error) {
	resolver := c.opts.DNSLookupA
	if resolver == nil {
		resolver = net.LookupIP
	}
	return resolver(domain)
}

// ipMatches checks if the client IP matches the given IP with optional CIDR.
func (c *spfChecker) ipMatches(ip net.IP, cidr int) bool {
	if cidr == -1 {
		// Exact match
		return c.ip.Equal(ip)
	}

	// CIDR match
	var mask net.IPMask
	if c.ip.To4() != nil {
		mask = net.CIDRMask(cidr, 32)
	} else {
		mask = net.CIDRMask(cidr, 128)
	}

	ipNet := &net.IPNet{IP: ip.Mask(mask), Mask: mask}
	return ipNet.Contains(c.ip)
}

// expandMacros expands SPF macros in the given string per RFC 7208 Section 7.
func (c *spfChecker) expandMacros(s, domain string) string {
	// Simple macro expansion - handles the most common cases
	// Full macro expansion with transformers would require more complex parsing

	result := strings.Builder{}
	i := 0

	for i < len(s) {
		if s[i] == '%' && i+1 < len(s) {
			if s[i+1] == '%' {
				result.WriteByte('%')
				i += 2
				continue
			}
			if s[i+1] == '_' {
				result.WriteByte(' ')
				i += 2
				continue
			}
			if s[i+1] == '-' {
				result.WriteString("%20")
				i += 2
				continue
			}
			if s[i+1] == '{' {
				// Find closing brace
				end := strings.Index(s[i:], "}")
				if end == -1 {
					result.WriteByte(s[i])
					i++
					continue
				}

				macro := s[i+2 : i+end]
				expanded := c.expandMacro(macro, domain)
				result.WriteString(expanded)
				i = i + end + 1
				continue
			}
		}
		result.WriteByte(s[i])
		i++
	}

	return result.String()
}

// expandMacro expands a single macro.
func (c *spfChecker) expandMacro(macro, domain string) string {
	if len(macro) == 0 {
		return ""
	}

	letter := strings.ToLower(string(macro[0]))
	// Parse transformers (digits and 'r')
	transformer := ""
	if len(macro) > 1 {
		transformer = macro[1:]
	}

	var value string

	switch letter {
	case "s":
		// <sender>
		value = c.sender
	case "l":
		// local-part of <sender>
		value = c.senderLocal
	case "o":
		// domain of <sender>
		value = c.senderDomain
	case "d":
		// <domain>
		value = domain
	case "i":
		// <ip> in dot format
		value = c.formatIPForMacro()
	case "p":
		// validated domain name of <ip> (deprecated)
		value = "unknown"
	case "v":
		// "in-addr" if IPv4, "ip6" if IPv6
		if c.ip.To4() != nil {
			value = "in-addr"
		} else {
			value = "ip6"
		}
	case "h":
		// HELO/EHLO domain
		value = c.heloDomain
		if value == "" {
			value = "unknown"
		}
	case "c":
		// SMTP client IP (readable format) - only in exp
		value = c.ip.String()
	case "r":
		// receiving domain - only in exp
		value = c.opts.ReceiverDomain
		if value == "" {
			value = "unknown"
		}
	case "t":
		// current timestamp - only in exp
		value = strconv.FormatInt(time.Now().Unix(), 10)
	default:
		return ""
	}

	// Apply transformers
	if transformer != "" {
		value = c.applyTransformers(value, transformer)
	}

	// URL encode if uppercase
	if len(macro) > 0 && macro[0] >= 'A' && macro[0] <= 'Z' {
		value = urlEncode(value)
	}

	return value
}

// formatIPForMacro formats the IP address for use in macros.
func (c *spfChecker) formatIPForMacro() string {
	if c.ip.To4() != nil {
		// IPv4: dotted quad
		return c.ip.String()
	}

	// IPv6: dot-separated nibbles
	ip := c.ip.To16()
	parts := make([]string, 32)
	for i := range 16 {
		parts[i*2] = fmt.Sprintf("%x", ip[i]>>4)
		parts[i*2+1] = fmt.Sprintf("%x", ip[i]&0x0f)
	}
	return strings.Join(parts, ".")
}

// applyTransformers applies macro transformers (digit and 'r').
func (c *spfChecker) applyTransformers(value, transformer string) string {
	// Parse digit
	digits := 0
	reverse := false
	delimiter := "."

	for _, ch := range transformer {
		if ch >= '0' && ch <= '9' {
			digits = digits*10 + int(ch-'0')
		} else if ch == 'r' || ch == 'R' {
			reverse = true
		} else {
			// Custom delimiter
			delimiter = string(ch)
		}
	}

	// Split value
	parts := strings.Split(value, delimiter)

	// Reverse if requested
	if reverse {
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
	}

	// Take only specified number of parts from the right
	if digits > 0 && digits < len(parts) {
		parts = parts[len(parts)-digits:]
	}

	// Rejoin with dots
	return strings.Join(parts, ".")
}

// urlEncode URL-encodes characters not in the unreserved set per RFC 3986.
func urlEncode(s string) string {
	result := strings.Builder{}
	for _, ch := range s {
		if isUnreserved(byte(ch)) {
			result.WriteByte(byte(ch))
		} else {
			result.WriteString(fmt.Sprintf("%%%02X", ch))
		}
	}
	return result.String()
}

// isUnreserved checks if a character is in the unreserved set per RFC 3986.
func isUnreserved(ch byte) bool {
	return (ch >= 'A' && ch <= 'Z') ||
		(ch >= 'a' && ch <= 'z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '-' || ch == '.' || ch == '_' || ch == '~'
}

// qualifierToResult converts an SPF qualifier to a result.
func qualifierToResult(q SPFQualifier) SPFResult {
	switch q {
	case SPFQualifierPass:
		return SPFResultPass
	case SPFQualifierFail:
		return SPFResultFail
	case SPFQualifierSoftfail:
		return SPFResultSoftfail
	case SPFQualifierNeutral:
		return SPFResultNeutral
	default:
		return SPFResultNeutral
	}
}

// mechToString converts a mechanism to a string representation.
func mechToString(mech SPFMechanism) string {
	result := string(mech.Qualifier) + string(mech.Type)
	if mech.Value != "" {
		result += ":" + mech.Value
	}
	if mech.CIDR != -1 {
		result += fmt.Sprintf("/%d", mech.CIDR)
	}
	if mech.CIDR6 != -1 {
		result += fmt.Sprintf("/%d", mech.CIDR6)
	}
	return result
}

// isValidDomain checks if a domain is valid per RFC 7208 Section 4.3.
func isValidDomain(domain string) bool {
	if domain == "" {
		return false
	}

	// Must be multi-label
	if !strings.Contains(domain, ".") {
		return false
	}

	// Check for valid labels
	labels := strings.SplitSeq(domain, ".")
	for label := range labels {
		// Labels can't be empty (except trailing dot)
		if label == "" {
			continue
		}
		// Labels can't exceed 63 characters
		if len(label) > 63 {
			return false
		}
	}

	// Total length can't exceed 253 characters
	if len(domain) > 253 {
		return false
	}

	return true
}

// parseSender extracts local-part and domain from a sender address.
func parseSender(sender string) (local, domain string) {
	if sender == "" {
		return "", ""
	}

	// Handle angle brackets
	sender = strings.TrimPrefix(sender, "<")
	sender = strings.TrimSuffix(sender, ">")

	atIdx := strings.LastIndex(sender, "@")
	if atIdx == -1 {
		// No @ sign, treat entire string as domain
		return "", sender
	}

	return sender[:atIdx], sender[atIdx+1:]
}

// SPFReceivedHeader generates a Received-SPF header field per RFC 7208 Section 9.1.
func (r *SPFCheckResult) ReceivedSPFHeader() string {
	var sb strings.Builder

	sb.WriteString("Received-SPF: ")
	sb.WriteString(string(r.Result))

	// Add comment with details
	sb.WriteString(" (")
	switch r.Result {
	case SPFResultPass:
		sb.WriteString(fmt.Sprintf("%s: domain of %s designates %s as permitted sender",
			r.Domain, r.Sender, r.ClientIP.String()))
	case SPFResultFail:
		sb.WriteString(fmt.Sprintf("%s: domain of %s does not designate %s as permitted sender",
			r.Domain, r.Sender, r.ClientIP.String()))
	default:
		sb.WriteString(fmt.Sprintf("%s: %s", r.Domain, r.Result))
	}
	sb.WriteString(")")

	// Add key-value pairs
	sb.WriteString(fmt.Sprintf(" client-ip=%s;", r.ClientIP.String()))
	if r.Sender != "" {
		sb.WriteString(fmt.Sprintf(" envelope-from=\"%s\";", r.Sender))
	}
	sb.WriteString(fmt.Sprintf(" mechanism=%s;", r.Mechanism))

	return sb.String()
}

// SPFVerifyOptions contains options for server-side SPF verification.
type SPFVerifyOptions struct {
	// Enabled enables SPF checking.
	Enabled bool

	// FailAction specifies what to do when SPF check returns fail.
	// Default is to add header but accept the message.
	FailAction SPFAction

	// SoftFailAction specifies what to do when SPF check returns softfail.
	SoftFailAction SPFAction

	// CheckOptions contains the underlying SPF check options.
	CheckOptions *SPFCheckOptions
}

// SPFAction specifies the action to take based on SPF result.
type SPFAction int

const (
	// SPFActionAccept accepts the message and adds a Received-SPF header.
	SPFActionAccept SPFAction = iota

	// SPFActionReject rejects the message with a 550 response.
	SPFActionReject

	// SPFActionMark accepts the message and adds headers marking it as suspicious.
	SPFActionMark
)

// DefaultSPFVerifyOptions returns SPFVerifyOptions with reasonable defaults.
func DefaultSPFVerifyOptions() *SPFVerifyOptions {
	return &SPFVerifyOptions{
		Enabled:        true,
		FailAction:     SPFActionAccept, // Conservative default
		SoftFailAction: SPFActionAccept,
		CheckOptions:   DefaultSPFCheckOptions(),
	}
}

// ValidateSPF is a regex pattern for validating SPF record format.
var ValidateSPF = regexp.MustCompile(`^v=spf1(\s|$)`)
