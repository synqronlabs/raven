package spf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SPF evaluation errors.
var (
	ErrNoRecord           = errors.New("spf: no SPF record found")
	ErrMultipleRecords    = errors.New("spf: multiple SPF records found")
	ErrTooManyDNSRequests = errors.New("spf: exceeded maximum DNS lookups")
	ErrTooManyVoidLookups = errors.New("spf: exceeded maximum void lookups")
	ErrMacroSyntax        = errors.New("spf: macro syntax error")
	ErrInvalidDomain      = errors.New("spf: invalid domain name")
)

// SPF evaluation limits per RFC 7208.
const (
	// Maximum number of DNS-querying mechanisms and modifiers.
	// This includes: include, a, mx, ptr, exists, redirect.
	dnsRequestsMax = 10

	// Maximum number of "void" lookups (lookups returning no records).
	// This is an anti-abuse measure.
	voidLookupsMax = 2

	// Maximum number of MX or PTR records to process per mechanism.
	mxPtrLimit = 10
)

// Status is the result of SPF verification.
type Status string

const (
	// StatusNone indicates no SPF record was found or no domain to check.
	StatusNone Status = "none"

	// StatusNeutral indicates the domain owner has explicitly stated nothing about the IP.
	// Equivalent to "?" qualifier or no match with no default.
	StatusNeutral Status = "neutral"

	// StatusPass indicates the IP is authorized to send mail for the domain.
	StatusPass Status = "pass"

	// StatusFail indicates the IP is explicitly not authorized. "-" qualifier.
	StatusFail Status = "fail"

	// StatusSoftfail indicates weak statement that IP is probably not authorized. "~" qualifier.
	StatusSoftfail Status = "softfail"

	// StatusTemperror indicates a temporary error (e.g., DNS timeout).
	StatusTemperror Status = "temperror"

	// StatusPermerror indicates a permanent error (e.g., invalid SPF record).
	StatusPermerror Status = "permerror"
)

// Args are the parameters for SPF verification.
type Args struct {
	// RemoteIP is the IP address of the sending server to check.
	RemoteIP net.IP

	// MailFromDomain is the domain from SMTP MAIL FROM.
	// Empty for null reverse-path (bounces).
	MailFromDomain string

	// MailFromLocal is the local-part from SMTP MAIL FROM.
	// Used for macro expansion.
	MailFromLocal string

	// HelloDomain is the domain or IP from SMTP EHLO/HELO command.
	HelloDomain string

	// HelloIsIP indicates if HelloDomain is actually an IP literal.
	HelloIsIP bool

	// LocalIP is the receiving server's IP address. Used for "c" macro.
	LocalIP net.IP

	// LocalHostname is the receiving server's hostname. Used for "r" macro.
	LocalHostname string

	// Logger for debug output.
	Logger *slog.Logger

	// Internal fields for recursive evaluation.
	domain       string  // Current domain being checked
	senderLocal  string  // Effective sender local-part
	senderDomain string  // Effective sender domain
	explanation  *string // Explanation from original domain
	dnsRequests  *int    // Counter for DNS lookups
	voidLookups  *int    // Counter for void lookups
}

// Received contains the SPF verification result for header generation.
type Received struct {
	// Result is the SPF status.
	Result Status

	// Comment provides additional context about the result.
	Comment string

	// ClientIP is the remote IP that was checked.
	ClientIP net.IP

	// EnvelopeFrom is the sender mailbox checked.
	EnvelopeFrom string

	// Helo is the EHLO/HELO domain or IP.
	Helo string

	// Problem describes any error that occurred.
	Problem string

	// Receiver is the hostname of the receiving server.
	Receiver string

	// Identity indicates what was checked: "mailfrom" or "helo".
	Identity string

	// Mechanism is the SPF mechanism that caused the result.
	Mechanism string

	// Authentic indicates if DNS responses were DNSSEC-validated.
	Authentic bool
}

// Header generates a Received-SPF header value.
func (r Received) Header() string {
	var b strings.Builder
	b.WriteString("Received-SPF: ")
	b.WriteString(string(r.Result))

	if r.Comment != "" {
		b.WriteString(" (")
		b.WriteString(r.Comment)
		b.WriteString(")")
	}

	b.WriteString(" client-ip=")
	b.WriteString(encodeHeaderValue(r.ClientIP.String()))
	b.WriteByte(';')

	b.WriteString(" envelope-from=")
	b.WriteString(encodeHeaderValue(r.EnvelopeFrom))
	b.WriteByte(';')

	b.WriteString(" helo=")
	b.WriteString(encodeHeaderValue(r.Helo))
	b.WriteByte(';')

	if r.Problem != "" {
		// Truncate problem to avoid excessively long headers
		problem := r.Problem
		if len(problem) > 60 {
			problem = problem[:60]
		}
		b.WriteString(" problem=")
		b.WriteString(encodeHeaderValue(problem))
		b.WriteByte(';')
	}

	if r.Mechanism != "" {
		b.WriteString(" mechanism=")
		b.WriteString(encodeHeaderValue(r.Mechanism))
		b.WriteByte(';')
	}

	b.WriteString(" receiver=")
	b.WriteString(encodeHeaderValue(r.Receiver))
	b.WriteByte(';')

	b.WriteString(" identity=")
	b.WriteString(encodeHeaderValue(r.Identity))

	return b.String()
}

// encodeHeaderValue encodes a value for use in the Received-SPF header.
func encodeHeaderValue(s string) string {
	if s == "" {
		return `""`
	}
	// Check if quoting is needed
	needsQuote := false
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' ||
			c == '*' || c == '+' || c == '-' || c == '/' || c == '=' || c == '?' ||
			c == '^' || c == '_' || c == '`' || c == '{' || c == '|' || c == '}' || c == '~' ||
			c == '.') {
			needsQuote = true
			break
		}
	}
	if !needsQuote {
		return s
	}

	// Quote the string
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range s {
		if c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	b.WriteByte('"')
	return b.String()
}

// Mocked for testing the "t" macro.
var timeNow = time.Now

// Lookup looks up and parses an SPF TXT record for a domain.
func Lookup(ctx context.Context, resolver Resolver, domain string) (status Status, txt string, record *Record, authentic bool, err error) {
	// Validate domain name
	if err := validateDomain(domain); err != nil {
		return StatusNone, "", nil, false, fmt.Errorf("%w: %v", ErrInvalidDomain, err)
	}

	// Look up TXT records
	txts, result, err := resolver.LookupTXT(ctx, domain+".")
	if errors.Is(err, ErrDNSNotFound) {
		return StatusNone, "", nil, result.Authentic, ErrNoRecord
	}
	if err != nil {
		return StatusTemperror, "", nil, result.Authentic, fmt.Errorf("DNS lookup failed: %w", err)
	}

	// Find SPF records
	var spfRecord *Record
	var spfTxt string
	for _, txt := range txts {
		r, isSPF, parseErr := ParseRecord(txt)
		if !isSPF {
			continue
		}
		if parseErr != nil {
			return StatusPermerror, txt, nil, result.Authentic, fmt.Errorf("%w: %v", ErrRecordSyntax, parseErr)
		}
		if spfRecord != nil {
			// Multiple SPF records is a permanent error
			return StatusPermerror, "", nil, result.Authentic, ErrMultipleRecords
		}
		spfRecord = r
		spfTxt = txt
	}

	if spfRecord == nil {
		return StatusNone, "", nil, result.Authentic, ErrNoRecord
	}

	return StatusNone, spfTxt, spfRecord, result.Authentic, nil
}

// Verify checks if a remote IP is authorized to send email for a domain.
//
// The MailFromDomain is used as the primary identity. If it's empty (null reverse-path),
// the HelloDomain is used instead.
//
// Returns the verification result, the domain that was checked, an explanation
// (for StatusFail), and whether DNS responses were DNSSEC-authenticated.
func Verify(ctx context.Context, resolver Resolver, args Args) (received Received, domain string, explanation string, authentic bool, err error) {
	isHelo, ok := prepareArgs(&args)
	if !ok {
		// No domain to check
		received = Received{
			Result:       StatusNone,
			Comment:      "no domain to check (HELO is IP literal and MAIL FROM is empty)",
			ClientIP:     args.RemoteIP,
			EnvelopeFrom: fmt.Sprintf("%s@%s", args.senderLocal, args.HelloDomain),
			Helo:         args.HelloDomain,
			Receiver:     args.LocalHostname,
			Identity:     "helo",
		}
		return received, "", "", false, nil
	}

	status, mechanism, expl, authentic, err := checkHost(ctx, resolver, args)

	comment := fmt.Sprintf("domain %s", args.domain)
	if isHelo {
		comment += " (from HELO because MAIL FROM is empty)"
	}

	received = Received{
		Result:       status,
		Comment:      comment,
		ClientIP:     args.RemoteIP,
		EnvelopeFrom: fmt.Sprintf("%s@%s", args.senderLocal, args.senderDomain),
		Helo:         args.HelloDomain,
		Receiver:     args.LocalHostname,
		Mechanism:    mechanism,
		Authentic:    authentic,
	}

	if isHelo {
		received.Identity = "helo"
	} else {
		received.Identity = "mailfrom"
	}

	if err != nil {
		received.Problem = err.Error()
	}

	return received, args.domain, expl, authentic, err
}

// Evaluate evaluates an IP and names from args against a pre-parsed SPF record.
// This is useful when the record has been looked up and cached separately.
func Evaluate(ctx context.Context, resolver Resolver, record *Record, args Args) (status Status, mechanism string, explanation string, authentic bool, err error) {
	_, ok := prepareArgs(&args)
	if !ok {
		return StatusNone, "default", "", false, fmt.Errorf("no domain name to validate")
	}
	return evaluate(ctx, resolver, record, args)
}

// prepareArgs sets up the internal fields for SPF verification.
// Returns isHelo (whether HELO domain is being checked) and ok (whether there's a domain to check).
func prepareArgs(args *Args) (isHelo bool, ok bool) {
	// Reset internal state
	args.explanation = nil
	args.dnsRequests = nil
	args.voidLookups = nil

	if args.MailFromDomain == "" {
		// Null reverse-path: check HELO domain instead
		if args.HelloIsIP || args.HelloDomain == "" {
			return false, false
		}
		args.senderLocal = "postmaster"
		args.senderDomain = args.HelloDomain
		isHelo = true
	} else {
		args.senderLocal = args.MailFromLocal
		if args.senderLocal == "" {
			args.senderLocal = "postmaster"
		}
		args.senderDomain = args.MailFromDomain
	}

	args.domain = args.senderDomain
	return isHelo, true
}

// checkHost performs the SPF check_host algorithm.
func checkHost(ctx context.Context, resolver Resolver, args Args) (status Status, mechanism string, explanation string, authentic bool, err error) {
	status, _, record, authentic, err := Lookup(ctx, resolver, args.domain)
	if err != nil {
		return status, "", "", authentic, err
	}

	evalAuthentic := false
	status, mechanism, explanation, evalAuthentic, err = evaluate(ctx, resolver, record, args)
	authentic = authentic && evalAuthentic
	return
}

// evaluate evaluates the SPF record against the args.
func evaluate(ctx context.Context, resolver Resolver, record *Record, args Args) (status Status, mechanism string, explanation string, authentic bool, err error) {
	// Initialize counters if not already done
	if args.dnsRequests == nil {
		args.dnsRequests = new(int)
		args.voidLookups = new(int)
	}

	// Assume authentic until proven otherwise
	authentic = true

	// Determine IP version
	var remote6 net.IP
	remote4 := args.RemoteIP.To4()
	if remote4 == nil {
		remote6 = args.RemoteIP.To16()
	}

	// checkIP checks if an IP matches the remote IP with CIDR masking.
	checkIP := func(ip net.IP, d Directive) bool {
		if remote4 != nil {
			ip4 := ip.To4()
			if ip4 == nil {
				return false
			}
			ones := 32
			if d.IP4CIDRLen != nil {
				ones = *d.IP4CIDRLen
			}
			mask := net.CIDRMask(ones, 32)
			return ip4.Mask(mask).Equal(remote4.Mask(mask))
		}

		ip6 := ip.To16()
		if ip6 == nil {
			return false
		}
		ones := 128
		if d.IP6CIDRLen != nil {
			ones = *d.IP6CIDRLen
		}
		mask := net.CIDRMask(ones, 128)
		return ip6.Mask(mask).Equal(remote6.Mask(mask))
	}

	// checkHostIP checks if any A/AAAA record for a domain matches.
	checkHostIP := func(domain string, d Directive) (bool, Status, error) {
		ips, result, err := resolver.LookupIP(ctx, "ip", domain+".")
		authentic = authentic && result.Authentic
		trackVoidLookup(err, &args)
		if err != nil && !errors.Is(err, ErrDNSNotFound) {
			return false, StatusTemperror, err
		}
		for _, ip := range ips {
			if checkIP(ip, d) {
				return true, StatusPass, nil
			}
		}
		return false, StatusNone, nil
	}

	// Evaluate each directive
	for _, d := range record.Directives {
		// Check DNS lookup limit for mechanisms that require lookups
		switch d.Mechanism {
		case "include", "a", "mx", "ptr", "exists":
			if err := trackLookupLimits(&args); err != nil {
				return StatusPermerror, d.MechanismString(), "", authentic, err
			}
		}

		var match bool

		switch d.Mechanism {
		case "all":
			// Matches everything
			match = true

		case "include":
			// Recursive SPF check
			name, expAuthentic, err := expandDomainSpec(ctx, resolver, d.DomainSpec, args, true)
			authentic = authentic && expAuthentic
			if err != nil {
				return StatusPermerror, d.MechanismString(), "", authentic, fmt.Errorf("expanding include domain: %w", err)
			}

			nargs := args
			nargs.domain = strings.TrimSuffix(name, ".")
			nargs.explanation = &record.Explanation

			includeStatus, _, _, incAuthentic, err := checkHost(ctx, resolver, nargs)
			authentic = authentic && incAuthentic

			switch includeStatus {
			case StatusPass:
				match = true
			case StatusTemperror:
				return StatusTemperror, d.MechanismString(), "", authentic, fmt.Errorf("include %q: %w", name, err)
			case StatusPermerror, StatusNone:
				return StatusPermerror, d.MechanismString(), "", authentic, fmt.Errorf("include %q resulted in %s: %w", name, includeStatus, err)
			}

		case "a":
			host := args.domain
			if d.DomainSpec != "" {
				h, expAuthentic, err := expandDomainSpec(ctx, resolver, d.DomainSpec, args, true)
				authentic = authentic && expAuthentic
				if err != nil {
					return StatusPermerror, d.MechanismString(), "", authentic, err
				}
				host = strings.TrimSuffix(h, ".")
			}

			hmatch, status, err := checkHostIP(host, d)
			if err != nil {
				return status, d.MechanismString(), "", authentic, err
			}
			match = hmatch

		case "mx":
			host := args.domain
			if d.DomainSpec != "" {
				h, expAuthentic, err := expandDomainSpec(ctx, resolver, d.DomainSpec, args, true)
				authentic = authentic && expAuthentic
				if err != nil {
					return StatusPermerror, d.MechanismString(), "", authentic, err
				}
				host = strings.TrimSuffix(h, ".")
			}

			mxs, result, err := resolver.LookupMX(ctx, host+".")
			authentic = authentic && result.Authentic
			trackVoidLookup(err, &args)
			if err != nil && !errors.Is(err, ErrDNSNotFound) {
				return StatusTemperror, d.MechanismString(), "", authentic, err
			}

			// Check for explicit "no MX" record
			if err == nil && len(mxs) == 1 && mxs[0].Host == "." {
				continue
			}

			// Process up to mxPtrLimit MX records
			for i, mx := range mxs {
				if i >= mxPtrLimit {
					return StatusPermerror, d.MechanismString(), "", authentic, ErrTooManyDNSRequests
				}
				mxHost := strings.TrimSuffix(mx.Host, ".")
				if mxHost == "" {
					continue
				}

				hmatch, status, err := checkHostIP(mxHost, d)
				if err != nil {
					return status, d.MechanismString(), "", authentic, err
				}
				if hmatch {
					match = true
					break
				}
			}

		case "ptr":
			host := args.domain
			if d.DomainSpec != "" {
				h, expAuthentic, err := expandDomainSpec(ctx, resolver, d.DomainSpec, args, true)
				authentic = authentic && expAuthentic
				if err != nil {
					return StatusPermerror, d.MechanismString(), "", authentic, err
				}
				host = strings.TrimSuffix(h, ".")
			}

			// Reverse lookup
			rnames, result, err := resolver.LookupAddr(ctx, args.RemoteIP.String())
			authentic = authentic && result.Authentic
			trackVoidLookup(err, &args)
			if err != nil && !errors.Is(err, ErrDNSNotFound) {
				return StatusTemperror, d.MechanismString(), "", authentic, err
			}

			lookups := 0
		ptrLoop:
			for _, rname := range rnames {
				rname = strings.TrimSuffix(rname, ".")
				if rname == "" {
					continue
				}

				// Check if the PTR name matches the target domain
				if !strings.EqualFold(rname, host) && !strings.HasSuffix(strings.ToLower(rname), "."+strings.ToLower(host)) {
					continue
				}

				// Verify the PTR record points back to our IP
				if lookups >= mxPtrLimit {
					break
				}
				lookups++

				ips, result, err := resolver.LookupIP(ctx, "ip", rname+".")
				authentic = authentic && result.Authentic
				trackVoidLookup(err, &args)
				for _, ip := range ips {
					if checkIP(ip, d) {
						match = true
						break ptrLoop
					}
				}
			}

		case "ip4":
			if remote4 != nil {
				match = checkIP(d.IP, d)
			}

		case "ip6":
			if remote6 != nil {
				match = checkIP(d.IP, d)
			}

		case "exists":
			name, expAuthentic, err := expandDomainSpec(ctx, resolver, d.DomainSpec, args, true)
			authentic = authentic && expAuthentic
			if err != nil {
				return StatusPermerror, d.MechanismString(), "", authentic, fmt.Errorf("expanding exists domain: %w", err)
			}

			ips, result, err := resolver.LookupIP(ctx, "ip4", ensureAbsDNS(name))
			authentic = authentic && result.Authentic
			trackVoidLookup(err, &args)
			if err != nil && !errors.Is(err, ErrDNSNotFound) {
				return StatusTemperror, d.MechanismString(), "", authentic, err
			}
			match = len(ips) > 0

		default:
			return StatusPermerror, d.MechanismString(), "", authentic, fmt.Errorf("unknown mechanism: %s", d.Mechanism)
		}

		if !match {
			continue
		}

		// Determine result based on qualifier
		switch d.Qualifier {
		case "", "+":
			return StatusPass, d.MechanismString(), "", authentic, nil
		case "?":
			return StatusNeutral, d.MechanismString(), "", authentic, nil
		case "-":
			// Get explanation for fail
			expAuthentic := false
			expl := ""
			expl, expAuthentic = getExplanation(ctx, resolver, record, args)
			authentic = authentic && expAuthentic
			return StatusFail, d.MechanismString(), expl, authentic, nil
		case "~":
			return StatusSoftfail, d.MechanismString(), "", authentic, nil
		}
	}

	// No directive matched, check for redirect
	if record.Redirect != "" {
		if err := trackLookupLimits(&args); err != nil {
			return StatusPermerror, "", "", authentic, err
		}

		name, expAuthentic, err := expandDomainSpec(ctx, resolver, record.Redirect, args, true)
		authentic = authentic && expAuthentic
		if err != nil {
			return StatusPermerror, "", "", authentic, fmt.Errorf("expanding redirect domain: %w", err)
		}

		nargs := args
		nargs.domain = strings.TrimSuffix(name, ".")
		nargs.explanation = nil // Redirect clears explanation

		status, mechanism, expl, redAuthentic, err := checkHost(ctx, resolver, nargs)
		authentic = authentic && redAuthentic

		if status == StatusNone {
			return StatusPermerror, mechanism, "", authentic, err
		}
		return status, mechanism, expl, authentic, err
	}

	// Default result is neutral
	return StatusNeutral, "default", "", authentic, nil
}

// getExplanation fetches the explanation for a fail result.
func getExplanation(ctx context.Context, resolver Resolver, record *Record, args Args) (string, bool) {
	expl := record.Explanation
	if args.explanation != nil {
		expl = *args.explanation
	}

	if expl == "" {
		return "", true
	}

	// Reset counters for explanation lookup
	args.dnsRequests = new(int)
	args.voidLookups = new(int)

	name, authentic, err := expandDomainSpec(ctx, resolver, expl, args, true)
	if err != nil || name == "" {
		return "", authentic
	}

	txts, result, err := resolver.LookupTXT(ctx, ensureAbsDNS(name))
	authentic = authentic && result.Authentic
	if err != nil || len(txts) == 0 {
		return "", authentic
	}

	txt := strings.Join(txts, "")
	s, expAuthentic, err := expandDomainSpec(ctx, resolver, txt, args, false)
	authentic = authentic && expAuthentic
	if err != nil {
		return "", authentic
	}

	return s, authentic
}

// expandDomainSpec expands macros in a domain-spec.
func expandDomainSpec(ctx context.Context, resolver Resolver, spec string, args Args, isDNS bool) (string, bool, error) {
	authentic := true

	var b strings.Builder
	i := 0
	n := len(spec)

	for i < n {
		c := spec[i]
		i++

		if c != '%' {
			b.WriteByte(c)
			continue
		}

		if i >= n {
			return "", authentic, fmt.Errorf("%w: trailing %%", ErrMacroSyntax)
		}
		c = spec[i]
		i++

		switch c {
		case '%':
			b.WriteByte('%')
			continue
		case '_':
			b.WriteByte(' ')
			continue
		case '-':
			b.WriteString("%20")
			continue
		case '{':
			// Parse macro
		default:
			return "", authentic, fmt.Errorf("%w: invalid macro %%%c", ErrMacroSyntax, c)
		}

		if i >= n {
			return "", authentic, fmt.Errorf("%w: incomplete macro", ErrMacroSyntax)
		}
		c = spec[i]
		i++

		upper := false
		if c >= 'A' && c <= 'Z' {
			upper = true
			c += 'a' - 'A'
		}

		var v string
		switch c {
		case 's':
			v = args.senderLocal + "@" + args.senderDomain
		case 'l':
			v = args.senderLocal
		case 'o':
			v = args.senderDomain
		case 'd':
			v = args.domain
		case 'i':
			v = expandIP(args.RemoteIP)
		case 'p':
			// PTR validation macro
			if err := trackLookupLimits(&args); err != nil {
				return "", authentic, err
			}
			names, result, err := resolver.LookupAddr(ctx, args.RemoteIP.String())
			authentic = authentic && result.Authentic
			trackVoidLookup(err, &args)
			if len(names) == 0 || err != nil {
				v = "unknown"
				break
			}

			// Find a validated PTR name
			v = findValidatedPTR(ctx, resolver, names, args, &authentic)
		case 'v':
			if args.RemoteIP.To4() != nil {
				v = "in-addr"
			} else {
				v = "ip6"
			}
		case 'h':
			v = args.HelloDomain
		case 'c':
			if !isDNS {
				if args.LocalIP != nil {
					v = args.LocalIP.String()
				}
			} else {
				return "", authentic, fmt.Errorf("%w: macro %%c only allowed in exp", ErrMacroSyntax)
			}
		case 'r':
			if !isDNS {
				v = args.LocalHostname
			} else {
				return "", authentic, fmt.Errorf("%w: macro %%r only allowed in exp", ErrMacroSyntax)
			}
		case 't':
			if !isDNS {
				v = fmt.Sprintf("%d", timeNow().Unix())
			} else {
				return "", authentic, fmt.Errorf("%w: macro %%t only allowed in exp", ErrMacroSyntax)
			}
		default:
			return "", authentic, fmt.Errorf("%w: unknown macro letter %c", ErrMacroSyntax, c)
		}

		// Parse optional transformer
		digits := ""
		for i < n && spec[i] >= '0' && spec[i] <= '9' {
			digits += string(spec[i])
			i++
		}
		nlabels := -1
		if digits != "" {
			nv, err := strconv.Atoi(digits)
			if err != nil {
				return "", authentic, fmt.Errorf("%w: invalid digits %q", ErrMacroSyntax, digits)
			}
			if nv == 0 {
				return "", authentic, fmt.Errorf("%w: zero labels not allowed", ErrMacroSyntax)
			}
			nlabels = nv
		}

		// Optional reverse
		reverse := false
		if i < n && (spec[i] == 'r' || spec[i] == 'R') {
			reverse = true
			i++
		}

		// Optional delimiters
		delim := ""
		for i < n {
			switch spec[i] {
			case '.', '-', '+', ',', '/', '_', '=':
				delim += string(spec[i])
				i++
				continue
			}
			break
		}

		// Closing brace
		if i >= n || spec[i] != '}' {
			return "", authentic, fmt.Errorf("%w: missing closing }", ErrMacroSyntax)
		}
		i++

		// Apply transformers
		if nlabels >= 0 || reverse || delim != "" {
			if delim == "" {
				delim = "."
			}
			t := splitByDelim(v, delim)
			if reverse {
				reverseSlice(t)
			}
			if nlabels > 0 && nlabels < len(t) {
				t = t[len(t)-nlabels:]
			}
			v = strings.Join(t, ".")
		}

		// URL encode if uppercase
		if upper {
			v = url.QueryEscape(v)
		}

		b.WriteString(v)
	}

	result := b.String()

	if isDNS {
		// Ensure absolute DNS name
		isAbs := strings.HasSuffix(result, ".")
		if !isAbs {
			result += "."
		}

		// Validate and truncate if necessary
		if err := validateDomain(strings.TrimSuffix(result, ".")); err != nil {
			return "", authentic, err
		}

		// Truncate to 253 characters by removing labels from the left
		if len(result) > 254 {
			labels := strings.Split(result, ".")
			for i := range labels {
				if i == len(labels)-1 {
					return "", authentic, fmt.Errorf("expanded domain too long")
				}
				s := strings.Join(labels[i+1:], ".")
				if len(s) <= 254 {
					result = s
					break
				}
			}
		}

		if !isAbs {
			result = strings.TrimSuffix(result, ".")
		}
	}

	return result, authentic, nil
}

// findValidatedPTR finds a PTR name that validates back to the remote IP.
func findValidatedPTR(ctx context.Context, resolver Resolver, names []string, args Args, authentic *bool) string {
	domain := strings.ToLower(args.domain) + "."
	dotDomain := "." + domain

	// First try exact match
	for _, name := range names {
		nameLower := strings.ToLower(name)
		if nameLower == domain {
			if validatePTR(ctx, resolver, name, args, authentic) {
				return strings.TrimSuffix(name, ".")
			}
		}
	}

	// Then subdomain match
	for _, name := range names {
		nameLower := strings.ToLower(name)
		if strings.HasSuffix(nameLower, dotDomain) {
			if validatePTR(ctx, resolver, name, args, authentic) {
				return strings.TrimSuffix(name, ".")
			}
		}
	}

	// Finally any other name
	for _, name := range names {
		nameLower := strings.ToLower(name)
		if nameLower != domain && !strings.HasSuffix(nameLower, dotDomain) {
			if validatePTR(ctx, resolver, name, args, authentic) {
				return strings.TrimSuffix(name, ".")
			}
		}
	}

	return "unknown"
}

// validatePTR checks if a PTR name resolves back to the remote IP.
func validatePTR(ctx context.Context, resolver Resolver, name string, args Args, authentic *bool) bool {
	ips, result, err := resolver.LookupIP(ctx, "ip", name)
	*authentic = *authentic && result.Authentic
	trackVoidLookup(err, &args)
	for _, ip := range ips {
		if ip.Equal(args.RemoteIP) {
			return true
		}
	}
	return false
}

// expandIP expands an IP address for the "i" macro.
func expandIP(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 != nil {
		return ip4.String()
	}
	// IPv6: expand to dotted nibble format
	ip6 := ip.To16()
	var b strings.Builder
	for i, by := range ip6 {
		if i > 0 {
			b.WriteByte('.')
		}
		fmt.Fprintf(&b, "%x.%x", by>>4, by&0xf)
	}
	return b.String()
}

// ensureAbsDNS ensures a DNS name has a trailing dot.
func ensureAbsDNS(s string) string {
	if !strings.HasSuffix(s, ".") {
		return s + "."
	}
	return s
}

// splitByDelim splits a string by any character in delim.
func splitByDelim(s, delim string) []string {
	isDelim := func(c rune) bool {
		for _, d := range delim {
			if d == c {
				return true
			}
		}
		return false
	}

	var result []string
	start := 0
	for i, c := range s {
		if isDelim(c) {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}

// reverseSlice reverses a slice in place.
func reverseSlice(s []string) {
	n := len(s)
	for i := range n / 2 {
		s[i], s[n-1-i] = s[n-1-i], s[i]
	}
}

// validateDomain checks if a domain name is valid.
func validateDomain(s string) error {
	if s == "" {
		return fmt.Errorf("empty domain")
	}

	labels := strings.Split(s, ".")
	if len(labels) > 127 {
		return fmt.Errorf("too many labels")
	}

	for _, label := range labels {
		if len(label) > 63 {
			return fmt.Errorf("label too long")
		}
		if label == "" && s != "" {
			// Allow trailing dot but not empty labels otherwise
			continue
		}
	}

	return nil
}

// trackLookupLimits checks and increments DNS lookup counters.
func trackLookupLimits(args *Args) error {
	if *args.dnsRequests >= dnsRequestsMax {
		return ErrTooManyDNSRequests
	}
	if *args.voidLookups >= voidLookupsMax {
		return ErrTooManyVoidLookups
	}
	*args.dnsRequests++
	return nil
}

// trackVoidLookup increments the void lookup counter if the error indicates no records.
func trackVoidLookup(err error, args *Args) {
	if errors.Is(err, ErrDNSNotFound) {
		*args.voidLookups++
	}
}
