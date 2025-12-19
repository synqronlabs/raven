package dmarc

import (
	"fmt"
	"strings"
)

// URI is a destination address for DMARC aggregate or failure reports.
type URI struct {
	// Address is the full URI, typically starting with "mailto:".
	Address string

	// MaxSize is the optional maximum report size.
	MaxSize uint64

	// Unit is the size unit: "" (bytes), "k", "m", "g", or "t".
	// Units are powers of 2 (k = 2^10, etc.).
	Unit string
}

// String returns the URI formatted for a DMARC record.
func (u URI) String() string {
	s := u.Address
	s = strings.ReplaceAll(s, ",", "%2C")
	s = strings.ReplaceAll(s, "!", "%21")
	if u.MaxSize > 0 {
		s += fmt.Sprintf("!%d", u.MaxSize)
	}
	s += u.Unit
	return s
}

// Record is a parsed DMARC DNS TXT record.
//
// Example record:
//
//	v=DMARC1; p=reject; rua=mailto:dmarc@example.com
type Record struct {
	// Version must be "DMARC1".
	Version string

	// Policy is the requested policy for messages that fail DMARC. Required.
	Policy Policy

	// SubdomainPolicy is the policy for subdomains. If empty, Policy applies.
	SubdomainPolicy Policy

	// AggregateReportAddresses are URIs for aggregate reports (rua tag).
	AggregateReportAddresses []URI

	// FailureReportAddresses are URIs for failure reports (ruf tag).
	FailureReportAddresses []URI

	// ADKIM is the DKIM alignment mode: "r" (relaxed) or "s" (strict).
	// Default is "r".
	ADKIM Align

	// ASPF is the SPF alignment mode: "r" (relaxed) or "s" (strict).
	// Default is "r".
	ASPF Align

	// AggregateReportingInterval is the reporting interval in seconds.
	// Default is 86400 (1 day).
	AggregateReportingInterval int

	// FailureReportingOptions control when failure reports are sent.
	// "0" = if all auth fail (default)
	// "1" = if any auth fail
	// "d" = on DKIM failure
	// "s" = on SPF failure
	FailureReportingOptions []string

	// ReportingFormat is the format for failure reports.
	// Default is "afrf".
	ReportingFormat []string

	// Percentage is the percentage of messages to which the policy applies.
	// Between 0 and 100, default is 100.
	Percentage int
}

// DefaultRecord holds the default values for a DMARC record.
var DefaultRecord = Record{
	Version:                    "DMARC1",
	ADKIM:                      AlignRelaxed,
	ASPF:                       AlignRelaxed,
	AggregateReportingInterval: 86400,
	FailureReportingOptions:    []string{"0"},
	ReportingFormat:            []string{"afrf"},
	Percentage:                 100,
}

// String returns the DMARC record formatted for DNS TXT.
func (r Record) String() string {
	var b strings.Builder
	b.WriteString("v=")
	b.WriteString(r.Version)

	write := func(do bool, tag, value string) {
		if do {
			fmt.Fprintf(&b, "; %s=%s", tag, value)
		}
	}

	write(r.Policy != "", "p", string(r.Policy))
	write(r.SubdomainPolicy != "", "sp", string(r.SubdomainPolicy))

	if len(r.AggregateReportAddresses) > 0 {
		addrs := make([]string, len(r.AggregateReportAddresses))
		for i, a := range r.AggregateReportAddresses {
			addrs[i] = a.String()
		}
		write(true, "rua", strings.Join(addrs, ","))
	}

	if len(r.FailureReportAddresses) > 0 {
		addrs := make([]string, len(r.FailureReportAddresses))
		for i, a := range r.FailureReportAddresses {
			addrs[i] = a.String()
		}
		write(true, "ruf", strings.Join(addrs, ","))
	}

	// Only write non-default values
	write(r.ADKIM != AlignRelaxed, "adkim", string(r.ADKIM))
	write(r.ASPF != AlignRelaxed, "aspf", string(r.ASPF))
	write(r.AggregateReportingInterval != 86400, "ri", fmt.Sprintf("%d", r.AggregateReportingInterval))

	if len(r.FailureReportingOptions) > 0 && !(len(r.FailureReportingOptions) == 1 && r.FailureReportingOptions[0] == "0") {
		write(true, "fo", strings.Join(r.FailureReportingOptions, ":"))
	}

	if len(r.ReportingFormat) > 0 && !(len(r.ReportingFormat) == 1 && r.ReportingFormat[0] == "afrf") {
		write(true, "rf", strings.Join(r.ReportingFormat, ":"))
	}

	write(r.Percentage != 100, "pct", fmt.Sprintf("%d", r.Percentage))

	return b.String()
}

// EffectivePolicy returns the effective policy for the given domain.
// If the domain is a subdomain and SubdomainPolicy is set, it returns
// SubdomainPolicy. Otherwise, it returns Policy.
func (r *Record) EffectivePolicy(isSubdomain bool) Policy {
	if isSubdomain && r.SubdomainPolicy != PolicyEmpty {
		return r.SubdomainPolicy
	}
	return r.Policy
}
