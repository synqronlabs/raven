package dmarc

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// parseErr is an internal parsing error.
type parseErr string

func (e parseErr) Error() string {
	return string(e)
}

// ParseRecord parses a DMARC TXT record string.
//
// Fields and values that are case-insensitive in DMARC are returned in lower
// case for easy comparison.
//
// Returns the parsed record, whether the string looks like a DMARC record
// (starts with "v=DMARC1"), and any parsing error.
func ParseRecord(s string) (record *Record, isDMARC bool, err error) {
	return parseRecord(s, true)
}

// ParseRecordNoRequired is like ParseRecord but doesn't check for required
// fields. This is useful for parsing _report._dmarc records used for opting
// into receiving reports for other domains.
func ParseRecordNoRequired(s string) (record *Record, isDMARC bool, err error) {
	return parseRecord(s, false)
}

func parseRecord(s string, checkRequired bool) (record *Record, isDMARC bool, rerr error) {
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		if err, ok := x.(parseErr); ok {
			rerr = err
			return
		}
		panic(x)
	}()

	r := DefaultRecord
	p := newParser(s)

	// v= is required and must be first per RFC 7489 Section 6.3
	p.xtake("v")
	p.wsp()
	p.xtake("=")
	p.wsp()
	r.Version = p.xtakecase("DMARC1")
	p.wsp()
	p.xtake(";")
	isDMARC = true

	seen := map[string]bool{}

	for {
		p.wsp()
		if p.empty() {
			break
		}

		tagName := p.xword()
		tag := strings.ToLower(tagName)

		if seen[tag] {
			// RFC does not explicitly forbid duplicates, but they can only
			// cause confusion, so we reject them.
			p.xerrorf("duplicate tag %q", tagName)
		}
		seen[tag] = true

		p.wsp()
		p.xtake("=")
		p.wsp()

		switch tag {
		case "p":
			// Policy must be the first tag after version (RFC 7489 Section 6.3)
			if len(seen) != 1 {
				p.xerrorf("p= (policy) must be first tag")
			}
			r.Policy = Policy(p.xtakelist("none", "quarantine", "reject"))

		case "sp":
			sp := p.xkeyword()
			r.SubdomainPolicy = Policy(sp)
			// Validate later

		case "rua":
			r.AggregateReportAddresses = append(r.AggregateReportAddresses, p.xuri())
			p.wsp()
			for p.take(",") {
				p.wsp()
				r.AggregateReportAddresses = append(r.AggregateReportAddresses, p.xuri())
				p.wsp()
			}

		case "ruf":
			r.FailureReportAddresses = append(r.FailureReportAddresses, p.xuri())
			p.wsp()
			for p.take(",") {
				p.wsp()
				r.FailureReportAddresses = append(r.FailureReportAddresses, p.xuri())
				p.wsp()
			}

		case "adkim":
			r.ADKIM = Align(p.xtakelist("r", "s"))

		case "aspf":
			r.ASPF = Align(p.xtakelist("r", "s"))

		case "ri":
			r.AggregateReportingInterval = p.xnumber()

		case "fo":
			r.FailureReportingOptions = []string{p.xtakelist("0", "1", "d", "s")}
			p.wsp()
			for p.take(":") {
				p.wsp()
				r.FailureReportingOptions = append(r.FailureReportingOptions, p.xtakelist("0", "1", "d", "s"))
				p.wsp()
			}

		case "rf":
			r.ReportingFormat = []string{p.xkeyword()}
			p.wsp()
			for p.take(":") {
				p.wsp()
				r.ReportingFormat = append(r.ReportingFormat, p.xkeyword())
				p.wsp()
			}

		case "pct":
			r.Percentage = p.xnumber()
			if r.Percentage > 100 {
				p.xerrorf("bad percentage %d", r.Percentage)
			}

		default:
			// Unknown tags - RFC 7489 implies we should be able to parse them.
			// Just consume until the next semicolon or end.
			for !p.empty() {
				if p.peek(';') {
					break
				}
				p.xtaken(1)
			}
		}

		p.wsp()
		if !p.take(";") && !p.empty() {
			p.xerrorf("expected ;")
		}
	}

	// Validate required fields and subdomain policy
	sp := r.SubdomainPolicy
	if checkRequired && (!seen["p"] || sp != PolicyEmpty && sp != PolicyNone && sp != PolicyQuarantine && sp != PolicyReject) {
		// Per RFC 7489 Section 6.6.3, if p= is invalid but rua= is present,
		// treat as p=none.
		if len(r.AggregateReportAddresses) > 0 {
			r.Policy = PolicyNone
			r.SubdomainPolicy = PolicyEmpty
		} else {
			p.xerrorf("invalid (subdomain)policy and no valid aggregate reporting address")
		}
	}

	return &r, true, nil
}

// parser holds state for parsing DMARC records.
type parser struct {
	s     string // Original string
	lower string // Lower-cased string for case-insensitive matching
	o     int    // Current offset
}

// toLower lower-cases ASCII A-Z without affecting other bytes.
func toLower(s string) string {
	r := []byte(s)
	for i, c := range r {
		if c >= 'A' && c <= 'Z' {
			r[i] = c + 0x20
		}
	}
	return string(r)
}

func newParser(s string) *parser {
	return &parser{
		s:     s,
		lower: toLower(s),
	}
}

func (p *parser) xerrorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if p.o < len(p.s) {
		msg += fmt.Sprintf(" (remain %q)", p.s[p.o:])
	}
	panic(parseErr(msg))
}

func (p *parser) empty() bool {
	return p.o >= len(p.s)
}

func (p *parser) peek(b byte) bool {
	return p.o < len(p.s) && p.s[p.o] == b
}

// prefix returns true if the remaining string starts with s (case-insensitive).
func (p *parser) prefix(s string) bool {
	return strings.HasPrefix(p.lower[p.o:], s)
}

func (p *parser) take(s string) bool {
	if p.prefix(s) {
		p.o += len(s)
		return true
	}
	return false
}

func (p *parser) xtaken(n int) string {
	r := p.lower[p.o : p.o+n]
	p.o += n
	return r
}

func (p *parser) xtake(s string) string {
	if !p.prefix(s) {
		p.xerrorf("expected %q", s)
	}
	return p.xtaken(len(s))
}

// xtakecase takes an exact-case string.
func (p *parser) xtakecase(s string) string {
	if !strings.HasPrefix(p.s[p.o:], s) {
		p.xerrorf("expected %q", s)
	}
	r := p.s[p.o : p.o+len(s)]
	p.o += len(s)
	return r
}

// wsp consumes optional whitespace.
func (p *parser) wsp() {
	for !p.empty() && (p.s[p.o] == ' ' || p.s[p.o] == '\t') {
		p.o++
	}
}

// xtakelist takes one of the strings in the list.
func (p *parser) xtakelist(l ...string) string {
	for _, s := range l {
		if p.prefix(s) {
			return p.xtaken(len(s))
		}
	}
	p.xerrorf("expected one of %v", l)
	panic("not reached")
}

func (p *parser) xtakefn1case(fn func(byte, int) bool) string {
	for i, b := range []byte(p.lower[p.o:]) {
		if !fn(b, i) {
			if i == 0 {
				p.xerrorf("expected at least one char")
			}
			return p.xtaken(i)
		}
	}
	if p.empty() {
		p.xerrorf("expected at least 1 char")
	}
	r := p.s[p.o:]
	p.o += len(r)
	return r
}

// xword parses a tag name (alphanumeric).
func (p *parser) xword() string {
	return p.xtakefn1case(func(c byte, _ int) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
	})
}

func (p *parser) xdigits() string {
	return p.xtakefn1case(func(b byte, _ int) bool {
		return isdigit(b)
	})
}

// xuri parses a DMARC URI (rua/ruf value).
func (p *parser) xuri() URI {
	// URIs can contain semicolons, but we assume no one uses them in DMARC.
	// Parse until space/comma/semicolon/end.
	v := p.xtakefn1case(func(b byte, _ int) bool {
		return b != ',' && b != ' ' && b != '\t' && b != ';'
	})

	t := strings.SplitN(v, "!", 2)
	u, err := url.Parse(t[0])
	if err != nil {
		p.xerrorf("parsing uri %q: %s", t[0], err)
	}
	if u.Scheme == "" {
		p.xerrorf("missing scheme in uri")
	}

	uri := URI{
		Address: t[0],
	}

	if len(t) == 2 {
		o := t[1]
		if o != "" {
			c := o[len(o)-1]
			switch c {
			case 'k', 'K', 'm', 'M', 'g', 'G', 't', 'T':
				uri.Unit = strings.ToLower(o[len(o)-1:])
				o = o[:len(o)-1]
			}
		}
		uri.MaxSize, err = strconv.ParseUint(o, 10, 64)
		if err != nil {
			p.xerrorf("parsing max size for uri: %s", err)
		}
	}

	return uri
}

func (p *parser) xnumber() int {
	digits := p.xdigits()
	v, err := strconv.Atoi(digits)
	if err != nil {
		p.xerrorf("parsing %q: %s", digits, err)
	}
	return v
}

// xkeyword parses an SMTP-style keyword.
func (p *parser) xkeyword() string {
	n := len(p.s) - p.o
	return p.xtakefn1case(func(b byte, i int) bool {
		return isalphadigit(b) || (b == '-' && i < n-1 && isalphadigit(p.s[p.o+i+1]))
	})
}

func isdigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func isalpha(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func isalphadigit(b byte) bool {
	return isdigit(b) || isalpha(b)
}
