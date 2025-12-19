package spf

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// SPF record parsing errors.
var (
	ErrRecordSyntax     = errors.New("spf: malformed SPF record")
	ErrInvalidMechanism = errors.New("spf: invalid mechanism")
	ErrInvalidQualifier = errors.New("spf: invalid qualifier")
	ErrInvalidCIDR      = errors.New("spf: invalid CIDR length")
	ErrInvalidIP        = errors.New("spf: invalid IP address")
)

// Record is a parsed SPF DNS record.
//
// An example record for example.com:
//
//	v=spf1 +mx a:colo.example.com/28 -all
type Record struct {
	// Version must be "spf1".
	Version string

	// Directives are evaluated in order until a match is found.
	Directives []Directive

	// Redirect specifies another domain to check if no directives match.
	// This is the "redirect=" modifier.
	Redirect string

	// Explanation specifies a domain to query for an explanation string
	// when the result is "fail". This is the "exp=" modifier.
	Explanation string

	// Other contains other modifiers that are not redirect or exp.
	Other []Modifier
}

// String returns the SPF record as a DNS TXT record string.
func (r Record) String() string {
	var b strings.Builder
	b.WriteString("v=")
	b.WriteString(r.Version)

	for _, d := range r.Directives {
		b.WriteByte(' ')
		b.WriteString(d.String())
	}

	if r.Redirect != "" {
		b.WriteString(" redirect=")
		b.WriteString(r.Redirect)
	}

	if r.Explanation != "" {
		b.WriteString(" exp=")
		b.WriteString(r.Explanation)
	}

	for _, m := range r.Other {
		b.WriteByte(' ')
		b.WriteString(m.Key)
		b.WriteByte('=')
		b.WriteString(m.Value)
	}

	return b.String()
}

// Directive consists of a mechanism that describes how to check if an IP matches,
// an optional qualifier indicating the policy for a match, and optional
// parameters specific to the mechanism.
type Directive struct {
	// Qualifier sets the result if this directive matches.
	// "" and "+" mean "pass", "-" means "fail", "?" means "neutral", "~" means "softfail".
	Qualifier string

	// Mechanism is one of: "all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists".
	Mechanism string

	// DomainSpec is used for include, a, mx, ptr, exists mechanisms.
	// Always in lower-case when parsed using ParseRecord.
	DomainSpec string

	// IP is the parsed IP address for ip4 and ip6 mechanisms.
	IP net.IP

	// IPStr is the original string representation of the IP with CIDR.
	IPStr string

	// IP4CIDRLen is the CIDR prefix length for IPv4 (0-32).
	// nil means the default (32 for ip4, or depends on mechanism).
	IP4CIDRLen *int

	// IP6CIDRLen is the CIDR prefix length for IPv6 (0-128).
	// nil means the default (128 for ip6, or depends on mechanism).
	IP6CIDRLen *int
}

// String returns the directive in string form.
func (d Directive) String() string {
	var b strings.Builder
	b.WriteString(d.Qualifier)
	b.WriteString(d.Mechanism)

	if d.DomainSpec != "" {
		b.WriteByte(':')
		b.WriteString(d.DomainSpec)
	} else if d.IP != nil {
		b.WriteByte(':')
		b.WriteString(d.IP.String())
	}

	if d.IP4CIDRLen != nil {
		fmt.Fprintf(&b, "/%d", *d.IP4CIDRLen)
	}

	if d.IP6CIDRLen != nil {
		if d.Mechanism != "ip6" {
			b.WriteByte('/')
		}
		fmt.Fprintf(&b, "/%d", *d.IP6CIDRLen)
	}

	return b.String()
}

// MechanismString returns just the mechanism part for use in headers.
func (d Directive) MechanismString() string {
	return d.String()
}

// Modifier provides additional information for a policy.
// "redirect" and "exp" are not represented as Modifier but explicitly in Record.
type Modifier struct {
	Key   string // Key is case-insensitive.
	Value string
}

// parser is the internal state for parsing SPF records.
type parser struct {
	s     string // Original string
	lower string // Lower-cased string for case-insensitive matching
	o     int    // Current offset
}

// parseError is a recoverable parsing error.
type parseError string

func (e parseError) Error() string {
	return string(e)
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

// ParseRecord parses an SPF DNS TXT record.
// Returns the parsed record, whether it looks like an SPF record (starts with v=spf1),
// and any parsing error.
func ParseRecord(s string) (r *Record, isSPF bool, err error) {
	p := parser{s: s, lower: toLower(s)}

	r = &Record{
		Version: "spf1",
	}

	defer func() {
		x := recover()
		if x == nil {
			return
		}
		if perr, ok := x.(parseError); ok {
			err = fmt.Errorf("%w: %s", ErrRecordSyntax, perr)
			return
		}
		panic(x)
	}()

	// Must start with "v=spf1"
	if !p.take("v=spf1") {
		return nil, false, nil
	}

	for !p.empty() {
		// Require space between terms
		if !p.take(" ") {
			p.xerrorf("expected space")
		}
		isSPF = true // Has at least v=spf1 and a space

		// Skip multiple spaces
		for p.take(" ") {
		}

		if p.empty() {
			break
		}

		// Try to parse qualifier
		qualifier := p.takelist("+", "-", "?", "~")

		// Try to parse mechanism
		mechanism := p.takelist("all", "include:", "a", "mx", "ptr", "ip4:", "ip6:", "exists:")

		if qualifier != "" && mechanism == "" {
			p.xerrorf("expected mechanism after qualifier")
		}

		if mechanism == "" {
			// Try to parse modifier
			modifier := p.takelist("redirect=", "exp=")
			if modifier == "" {
				// Unknown modifier: name=value
				name := p.xtakefn1(func(c rune, i int) bool {
					alpha := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
					return alpha || i > 0 && (c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.')
				})
				if !p.take("=") {
					p.xerrorf("expected '=' after modifier name")
				}
				v := p.xmacroString(true)
				r.Other = append(r.Other, Modifier{name, v})
				continue
			}

			v := p.xdomainSpec(true)
			modifier = strings.TrimSuffix(modifier, "=")

			if modifier == "redirect" {
				if r.Redirect != "" {
					p.xerrorf("duplicate redirect modifier")
				}
				r.Redirect = v
			}
			if modifier == "exp" {
				if r.Explanation != "" {
					p.xerrorf("duplicate exp modifier")
				}
				r.Explanation = v
			}
			continue
		}

		// Parse directive
		d := Directive{
			Qualifier: qualifier,
			Mechanism: strings.TrimSuffix(mechanism, ":"),
		}

		switch d.Mechanism {
		case "all":
			// No additional parameters

		case "include":
			d.DomainSpec = p.xdomainSpec(false)

		case "a", "mx":
			if p.take(":") {
				d.DomainSpec = p.xdomainSpec(false)
			}
			if p.take("/") {
				if !p.take("/") {
					// IPv4 CIDR length
					num, _ := p.xnumber()
					if num > 32 {
						p.xerrorf("invalid IPv4 CIDR length %d", num)
					}
					d.IP4CIDRLen = &num
					if !p.take("//") {
						break
					}
				}
				// IPv6 CIDR length
				num, _ := p.xnumber()
				if num > 128 {
					p.xerrorf("invalid IPv6 CIDR length %d", num)
				}
				d.IP6CIDRLen = &num
			}

		case "ptr":
			if p.take(":") {
				d.DomainSpec = p.xdomainSpec(false)
			}

		case "ip4":
			d.IP, d.IPStr = p.xip4address()
			if p.take("/") {
				num, _ := p.xnumber()
				if num > 32 {
					p.xerrorf("invalid IPv4 CIDR length %d", num)
				}
				d.IP4CIDRLen = &num
				d.IPStr += fmt.Sprintf("/%d", num)
			} else {
				num := 32
				d.IP4CIDRLen = &num
				d.IPStr += "/32"
			}

		case "ip6":
			d.IP, d.IPStr = p.xip6address()
			if p.take("/") {
				num, _ := p.xnumber()
				if num > 128 {
					p.xerrorf("invalid IPv6 CIDR length %d", num)
				}
				d.IP6CIDRLen = &num
				d.IPStr += fmt.Sprintf("/%d", num)
			} else {
				num := 128
				d.IP6CIDRLen = &num
				d.IPStr += "/128"
			}

		case "exists":
			d.DomainSpec = p.xdomainSpec(false)

		default:
			return nil, true, fmt.Errorf("%w: unknown mechanism %q", ErrInvalidMechanism, d.Mechanism)
		}

		r.Directives = append(r.Directives, d)
	}

	return r, true, nil
}

func (p *parser) xerrorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if !p.empty() {
		msg += fmt.Sprintf(" (remaining: %q)", p.s[p.o:])
	}
	panic(parseError(msg))
}

func (p *parser) empty() bool {
	return p.o >= len(p.s)
}

func (p *parser) peekchar() byte {
	return p.s[p.o]
}

func (p *parser) take(s string) bool {
	if strings.HasPrefix(p.lower[p.o:], s) {
		p.o += len(s)
		return true
	}
	return false
}

func (p *parser) xtake(s string) string {
	if !p.take(s) {
		p.xerrorf("expected %q", s)
	}
	return s
}

func (p *parser) takelist(l ...string) string {
	for _, w := range l {
		if strings.HasPrefix(p.lower[p.o:], w) {
			p.o += len(w)
			return w
		}
	}
	return ""
}

func (p *parser) xtakelist(l ...string) string {
	w := p.takelist(l...)
	if w == "" {
		p.xerrorf("no match for %v", l)
	}
	return w
}

// xtakefn1 takes one or more characters matching fn.
func (p *parser) xtakefn1(fn func(rune, int) bool) string {
	r := ""
	for i, c := range p.s[p.o:] {
		if !fn(c, i) {
			break
		}
		r += string(c)
	}
	if r == "" {
		p.xerrorf("need at least 1 character")
	}
	p.o += len(r)
	return r
}

// digits parses zero or more digits.
func (p *parser) digits() string {
	r := ""
	for !p.empty() {
		b := p.peekchar()
		if b >= '0' && b <= '9' {
			r += string(b)
			p.o++
		} else {
			break
		}
	}
	return r
}

func (p *parser) xnumber() (int, string) {
	s := p.digits()
	if s == "" {
		p.xerrorf("expected number")
	}
	if s == "0" {
		return 0, s
	}
	if strings.HasPrefix(s, "0") {
		p.xerrorf("invalid leading zero in number")
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		p.xerrorf("parsing number %q: %s", s, err)
	}
	return v, s
}

// xdomainSpec parses a domain-spec.
// includingSlash should be false when parsing "a" or "mx" to avoid consuming the /.
func (p *parser) xdomainSpec(includingSlash bool) string {
	s := p.xmacroString(includingSlash)

	// Validate domain-end: must end with macro-expand or valid toplabel
	for _, suf := range []string{"%%", "%_", "%-", "}"} {
		if strings.HasSuffix(s, suf) {
			return s
		}
	}

	// Check toplabel validity
	tl := strings.Split(strings.TrimSuffix(s, "."), ".")
	if len(tl) == 0 {
		return s
	}
	t := tl[len(tl)-1]
	if t == "" {
		p.xerrorf("invalid empty toplabel")
	}

	nums := 0
	for i, c := range t {
		switch {
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			// OK
		case c >= '0' && c <= '9':
			nums++
		case c == '-':
			if i == 0 {
				p.xerrorf("toplabel cannot start with dash")
			}
			if i == len(t)-1 {
				p.xerrorf("toplabel cannot end with dash")
			}
		default:
			p.xerrorf("invalid character in toplabel")
		}
	}
	if nums == len(t) {
		p.xerrorf("toplabel cannot be all digits")
	}

	return s
}

// xmacroString parses a macro-string.
func (p *parser) xmacroString(includingSlash bool) string {
	r := ""
	for !p.empty() {
		w := p.takelist("%{", "%%", "%_", "%-")
		if w == "" {
			// macro-literal
			if !p.empty() {
				b := p.peekchar()
				if b > ' ' && b < 0x7f && b != '%' && (includingSlash || b != '/') {
					r += string(b)
					p.o++
					continue
				}
			}
			break
		}
		r += w
		if w != "%{" {
			continue
		}

		// Parse macro letter
		r += p.xtakelist("s", "l", "o", "d", "i", "p", "h", "c", "r", "t", "v")

		// Optional digits (transformer)
		digits := p.digits()
		if digits != "" {
			v, err := strconv.Atoi(digits)
			if err != nil {
				p.xerrorf("invalid digits: %v", err)
			}
			if v == 0 {
				p.xerrorf("zero labels not allowed")
			}
		}
		r += digits

		// Optional reverse
		if p.take("r") {
			r += "r"
		}

		// Optional delimiters
		for {
			delimiter := p.takelist(".", "-", "+", ",", "/", "_", "=")
			if delimiter == "" {
				break
			}
			r += delimiter
		}

		// Closing brace
		r += p.xtake("}")
	}
	return r
}

func (p *parser) xip4address() (net.IP, string) {
	ip4num := func() (byte, string) {
		v, vs := p.xnumber()
		if v > 255 {
			p.xerrorf("invalid IPv4 octet %d", v)
		}
		return byte(v), vs
	}

	a, as := ip4num()
	p.xtake(".")
	b, bs := ip4num()
	p.xtake(".")
	c, cs := ip4num()
	p.xtake(".")
	d, ds := ip4num()

	return net.IPv4(a, b, c, d), as + "." + bs + "." + cs + "." + ds
}

func (p *parser) xip6address() (net.IP, string) {
	// Take all valid IPv6 characters and parse with net.ParseIP
	s := p.xtakefn1(func(c rune, i int) bool {
		return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == ':' || c == '.'
	})
	ip := net.ParseIP(s)
	if ip == nil {
		p.xerrorf("invalid IPv6 address %q", s)
	}
	return ip, s
}
