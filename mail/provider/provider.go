// Package provider models how popular mail providers treat email addresses.
//
// The package is additive: it builds on the RFC 5321/5322 parser in the mail
// package and never changes its behavior. It answers two questions that the RFCs
// do not:
//
//   - Are two addresses the same mailbox to a given provider? Providers differ
//     in whether they treat dots as significant (Gmail ignores them), whether
//     they support "+tag" or "-tag" subaddressing, and whether different domains
//     (gmail.com vs googlemail.com) are aliases of the same mailbox.
//   - Does a provider accept syntax that is otherwise RFC-valid, such as an IP
//     address literal domain or a quoted local-part?
//
// Built-in profiles cover common consumer providers; define a custom Profile
// when you need different rules. Provider rules reflect commonly-observed
// behavior and are intentionally conservative.
package provider

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/synqronlabs/raven/mail"
)

// Validation errors returned by Profile.Validate. Use errors.Is to test them.
var (
	ErrIPLiteralDomain  = errors.New("provider does not accept IP address literals as the domain")
	ErrQuotedLocalPart  = errors.New("provider does not accept quoted local-parts")
	ErrSMTPUTF8         = errors.New("provider does not accept internationalized (SMTPUTF8) addresses")
	ErrLocalPartTooLong = errors.New("local-part exceeds the provider's maximum length")
	ErrAddressTooLong   = errors.New("address exceeds the provider's maximum length")
)

// Profile describes how a provider treats email addresses.
//
// The zero value is a valid generic profile: the local-part and domain are both
// compared case-insensitively and no provider-specific normalization or
// restrictions are applied. Fields are intentionally coarse so that a profile
// stays easy to reason about and override.
type Profile struct {
	// Name is a human-readable provider name (for example "Gmail").
	Name string

	// Domains lists the domains served by the profile.
	Domains []string

	// DomainAliases maps an alternate domain to the canonical domain it is an
	// alias for (for example "googlemail.com" -> "gmail.com"). Aliased domains
	// are treated as the same mailbox when comparing addresses.
	DomainAliases map[string]string

	// IgnoreDotsInLocalPart reports whether dots in the local-part are
	// insignificant when comparing addresses (Gmail).
	IgnoreDotsInLocalPart bool

	// SubaddressSeparator, when non-zero, introduces a subaddress tag. The tag
	// and everything after the first separator are ignored when comparing
	// addresses (for example '+' for Gmail and '-' for Yahoo).
	SubaddressSeparator byte

	// CaseSensitiveLocalPart reports whether the local-part is case-sensitive.
	// Most consumer providers are effectively case-insensitive.
	CaseSensitiveLocalPart bool

	// AllowIPLiteralDomain reports whether the provider accepts an address
	// literal such as user@[192.0.2.1] as the domain.
	AllowIPLiteralDomain bool

	// AllowQuotedLocalPart reports whether the provider accepts a quoted-string
	// local-part such as "user name"@example.com.
	AllowQuotedLocalPart bool

	// AllowSMTPUTF8 reports whether the provider accepts non-ASCII
	// (internationalized) addresses.
	AllowSMTPUTF8 bool

	// MaxLocalPart is the maximum accepted local-part length in octets. Zero
	// means only the RFC 5321 limit applies.
	MaxLocalPart int

	// MaxAddressLength is the maximum accepted total address length in octets.
	// Zero means only the RFC 5321 limit applies.
	MaxAddressLength int
}

// Clone returns a deep copy of the profile, or nil for a nil receiver.
func (p *Profile) Clone() *Profile {
	if p == nil {
		return nil
	}
	c := *p
	c.Domains = append([]string(nil), p.Domains...)
	if p.DomainAliases != nil {
		c.DomainAliases = make(map[string]string, len(p.DomainAliases))
		for k, v := range p.DomainAliases {
			c.DomainAliases[k] = v
		}
	}
	return &c
}

// Serves reports whether domain is one of the profile's domains or aliases.
func (p *Profile) Serves(domain string) bool {
	if p == nil {
		return false
	}
	domain = normalizeDomain(domain)
	if _, ok := p.DomainAliases[domain]; ok {
		return true
	}
	for _, d := range p.Domains {
		if normalizeDomain(d) == domain {
			return true
		}
	}
	return false
}

// Canonical returns the form of m used for equality comparison under the
// profile: the domain is lowercased and alias-resolved, the local-part is
// lowercased (unless case-sensitive), any subaddress tag is removed, and dots
// are removed when they are insignificant. The display name is dropped. A nil
// profile behaves like the zero value.
func (p *Profile) Canonical(m mail.MailboxAddress) mail.MailboxAddress {
	local := m.LocalPart
	domain := normalizeDomain(m.Domain)

	if p == nil {
		p = &Profile{}
	}
	if alias, ok := p.DomainAliases[domain]; ok {
		domain = alias
	}
	if !p.CaseSensitiveLocalPart {
		local = strings.ToLower(local)
	}
	if p.SubaddressSeparator != 0 {
		if i := strings.IndexByte(local, p.SubaddressSeparator); i > 0 {
			local = local[:i]
		}
	}
	if p.IgnoreDotsInLocalPart {
		local = strings.ReplaceAll(local, ".", "")
	}

	return mail.MailboxAddress{LocalPart: local, Domain: domain}
}

// CanonicalString parses addr and returns its canonical form under the profile.
func (p *Profile) CanonicalString(addr string) (string, error) {
	m, err := mail.ParseAddress(addr)
	if err != nil {
		return "", err
	}
	c := p.Canonical(m)
	return c.String(), nil
}

// EquivalentMailbox reports whether a and b refer to the same mailbox under the
// profile. Display names are ignored.
func (p *Profile) EquivalentMailbox(a, b mail.MailboxAddress) bool {
	ca := p.Canonical(a)
	cb := p.Canonical(b)
	return ca.LocalPart == cb.LocalPart && ca.Domain == cb.Domain
}

// Equivalent parses and compares two addresses under the profile.
func (p *Profile) Equivalent(a, b string) (bool, error) {
	ma, err := mail.ParseAddress(a)
	if err != nil {
		return false, err
	}
	mb, err := mail.ParseAddress(b)
	if err != nil {
		return false, err
	}
	return p.EquivalentMailbox(ma, mb), nil
}

// SplitSubaddress splits the local-part of m into its base and subaddress tag
// at the profile's separator. The tag is empty when the profile has no separator
// or the address carries no tag.
func (p *Profile) SplitSubaddress(m mail.MailboxAddress) (base, tag string) {
	if p == nil || p.SubaddressSeparator == 0 {
		return m.LocalPart, ""
	}
	if i := strings.IndexByte(m.LocalPart, p.SubaddressSeparator); i >= 0 {
		return m.LocalPart[:i], m.LocalPart[i+1:]
	}
	return m.LocalPart, ""
}

// Validate reports whether the provider accepts the syntax of addr. The address
// must be RFC-valid; Validate then applies the provider's restrictions and
// returns the first one that is violated, wrapped so errors.Is works.
func (p *Profile) Validate(addr string) error {
	m, err := mail.ParseAddress(addr)
	if err != nil {
		return err
	}
	if p == nil {
		return nil
	}

	addrSpec := addrSpecOf(addr)

	if !p.AllowIPLiteralDomain && strings.HasPrefix(m.Domain, "[") {
		return fmt.Errorf("%w: %s", ErrIPLiteralDomain, m.Domain)
	}
	if !p.AllowQuotedLocalPart && strings.HasPrefix(m.LocalPart, `"`) {
		return fmt.Errorf("%w: %s", ErrQuotedLocalPart, m.LocalPart)
	}
	if !p.AllowSMTPUTF8 && containsNonASCII(addrSpec) {
		return fmt.Errorf("%w: %s", ErrSMTPUTF8, addrSpec)
	}
	if p.MaxLocalPart > 0 && len(m.LocalPart) > p.MaxLocalPart {
		return fmt.Errorf("%w: %d > %d", ErrLocalPartTooLong, len(m.LocalPart), p.MaxLocalPart)
	}
	if p.MaxAddressLength > 0 {
		c := p.Canonical(m)
		if n := len(c.String()); n > p.MaxAddressLength {
			return fmt.Errorf("%w: %d > %d", ErrAddressTooLong, n, p.MaxAddressLength)
		}
	}
	return nil
}

// Accepts reports whether the provider accepts the syntax of addr.
func (p *Profile) Accepts(addr string) bool {
	return p.Validate(addr) == nil
}

// addrSpecOf returns the addr-spec portion of a mailbox string, dropping a
// display name if one is present.
func addrSpecOf(addr string) string {
	if i := strings.LastIndexByte(addr, '<'); i >= 0 {
		if j := strings.IndexByte(addr[i:], '>'); j >= 0 {
			return addr[i+1 : i+j]
		}
	}
	return addr
}

func containsNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return true
		}
	}
	return false
}

func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	return strings.TrimSuffix(domain, ".")
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

var (
	registryMu    sync.RWMutex
	registry      = map[string]*Profile{}
	registryOrder []*Profile
)

// Register makes p discoverable by ByDomain for every domain and alias it
// declares. It returns an error if a domain is already registered.
func Register(p *Profile) error {
	if p == nil {
		return errors.New("provider: nil profile")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	domains := p.allDomains()
	for _, d := range domains {
		if existing, ok := registry[d]; ok && existing != p {
			return fmt.Errorf("provider: domain %q already registered to %q", d, existing.Name)
		}
	}

	needsAppend := false
	for _, d := range domains {
		if _, ok := registry[d]; !ok {
			needsAppend = true
		}
		registry[d] = p
	}
	if needsAppend {
		registryOrder = append(registryOrder, p)
	}
	return nil
}

func (p *Profile) allDomains() []string {
	seen := make(map[string]struct{}, len(p.Domains)+len(p.DomainAliases))
	out := make([]string, 0, len(p.Domains)+len(p.DomainAliases))
	for _, d := range p.Domains {
		d = normalizeDomain(d)
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	for d := range p.DomainAliases {
		d = normalizeDomain(d)
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func lookup(domain string) (*Profile, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	p, ok := registry[normalizeDomain(domain)]
	return p, ok
}

// ByDomain returns the built-in or registered profile serving domain, or false
// if none is known. The returned profile is a copy and may be modified freely.
func ByDomain(domain string) (*Profile, bool) {
	p, ok := lookup(domain)
	if !ok {
		return nil, false
	}
	return p.Clone(), true
}

// Profiles returns a copy of every registered profile, in registration order.
func Profiles() []*Profile {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]*Profile, 0, len(registryOrder))
	for _, p := range registryOrder {
		out = append(out, p.Clone())
	}
	return out
}

// Default returns a generic profile for providers that are not otherwise known:
// the local-part is compared case-insensitively, the domain case-insensitively,
// and no provider-specific normalization or restrictions are applied.
func Default() *Profile {
	return genericProfile.Clone()
}

// profileFor returns the registered profile for domain, or the generic profile.
func profileFor(domain string) *Profile {
	if p, ok := lookup(domain); ok {
		return p
	}
	return genericProfile
}

// Canonical parses addr and returns its canonical form, using the profile
// registered for the address's domain (or the generic profile if unknown).
func Canonical(addr string) (string, error) {
	m, err := mail.ParseAddress(addr)
	if err != nil {
		return "", err
	}
	c := profileFor(m.Domain).Canonical(m)
	return c.String(), nil
}

// Equivalent reports whether two addresses refer to the same mailbox. When both
// domains map to the same registered profile that profile's rules are used;
// otherwise the generic profile is applied.
func Equivalent(a, b string) (bool, error) {
	ma, err := mail.ParseAddress(a)
	if err != nil {
		return false, err
	}
	mb, err := mail.ParseAddress(b)
	if err != nil {
		return false, err
	}

	profile := genericProfile
	if pa, ok := lookup(ma.Domain); ok {
		if pb, ok := lookup(mb.Domain); ok && pa == pb {
			profile = pa
		}
	}
	return profile.EquivalentMailbox(ma, mb), nil
}

// ---------------------------------------------------------------------------
// Built-in profiles
// ---------------------------------------------------------------------------

var genericProfile = &Profile{Name: "Generic"}

var (
	gmailProfile = &Profile{
		Name:                   "Gmail",
		Domains:                []string{"gmail.com"},
		DomainAliases:          map[string]string{"googlemail.com": "gmail.com"},
		IgnoreDotsInLocalPart:  true,
		SubaddressSeparator:    '+',
		CaseSensitiveLocalPart: false,
	}
	outlookProfile = &Profile{
		Name:                   "Outlook",
		Domains:                []string{"outlook.com", "hotmail.com", "live.com", "msn.com"},
		SubaddressSeparator:    '+',
		CaseSensitiveLocalPart: false,
	}
	yahooProfile = &Profile{
		Name:                   "Yahoo",
		Domains:                []string{"yahoo.com", "ymail.com", "rocketmail.com"},
		SubaddressSeparator:    '-',
		CaseSensitiveLocalPart: false,
	}
	icloudProfile = &Profile{
		Name:                   "iCloud",
		Domains:                []string{"icloud.com"},
		DomainAliases:          map[string]string{"me.com": "icloud.com", "mac.com": "icloud.com"},
		SubaddressSeparator:    '+',
		CaseSensitiveLocalPart: false,
	}
	protonProfile = &Profile{
		Name:                   "Proton Mail",
		Domains:                []string{"protonmail.com"},
		DomainAliases:          map[string]string{"proton.me": "protonmail.com"},
		SubaddressSeparator:    '+',
		CaseSensitiveLocalPart: false,
	}
	fastmailProfile = &Profile{
		Name:                   "Fastmail",
		Domains:                []string{"fastmail.com"},
		DomainAliases:          map[string]string{"fastmail.fm": "fastmail.com"},
		SubaddressSeparator:    '+',
		CaseSensitiveLocalPart: false,
	}
	gmxProfile = &Profile{
		Name:                   "GMX",
		Domains:                []string{"gmx.com", "gmx.net", "gmx.de"},
		SubaddressSeparator:    '+',
		CaseSensitiveLocalPart: false,
	}
	zohoProfile = &Profile{
		Name:                   "Zoho Mail",
		Domains:                []string{"zoho.com"},
		SubaddressSeparator:    '+',
		CaseSensitiveLocalPart: false,
	}
	aolProfile = &Profile{
		Name:                   "AOL",
		Domains:                []string{"aol.com"},
		SubaddressSeparator:    '+',
		CaseSensitiveLocalPart: false,
	}
)

func init() {
	for _, p := range []*Profile{
		gmailProfile,
		outlookProfile,
		yahooProfile,
		icloudProfile,
		protonProfile,
		fastmailProfile,
		gmxProfile,
		zohoProfile,
		aolProfile,
	} {
		if err := Register(p); err != nil {
			panic(err)
		}
	}
}

// Gmail returns the Gmail profile.
func Gmail() *Profile { return gmailProfile.Clone() }

// Outlook returns the Outlook/Hotmail/Live profile.
func Outlook() *Profile { return outlookProfile.Clone() }

// Yahoo returns the Yahoo profile.
func Yahoo() *Profile { return yahooProfile.Clone() }

// ICloud returns the iCloud profile.
func ICloud() *Profile { return icloudProfile.Clone() }

// Proton returns the Proton Mail profile.
func Proton() *Profile { return protonProfile.Clone() }

// Fastmail returns the Fastmail profile.
func Fastmail() *Profile { return fastmailProfile.Clone() }

// GMX returns the GMX profile.
func GMX() *Profile { return gmxProfile.Clone() }

// Zoho returns the Zoho Mail profile.
func Zoho() *Profile { return zohoProfile.Clone() }

// AOL returns the AOL profile.
func AOL() *Profile { return aolProfile.Clone() }
