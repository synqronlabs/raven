package mail

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// errInvalidDate is returned by ParseDate for values that are not valid
// RFC 5322 date-time strings.
var errInvalidDate = errors.New("invalid date-time")

// ParseDate parses an RFC 5322 date-time value (the body of a Date or the
// timestamp in a Received header) into a time.Time.
//
// Both the modern form ("Mon, 02 Jan 2006 15:04:05 -0700") and the obsolete
// forms permitted by RFC 5322 section 4.3 are accepted: an optional day-of-week,
// a two- or four-digit year, one- or two-digit time components, and the obsolete
// zone names (UT, GMT, and the US and military zones). Comments and folding
// white space may appear between tokens.
func ParseDate(value string) (time.Time, error) {
	t, ok := new(dateParser).parse(value)
	if !ok {
		return time.Time{}, errInvalidDate
	}
	return t, nil
}

// dateParser holds the state of an in-progress date-time parse.
type dateParser struct {
	s   string
	pos int
}

func (p *dateParser) peek() byte {
	if p.pos < len(p.s) {
		return p.s[p.pos]
	}
	return 0
}

func (p *dateParser) skip() bool {
	next, err := skipCFWS(p.s, p.pos)
	if err != nil {
		return false
	}
	p.pos = next
	return true
}

func (p *dateParser) parse(value string) (time.Time, bool) {
	p.s = value
	p.pos = 0

	if !p.skip() {
		return time.Time{}, false
	}

	// Optional day-of-week, with or without the separating comma (obs).
	if p.matchWeekday() {
		if !p.skip() {
			return time.Time{}, false
		}
		if p.peek() == ',' {
			p.pos++
			if !p.skip() {
				return time.Time{}, false
			}
		}
	}

	day, ok := p.number(1, 2)
	if !ok || !p.skip() {
		return time.Time{}, false
	}

	month, ok := p.matchMonth()
	if !ok || !p.skip() {
		return time.Time{}, false
	}

	year, ok := p.number(2, 4)
	if !ok || !p.skip() {
		return time.Time{}, false
	}

	hour, ok := p.number(1, 2)
	if !ok || !p.skip() || p.peek() != ':' {
		return time.Time{}, false
	}
	p.pos++
	if !p.skip() {
		return time.Time{}, false
	}

	minute, ok := p.number(1, 2)
	if !ok {
		return time.Time{}, false
	}
	if !p.skip() {
		return time.Time{}, false
	}

	second := 0
	if p.peek() == ':' {
		p.pos++
		if !p.skip() {
			return time.Time{}, false
		}
		second, ok = p.number(1, 2)
		if !ok {
			return time.Time{}, false
		}
	}

	if !p.skip() {
		return time.Time{}, false
	}

	offset, ok := p.zone()
	if !ok || !p.skip() || p.pos != len(p.s) {
		return time.Time{}, false
	}

	if day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60 {
		return time.Time{}, false
	}

	// Two-digit years: 00-49 => 2000-2049, 50-99 => 1950-1999 (RFC 5322 4.3).
	yearNum := year
	if year < 100 {
		if year < 50 {
			yearNum += 2000
		} else {
			yearNum += 1900
		}
	}

	return time.Date(yearNum, month, day, hour, minute, second, 0, time.FixedZone("", offset)), true
}

// number reads between min and max decimal digits.
func (p *dateParser) number(min, max int) (int, bool) {
	start := p.pos
	for p.pos < len(p.s) && p.pos-start < max && isDateDigit(p.s[p.pos]) {
		p.pos++
	}
	if p.pos-start < min {
		return 0, false
	}
	value, err := strconv.Atoi(p.s[start:p.pos])
	if err != nil {
		return 0, false
	}
	return value, true
}

// matchWeekday consumes a day name and reports whether one was present.
func (p *dateParser) matchWeekday() bool {
	word, ok := p.letterWord(3)
	if !ok {
		return false
	}
	switch strings.ToLower(word) {
	case "mon", "tue", "wed", "thu", "fri", "sat", "sun":
		return true
	default:
		p.pos -= len(word)
		return false
	}
}

// matchMonth consumes a month name and returns its time.Month.
func (p *dateParser) matchMonth() (time.Month, bool) {
	word, ok := p.letterWord(3)
	if !ok {
		return 0, false
	}
	for month := time.January; month <= time.December; month++ {
		if strings.EqualFold(month.String()[:3], word) {
			return month, true
		}
	}
	p.pos -= len(word)
	return 0, false
}

// letterWord reads up to n ASCII letters, requiring exactly n.
func (p *dateParser) letterWord(n int) (string, bool) {
	if p.pos+n > len(p.s) {
		return "", false
	}
	for i := 0; i < n; i++ {
		if !isDateAlpha(p.s[p.pos+i]) {
			return "", false
		}
	}
	word := p.s[p.pos : p.pos+n]
	p.pos += n
	return word, true
}

// zone parses the numeric or obsolete zone and returns its offset in seconds.
func (p *dateParser) zone() (int, bool) {
	sign := p.peek()
	if sign == '+' || sign == '-' {
		p.pos++
		digits := p.fixedDigits(4)
		if digits == "" {
			return 0, false
		}
		hh, _ := strconv.Atoi(digits[:2])
		mm, _ := strconv.Atoi(digits[2:])
		if hh > 23 || mm > 59 {
			return 0, false
		}
		offset := hh*3600 + mm*60
		if sign == '-' {
			offset = -offset
		}
		return offset, true
	}

	if !isDateAlpha(sign) {
		return 0, false
	}
	start := p.pos
	for p.pos < len(p.s) && isDateAlpha(p.s[p.pos]) {
		p.pos++
	}
	name := strings.ToUpper(p.s[start:p.pos])

	if offset, ok := obsZones[name]; ok {
		return offset, true
	}
	if len(name) == 1 {
		return militaryZone(name[0])
	}
	return 0, false
}

// fixedDigits reads exactly n decimal digits.
func (p *dateParser) fixedDigits(n int) string {
	if p.pos+n > len(p.s) {
		return ""
	}
	for i := 0; i < n; i++ {
		if !isDateDigit(p.s[p.pos+i]) {
			return ""
		}
	}
	digits := p.s[p.pos : p.pos+n]
	p.pos += n
	return digits
}

// obsZones maps the obsolete RFC 5322 zone names to offsets in seconds.
var obsZones = map[string]int{
	"UT":  0,
	"GMT": 0,
	"EST": -5 * 3600,
	"EDT": -4 * 3600,
	"CST": -6 * 3600,
	"CDT": -5 * 3600,
	"MST": -7 * 3600,
	"MDT": -6 * 3600,
	"PST": -8 * 3600,
	"PDT": -7 * 3600,
}

// militaryZone maps a single-letter military zone to its offset in seconds.
func militaryZone(letter byte) (int, bool) {
	switch {
	case letter >= 'A' && letter <= 'I':
		return int(letter-'A'+1) * 3600, true
	case letter >= 'K' && letter <= 'M':
		return int(letter-'K'+10) * 3600, true
	case letter >= 'N' && letter <= 'Y':
		return -int(letter-'N'+1) * 3600, true
	case letter == 'Z':
		return 0, true
	default:
		return 0, false
	}
}

func isDateDigit(c byte) bool { return c >= '0' && c <= '9' }

func isDateAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
