// Package smtppath splits the outer framing of an SMTP path from its
// parameters. It deliberately does not validate the addr-spec; callers that
// need full validation use mail.ParseAddrSpec or mail.ParsePath.
package smtppath

import (
	"errors"
	"strings"
)

var (
	// ErrEmpty is returned when the input contains no path.
	ErrEmpty = errors.New("empty path")
	// ErrMissingBrackets is returned when a path is not enclosed in angle
	// brackets or the closing bracket cannot be found.
	ErrMissingBrackets = errors.New("path must be enclosed in angle brackets")
)

// Split extracts the content between the outermost angle brackets and the
// trailing ESMTP parameters. A quoted local-part or a domain literal may
// contain a '>', so the closing bracket is found with those constructs in
// mind rather than with a plain string search.
//
// Split does not remove an obsolete source route. Use SplitSourceRoute after
// Split when the caller needs the final addr-spec.
func Split(s string) (path, params string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", ErrEmpty
	}
	if s[0] != '<' {
		return "", "", ErrMissingBrackets
	}

	end := findClosingAngle(s)
	if end < 0 {
		return "", "", ErrMissingBrackets
	}

	return s[1:end], strings.TrimSpace(s[end+1:]), nil
}

// SplitSourceRoute removes an obsolete A-d-l source route from path. It
// returns the route (including its leading '@'), the remaining addr-spec, and
// whether a route terminator was found. A malformed route without a
// top-level colon is left in path so the addr-spec parser can reject it.
func SplitSourceRoute(path string) (route, rest string, ok bool) {
	if path == "" || path[0] != '@' {
		return "", path, false
	}

	depth := 0
	for i := 0; i < len(path); i++ {
		switch path[i] {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case ':':
			// Colons inside address literals (notably [IPv6:...]) are
			// part of the literal, not route separators.
			if depth == 0 {
				return path[:i], path[i+1:], true
			}
		}
	}
	return "", path, false
}

// findClosingAngle returns the index of the '>' that closes the path, ignoring
// brackets and quoted strings embedded in the path. s must start with '<'.
func findClosingAngle(s string) int {
	inQuote := false
	inLiteral := false
	escaped := false

	for i := 1; i < len(s); i++ {
		c := s[i]

		if inQuote {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inQuote = false
			}
			continue
		}

		if inLiteral {
			// Address literals cannot nest brackets or contain quoted
			// strings; the first unescaped ']' ends the literal.
			if c == ']' {
				inLiteral = false
			}
			continue
		}

		switch c {
		case '"':
			inQuote = true
		case '[':
			inLiteral = true
		case '>':
			return i
		}
	}

	return -1
}
