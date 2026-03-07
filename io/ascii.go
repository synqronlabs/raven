package io

import "unicode/utf8"

// ContainsNonASCII reports whether s contains at least one non-ASCII rune.
func ContainsNonASCII(s string) bool {
	for _, v := range s {
		if v >= utf8.RuneSelf {
			return true
		}
	}
	return false
}
