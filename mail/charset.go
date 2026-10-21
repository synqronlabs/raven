package mail

import (
	"fmt"
	"io"
	"mime"
	"strings"

	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/encoding/ianaindex"
)

// decodeHeaderValue decodes RFC 2047 encoded-words. Character sets are resolved
// using the WHATWG encoding labels first (so iso-8859-1 behaves as the
// windows-1252 superset used by real-world mail), with the broader IANA MIME
// registry as a fallback.
func decodeHeaderValue(value string) (string, error) {
	decoder := &mime.WordDecoder{CharsetReader: charsetReader}
	return decoder.DecodeHeader(rewriteISO88591EncodedWords(value))
}

func charsetReader(charset string, input io.Reader) (io.Reader, error) {
	name := strings.ToLower(strings.TrimSpace(charset))

	enc, err := htmlindex.Get(name)
	if err != nil || enc == nil {
		enc, err = ianaindex.MIME.Encoding(name)
		if err != nil || enc == nil {
			return nil, fmt.Errorf("mime: unhandled charset %q", charset)
		}
	}
	return enc.NewDecoder().Reader(input), nil
}

// rewriteISO88591EncodedWords relabels ISO-8859-1 encoded-words as
// windows-1252. The standard library's WordDecoder handles iso-8859-1
// internally, before consulting CharsetReader, so the label must be changed
// before decoding to get the WHATWG interpretation.
func rewriteISO88591EncodedWords(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for {
		start := strings.Index(value, "=?")
		if start < 0 {
			b.WriteString(value)
			return b.String()
		}
		b.WriteString(value[:start])

		charsetStart := start + 2
		relEnd := strings.IndexByte(value[charsetStart:], '?')
		if relEnd < 0 {
			b.WriteString(value[start:])
			return b.String()
		}
		charsetEnd := charsetStart + relEnd
		charset := value[charsetStart:charsetEnd]
		if strings.EqualFold(charset, "iso-8859-1") {
			charset = "windows-1252"
		}

		b.WriteString("=?")
		b.WriteString(charset)
		value = value[charsetEnd:]
	}
}
