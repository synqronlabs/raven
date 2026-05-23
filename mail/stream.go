package mail

import (
	"io"
	"strings"
)

// NewHeaderPrependedReader returns a reader that streams headers followed by
// message. The headers string is used as-is, so callers should include the
// trailing CRLF for each generated header.
func NewHeaderPrependedReader(headers string, message io.Reader) io.Reader {
	return io.MultiReader(strings.NewReader(headers), message)
}

// PrependedSize returns the total byte size of headers prepended to a message.
func PrependedSize(headers string, messageSize int64) int64 {
	return int64(len(headers)) + messageSize
}
