package dkim

import (
	"bufio"
	"bytes"
	"crypto"
	"hash"
	"io"
	"strings"
)

// canonicalizeHeaderRelaxed returns the header in relaxed canonicalization.
// Relaxed canonicalization:
//   - Convert header name to lowercase
//   - Unfold header lines (remove CRLF before WSP)
//   - Compress WSP to single space
//   - Remove trailing WSP from header value
func canonicalizeHeaderRelaxed(header string) (string, error) {
	// Find header name and value
	idx := strings.Index(header, ":")
	if idx == -1 {
		return "", ErrHeaderMalformed
	}

	name := strings.ToLower(strings.TrimRight(header[:idx], " \t"))
	value := header[idx+1:]

	// Unfold (remove CRLF followed by WSP)
	value = strings.ReplaceAll(value, "\r\n\t", " ")
	value = strings.ReplaceAll(value, "\r\n ", " ")
	value = strings.ReplaceAll(value, "\n\t", " ")
	value = strings.ReplaceAll(value, "\n ", " ")

	// Compress WSP to single space
	var result strings.Builder
	prevWS := false
	for _, c := range value {
		if c == ' ' || c == '\t' {
			if !prevWS {
				result.WriteByte(' ')
				prevWS = true
			}
		} else {
			result.WriteRune(c)
			prevWS = false
		}
	}

	// Trim leading and trailing whitespace from value
	return name + ":" + strings.TrimSpace(result.String()), nil
}

// computeBodyHash calculates the hash of the message body.
func computeBodyHash(h hash.Hash, canonicalization Canonicalization, body []byte) ([]byte, error) {
	if canonicalization == CanonSimple {
		return bodyHashSimple(h, bytes.NewReader(body))
	}
	return bodyHashRelaxed(h, bytes.NewReader(body))
}

// computeBodyHashReader calculates the hash of the message body from a reader.
func computeBodyHashReader(h hash.Hash, canonicalization Canonicalization, body io.Reader) ([]byte, error) {
	br := bufio.NewReader(body)
	if canonicalization == CanonSimple {
		return bodyHashSimple(h, br)
	}
	return bodyHashRelaxed(h, br)
}

// bodyHashSimple computes the body hash using simple canonicalization.
// Simple body canonicalization:
//   - Ensure body ends with exactly one CRLF
//   - Multiple trailing CRLFs become one
//   - Empty body becomes single CRLF
func bodyHashSimple(h hash.Hash, body io.Reader) ([]byte, error) {
	br := bufio.NewReader(body)
	var crlf = []byte("\r\n")

	// Count trailing CRLFs, only write one at the end
	numTrailingCRLF := 0

	for {
		line, err := br.ReadBytes('\n')
		if len(line) == 0 && err == io.EOF {
			break
		}
		if err != nil && err != io.EOF {
			return nil, err
		}

		hasCRLF := bytes.HasSuffix(line, crlf)
		if hasCRLF {
			line = line[:len(line)-2]
		}

		// Write any pending CRLFs for non-empty content
		if len(line) > 0 {
			for i := 0; i < numTrailingCRLF; i++ {
				h.Write(crlf)
			}
			numTrailingCRLF = 0
			h.Write(line)
		}

		if hasCRLF {
			numTrailingCRLF++
		}
	}

	// Always end with exactly one CRLF
	h.Write(crlf)

	return h.Sum(nil), nil
}

// bodyHashRelaxed computes the body hash using relaxed canonicalization.
// Relaxed body canonicalization:
//   - Ignore all whitespace at end of lines
//   - Compress whitespace in lines to single space
//   - Ignore all empty lines at end of body
//   - Empty body stays empty (but we add CRLF per RFC)
func bodyHashRelaxed(h hash.Hash, body io.Reader) ([]byte, error) {
	br := bufio.NewReader(body)
	var crlf = []byte("\r\n")

	// Buffer empty lines to ignore trailing empty lines
	emptyLines := 0
	bodyNonEmpty := false
	lastLineHadCRLF := false

	for {
		line, err := br.ReadBytes('\n')
		if len(line) == 0 && err == io.EOF {
			break
		}
		if err != nil && err != io.EOF {
			return nil, err
		}

		bodyNonEmpty = true

		hasCRLF := bytes.HasSuffix(line, crlf)
		if hasCRLF {
			line = line[:len(line)-2]
		}

		// Trim trailing whitespace
		line = bytes.TrimRight(line, " \t")

		// Compress internal whitespace
		var processed []byte
		prevWS := false
		for _, b := range line {
			if b == ' ' || b == '\t' {
				if !prevWS {
					processed = append(processed, ' ')
					prevWS = true
				}
			} else {
				processed = append(processed, b)
				prevWS = false
			}
		}

		// Check if line is empty after processing
		if len(processed) == 0 {
			if hasCRLF {
				emptyLines++
			}
			lastLineHadCRLF = hasCRLF
			continue
		}

		// Write pending empty lines
		for i := 0; i < emptyLines; i++ {
			h.Write(crlf)
		}
		emptyLines = 0

		h.Write(processed)
		if hasCRLF {
			h.Write(crlf)
		}
		lastLineHadCRLF = hasCRLF
	}

	// Per RFC 6376: "If the body is non-null but does not end with a CRLF, a CRLF is added."
	// However, trailing CRLFs (empty lines) are ignored in relaxed mode.
	// So if we had non-empty content that didn't end with CRLF, add one.
	if bodyNonEmpty && !lastLineHadCRLF && emptyLines == 0 {
		h.Write(crlf)
	}

	return h.Sum(nil), nil
}

// computeDataHash calculates the hash of the signed headers and signature header.
func computeDataHash(h hash.Hash, canonicalization Canonicalization, headers []headerData, signedHeaders []string, sigHeader []byte) ([]byte, error) {
	// Build a map of headers in reverse order (most recent first)
	headerMap := make(map[string][]headerData)
	for i := len(headers) - 1; i >= 0; i-- {
		lkey := strings.ToLower(headers[i].key)
		headerMap[lkey] = append(headerMap[lkey], headers[i])
	}

	// Process signed headers in order
	for _, key := range signedHeaders {
		lkey := strings.ToLower(key)
		hdrs := headerMap[lkey]
		if len(hdrs) == 0 {
			// Header not present, skip (per RFC 6376 Section 5.4)
			continue
		}

		// Use the most recent one
		hdr := hdrs[0]
		headerMap[lkey] = hdrs[1:]

		if canonicalization == CanonSimple {
			// Simple: use raw header without trailing CRLF
			raw := string(hdr.raw)
			raw = strings.TrimSuffix(raw, "\r\n")
			h.Write([]byte(raw))
			h.Write([]byte("\r\n"))
		} else {
			// Relaxed: canonicalize header
			canonical, err := canonicalizeHeaderRelaxed(string(hdr.raw))
			if err != nil {
				return nil, err
			}
			h.Write([]byte(canonical))
			h.Write([]byte("\r\n"))
		}
	}

	// Add DKIM-Signature header (without trailing CRLF)
	if canonicalization == CanonSimple {
		h.Write(sigHeader)
	} else {
		canonical, err := canonicalizeHeaderRelaxed(string(sigHeader))
		if err != nil {
			return nil, err
		}
		h.Write([]byte(canonical))
	}

	return h.Sum(nil), nil
}

// headerData represents a parsed header.
type headerData struct {
	key   string // Original case
	lkey  string // Lowercase
	value []byte // Header value (after colon)
	raw   []byte // Complete header including name, colon, and value
}

// parseMessageHeaders parses message headers from raw message data.
// Returns headers and the offset where the body starts.
func parseMessageHeaders(data []byte) ([]headerData, int, error) {
	br := bufio.NewReader(bytes.NewReader(data))
	return parseHeaders(br)
}

// parseHeaders parses headers from a reader.
func parseHeaders(br *bufio.Reader) ([]headerData, int, error) {
	var headers []headerData
	var offset int
	var currentKey, currentLKey string
	var currentValue, currentRaw []byte

	for {
		line, err := readLine(br)
		if err != nil {
			return nil, 0, err
		}
		offset += len(line)

		// Empty line signals end of headers
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}

		// Check for continuation (folded header)
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if currentKey == "" {
				return nil, 0, ErrHeaderMalformed
			}
			currentValue = append(currentValue, line...)
			currentRaw = append(currentRaw, line...)
			continue
		}

		// Save previous header
		if currentKey != "" {
			headers = append(headers, headerData{
				key:   currentKey,
				lkey:  currentLKey,
				value: currentValue,
				raw:   currentRaw,
			})
		}

		// Parse new header
		colonIdx := bytes.IndexByte(line, ':')
		if colonIdx == -1 {
			return nil, 0, ErrHeaderMalformed
		}

		currentKey = strings.TrimRight(string(line[:colonIdx]), " \t")
		currentLKey = strings.ToLower(currentKey)
		currentValue = bytes.Clone(line[colonIdx+1:])
		currentRaw = bytes.Clone(line)

		// Validate header name
		for _, c := range currentKey {
			if c <= ' ' || c >= 0x7f {
				return nil, 0, ErrHeaderMalformed
			}
		}
	}

	// Don't forget the last header
	if currentKey != "" {
		headers = append(headers, headerData{
			key:   currentKey,
			lkey:  currentLKey,
			value: currentValue,
			raw:   currentRaw,
		})
	}

	return headers, offset, nil
}

// readLine reads a line including CRLF.
func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		buf = append(buf, line...)
		if bytes.HasSuffix(buf, []byte("\r\n")) {
			return buf, nil
		}
	}
}

// getHash returns the crypto.Hash for the given algorithm name.
func getHash(algorithm string) (crypto.Hash, bool) {
	switch strings.ToLower(algorithm) {
	case "sha256":
		return crypto.SHA256, true
	case "sha1":
		return crypto.SHA1, true
	default:
		return 0, false
	}
}
