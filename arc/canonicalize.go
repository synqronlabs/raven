package arc

import (
	"bufio"
	"bytes"
	"hash"
	"io"
	"strings"
)

// computeBodyHash calculates the hash of the message body with optional length limit.
func computeBodyHash(h hash.Hash, canon Canonicalization, body io.Reader, lengthLimit int64) ([]byte, error) {
	if canon == CanonRelaxed {
		return bodyHashRelaxed(h, body, lengthLimit)
	}
	return bodyHashSimple(h, body, lengthLimit)
}

// bodyHashSimple computes the body hash using simple canonicalization.
// Simple body canonicalization:
//   - Ensure body ends with exactly one CRLF
//   - Multiple trailing CRLFs become one
//   - Empty body becomes single CRLF
func bodyHashSimple(h hash.Hash, body io.Reader, lengthLimit int64) ([]byte, error) {
	br := bufio.NewReader(body)
	var crlf = []byte("\r\n")
	var written int64

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
				if lengthLimit >= 0 && written+2 > lengthLimit {
					// Don't write more than limit
					break
				}
				h.Write(crlf)
				written += 2
			}
			numTrailingCRLF = 0

			toWrite := line
			if lengthLimit >= 0 && written+int64(len(toWrite)) > lengthLimit {
				toWrite = toWrite[:lengthLimit-written]
			}
			h.Write(toWrite)
			written += int64(len(toWrite))
		}

		if hasCRLF {
			numTrailingCRLF++
		}

		if lengthLimit >= 0 && written >= lengthLimit {
			break
		}
	}

	// Always end with exactly one CRLF
	if lengthLimit < 0 || written+2 <= lengthLimit {
		h.Write(crlf)
	}

	return h.Sum(nil), nil
}

// bodyHashRelaxed computes the body hash using relaxed canonicalization.
// Relaxed body canonicalization:
//   - Ignore all whitespace at end of lines
//   - Compress whitespace in lines to single space
//   - Ignore all empty lines at end of body
//   - Empty body stays empty (but we add CRLF per RFC)
func bodyHashRelaxed(h hash.Hash, body io.Reader, lengthLimit int64) ([]byte, error) {
	br := bufio.NewReader(body)
	var crlf = []byte("\r\n")
	var written int64

	// Buffer empty lines to ignore trailing empty lines
	emptyLines := 0
	bodyNonEmpty := false

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
		line = compressWhitespace(line)

		// Empty line (after canonicalization)?
		if len(line) == 0 {
			if hasCRLF {
				emptyLines++
			}
			continue
		}

		// Write buffered empty lines
		for i := 0; i < emptyLines; i++ {
			if lengthLimit >= 0 && written+2 > lengthLimit {
				break
			}
			h.Write(crlf)
			written += 2
		}
		emptyLines = 0

		// Write the line content
		toWrite := line
		if lengthLimit >= 0 && written+int64(len(toWrite)) > lengthLimit {
			toWrite = toWrite[:lengthLimit-written]
		}
		h.Write(toWrite)
		written += int64(len(toWrite))

		// Write CRLF
		if hasCRLF {
			if lengthLimit < 0 || written+2 <= lengthLimit {
				h.Write(crlf)
				written += 2
			}
		}

		if lengthLimit >= 0 && written >= lengthLimit {
			break
		}
	}

	// Per RFC 6376, empty body with relaxed canonicalization should hash CRLF
	if !bodyNonEmpty || written == 0 {
		h.Write(crlf)
	}

	return h.Sum(nil), nil
}

// compressWhitespace compresses runs of whitespace to a single space.
func compressWhitespace(line []byte) []byte {
	var result []byte
	prevWS := false
	for _, c := range line {
		if c == ' ' || c == '\t' {
			if !prevWS {
				result = append(result, ' ')
				prevWS = true
			}
		} else {
			result = append(result, c)
			prevWS = false
		}
	}
	return result
}

// canonicalizeHeaderRelaxed returns the header in relaxed canonicalization.
func canonicalizeHeaderRelaxed(header []byte) (string, error) {
	// Find header name and value
	idx := bytes.Index(header, []byte(":"))
	if idx == -1 {
		return "", ErrSyntax
	}

	name := strings.ToLower(strings.TrimRight(string(header[:idx]), " \t"))
	value := string(header[idx+1:])

	// Remove trailing CRLF from value
	value = strings.TrimRight(value, "\r\n")

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

// computeAMSDataHash computes the data hash for ARC-Message-Signature verification.
func computeAMSDataHash(h hash.Hash, headerCanon Canonicalization, headers []headerData, signedHeaders []string, amsHeader []byte) ([]byte, error) {
	// Build list of headers to hash in order specified by h= tag
	// Per RFC 6376, we match headers from bottom to top
	headerCounts := make(map[string]int)
	for _, name := range signedHeaders {
		headerCounts[strings.ToLower(name)]++
	}

	// Find headers matching the signed list
	headerIndices := make(map[string][]int)
	for i := len(headers) - 1; i >= 0; i-- {
		lkey := headers[i].lkey
		if _, ok := headerCounts[lkey]; ok {
			headerIndices[lkey] = append(headerIndices[lkey], i)
		}
	}

	// Hash headers in order specified
	for _, name := range signedHeaders {
		lname := strings.ToLower(name)
		indices := headerIndices[lname]
		if len(indices) == 0 {
			continue
		}

		// Take the next available header (first in list = most recent unprocessed)
		idx := indices[0]
		headerIndices[lname] = indices[1:]

		hdr := headers[idx]
		var canonHeader string
		var err error

		if headerCanon == CanonRelaxed {
			canonHeader, err = canonicalizeHeaderRelaxed(hdr.raw)
			if err != nil {
				return nil, err
			}
		} else {
			// Simple: use raw header without trailing CRLF
			canonHeader = strings.TrimRight(string(hdr.raw), "\r\n")
		}

		h.Write([]byte(canonHeader))
		h.Write([]byte("\r\n"))
	}

	// Hash the ARC-Message-Signature header (with empty b= value)
	amsForHash := removeSignature(amsHeader)
	var canonAMS string
	var err error

	if headerCanon == CanonRelaxed {
		canonAMS, err = canonicalizeHeaderRelaxed(amsForHash)
		if err != nil {
			return nil, err
		}
	} else {
		canonAMS = strings.TrimRight(string(amsForHash), "\r\n")
	}

	// Final header is added without trailing CRLF
	h.Write([]byte(canonAMS))

	return h.Sum(nil), nil
}

// computeSealDataHash computes the data hash for ARC-Seal verification.
func computeSealDataHash(h hash.Hash, sets []*Set, headers []headerData) ([]byte, error) {
	// Per RFC 8617 Section 5.1.2:
	// The ARC-Seal covers (in order, relaxed canonicalization):
	// 1. ARC-Authentication-Results headers (i=1 to i=n)
	// 2. ARC-Message-Signature headers (i=1 to i=n)
	// 3. ARC-Seal headers (i=1 to i=n, with b= emptied for the last one)

	// Find headers in the message
	aarHeaders := make(map[int]headerData)
	amsHeaders := make(map[int]headerData)
	asHeaders := make(map[int]headerData)

	for _, hdr := range headers {
		switch hdr.lkey {
		case "arc-authentication-results":
			aar, _ := ParseAuthenticationResults(extractHeaderValue(hdr.raw))
			if aar != nil {
				aarHeaders[aar.Instance] = hdr
			}
		case "arc-message-signature":
			ms, _, _ := ParseMessageSignature(extractHeaderValue(hdr.raw))
			if ms != nil {
				amsHeaders[ms.Instance] = hdr
			}
		case "arc-seal":
			seal, _, _ := ParseSeal(extractHeaderValue(hdr.raw))
			if seal != nil {
				asHeaders[seal.Instance] = hdr
			}
		}
	}

	n := len(sets)

	// Hash ARC-Authentication-Results (i=1 to i=n)
	for i := 1; i <= n; i++ {
		hdr, ok := aarHeaders[i]
		if !ok {
			return nil, ErrInvalidChain
		}
		canonHeader, err := canonicalizeHeaderRelaxed(hdr.raw)
		if err != nil {
			return nil, err
		}
		h.Write([]byte(canonHeader))
		h.Write([]byte("\r\n"))
	}

	// Hash ARC-Message-Signature (i=1 to i=n)
	for i := 1; i <= n; i++ {
		hdr, ok := amsHeaders[i]
		if !ok {
			return nil, ErrInvalidChain
		}
		canonHeader, err := canonicalizeHeaderRelaxed(hdr.raw)
		if err != nil {
			return nil, err
		}
		h.Write([]byte(canonHeader))
		h.Write([]byte("\r\n"))
	}

	// Hash ARC-Seal (i=1 to i=n, with b= emptied for i=n)
	for i := 1; i <= n; i++ {
		hdr, ok := asHeaders[i]
		if !ok {
			return nil, ErrInvalidChain
		}

		var rawHeader []byte
		if i == n {
			// Empty b= for the last seal
			rawHeader = removeSignature(hdr.raw)
		} else {
			rawHeader = hdr.raw
		}

		canonHeader, err := canonicalizeHeaderRelaxed(rawHeader)
		if err != nil {
			return nil, err
		}

		if i == n {
			// Last header without trailing CRLF
			h.Write([]byte(canonHeader))
		} else {
			h.Write([]byte(canonHeader))
			h.Write([]byte("\r\n"))
		}
	}

	return h.Sum(nil), nil
}

// removeSignature removes the b= value from a signature header for verification.
func removeSignature(header []byte) []byte {
	// Find b= tag and empty its value
	headerStr := string(header)

	// Handle both raw header and just the value
	bIdx := strings.Index(strings.ToLower(headerStr), "b=")
	if bIdx == -1 {
		return header
	}

	// Find the end of the b= value (next ; or end of header)
	endIdx := bIdx + 2 // Start after "b="
	depth := 0
	for endIdx < len(headerStr) {
		c := headerStr[endIdx]
		if c == ';' && depth == 0 {
			break
		}
		if c == '(' {
			depth++
		}
		if c == ')' && depth > 0 {
			depth--
		}
		endIdx++
	}

	// Build the result with empty b= value
	result := headerStr[:bIdx+2] + headerStr[endIdx:]
	return []byte(result)
}
