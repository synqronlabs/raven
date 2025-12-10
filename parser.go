package raven

import (
	"errors"
	"fmt"
	"strings"
)

// parseCommand splits a command line into verb and arguments.
func parseCommand(line string) (cmd, args string) {
	line = strings.TrimSpace(line)
	if before, after, found := strings.Cut(line, " "); found {
		return strings.ToUpper(before), strings.TrimSpace(after)
	}
	return strings.ToUpper(line), ""
}

// parsePathWithParams parses an address path with optional parameters.
func parsePathWithParams(s string) (Path, map[string]string, error) {
	// Find the angle-bracketed address
	start := strings.IndexByte(s, '<')
	end := strings.IndexByte(s, '>')

	if start == -1 || end == -1 || end < start {
		return Path{}, nil, errors.New("missing angle brackets")
	}

	address := s[start+1 : end]
	paramStr := strings.TrimSpace(s[end+1:])

	// Parse address
	var path Path
	if address == "" {
		// Null path
		path = Path{}
	} else {
		addr, err := ParseAddress(address)
		if err != nil {
			return Path{}, nil, fmt.Errorf("invalid address: %w", err)
		}
		path = Path{Mailbox: addr}
	}

	// Parse parameters - lazy allocate map only when needed
	var params map[string]string
	if paramStr != "" {
		params = make(map[string]string)
		for param := range strings.FieldsSeq(paramStr) {
			if before, after, found := strings.Cut(param, "="); found {
				params[strings.ToUpper(before)] = after
			} else {
				params[strings.ToUpper(param)] = ""
			}
		}
	}

	return path, params, nil
}

// parseMessageContent parses raw message data into headers and body per RFC 5322.
// The header section is separated from the body by an empty line (CRLF CRLF).
func parseMessageContent(data []byte) (Headers, []byte) {
	// Find the header/body separator (empty line)
	// Per RFC 5322, headers and body are separated by an empty line
	var headerEnd int
	dataLen := len(data)

	for i := 0; i < dataLen-3; i++ {
		// Look for CRLF CRLF (end of headers)
		if data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n' {
			headerEnd = i + 2 // Points to the second CRLF
			break
		}
	}

	// If no empty line found, treat entire data as body (malformed message)
	if headerEnd == 0 {
		return nil, data
	}

	// Parse headers directly from bytes to avoid string conversion of entire header section
	// Estimate header count (average ~50 bytes per header)
	estimatedHeaders := max(headerEnd/50, 8)
	headers := make(Headers, 0, estimatedHeaders)

	var currentName, currentValue string
	lineStart := 0

	for i := 0; i < headerEnd; i++ {
		// Find end of line (CRLF)
		if data[i] == '\r' && i+1 < headerEnd && data[i+1] == '\n' {
			line := string(data[lineStart:i])
			lineStart = i + 2
			i++ // Skip the \n

			if line == "" {
				continue
			}

			// Check for continuation line (starts with whitespace)
			if line[0] == ' ' || line[0] == '\t' {
				// Continuation of previous header (folded header per RFC 5322)
				if currentName != "" {
					currentValue += " " + strings.TrimSpace(line)
				}
				continue
			}

			// Save previous header if exists
			if currentName != "" {
				headers = append(headers, Header{Name: currentName, Value: currentValue})
			}

			// Parse new header using strings.Cut
			if name, value, found := strings.Cut(line, ":"); found {
				currentName = strings.TrimSpace(name)
				currentValue = strings.TrimSpace(value)
			} else {
				// Malformed header line, skip it
				currentName = ""
				currentValue = ""
			}
		}
	}

	// Don't forget the last header
	if currentName != "" {
		headers = append(headers, Header{Name: currentName, Value: currentValue})
	}

	// Body starts after the empty line (CRLF CRLF)
	var body []byte
	if headerEnd+2 < dataLen {
		body = data[headerEnd+2:]
	}

	return headers, body
}
