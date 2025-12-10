package raven

import (
	"errors"
	"fmt"
	"strings"
)

// parseCommand splits a command line into verb and arguments.
func parseCommand(line string) (cmd, args string) {
	line = strings.TrimSpace(line)
	idx := strings.IndexByte(line, ' ')
	if idx == -1 {
		return strings.ToUpper(line), ""
	}
	return strings.ToUpper(line[:idx]), strings.TrimSpace(line[idx+1:])
}

// parsePathWithParams parses an address path with optional parameters.
func parsePathWithParams(s string) (Path, map[string]string, error) {
	params := make(map[string]string)

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

	// Parse parameters
	if paramStr != "" {
		for param := range strings.FieldsSeq(paramStr) {
			idx := strings.IndexByte(param, '=')
			if idx == -1 {
				params[strings.ToUpper(param)] = ""
			} else {
				params[strings.ToUpper(param[:idx])] = param[idx+1:]
			}
		}
	}

	return path, params, nil
}

// parseMessageContent parses raw message data into headers and body per RFC 5322.
// The header section is separated from the body by an empty line (CRLF CRLF).
func parseMessageContent(data []byte) (Headers, []byte) {
	headers := make(Headers, 0)

	// Find the header/body separator (empty line)
	// Per RFC 5322, headers and body are separated by an empty line
	var headerEnd int
	dataLen := len(data)

	for i := 0; i < dataLen-1; i++ {
		// Look for CRLF CRLF (end of headers)
		if data[i] == '\r' && data[i+1] == '\n' {
			if i+3 < dataLen && data[i+2] == '\r' && data[i+3] == '\n' {
				headerEnd = i + 2 // Points to the second CRLF
				break
			}
		}
	}

	// If no empty line found, treat entire data as body (malformed message)
	if headerEnd == 0 {
		return headers, data
	}

	// Parse headers
	headerSection := string(data[:headerEnd])
	var currentName, currentValue string

	for _, line := range strings.Split(headerSection, "\r\n") {
		if line == "" {
			continue
		}

		// Check for continuation line (starts with whitespace)
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
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

		// Parse new header
		colonIdx := strings.IndexByte(line, ':')
		if colonIdx == -1 {
			// Malformed header line, skip it
			currentName = ""
			currentValue = ""
			continue
		}

		currentName = strings.TrimSpace(line[:colonIdx])
		currentValue = strings.TrimSpace(line[colonIdx+1:])
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
