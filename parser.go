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
