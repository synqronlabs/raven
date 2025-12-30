package raven

import (
	"errors"
	"fmt"
	"strings"
)

// parseCommand splits a command line into verb and arguments.
func parseCommand(line string) (cmd Command, args string) {
	before, after, found := strings.Cut(line, " ")

	if !found {
		// Case: "QUIT", "NOOP", "RSET" (No arguments)
		cmd := canonicalizeVerb(before)
		return cmd, ""
	}

	// Case: "MAIL FROM:...", "RCPT TO:..."
	// Trim the args, but canonicalize the verb without allocation.
	cmd = canonicalizeVerb(before)
	return cmd, strings.TrimSpace(after)
}

func canonicalizeVerb(verb string) Command {
	switch len(verb) {
	case 4:
		if strings.EqualFold(verb, "HELO") {
			return CmdHelo
		}
		if strings.EqualFold(verb, "EHLO") {
			return CmdEhlo
		}
		if strings.EqualFold(verb, "MAIL") {
			return CmdMail
		}
		if strings.EqualFold(verb, "RCPT") {
			return CmdRcpt
		}
		if strings.EqualFold(verb, "DATA") {
			return CmdData
		}
		if strings.EqualFold(verb, "BDAT") {
			return CmdBdat
		}
		if strings.EqualFold(verb, "RSET") {
			return CmdRset
		}
		if strings.EqualFold(verb, "VRFY") {
			return CmdVrfy
		}
		if strings.EqualFold(verb, "EXPN") {
			return CmdExpn
		}
		if strings.EqualFold(verb, "HELP") {
			return CmdHelp
		}
		if strings.EqualFold(verb, "NOOP") {
			return CmdNoop
		}
		if strings.EqualFold(verb, "QUIT") {
			return CmdQuit
		}
		if strings.EqualFold(verb, "AUTH") {
			return CmdAuth
		}
	case 8:
		if strings.EqualFold(verb, "STARTTLS") {
			return CmdStartTLS
		}
	}
	return Command(strings.ToUpper(verb))
}

// parsePathWithParams parses an address path with optional parameters.
// Duplicate parameters are rejected.
func parsePathWithParams(s string) (Path, map[string]string, error) {
	start := strings.IndexByte(s, '<')
	end := strings.IndexByte(s, '>')

	if start == -1 || end == -1 || end < start {
		return Path{}, nil, errors.New("missing angle brackets")
	}

	address := s[start+1 : end]
	paramStr := strings.TrimSpace(s[end+1:])

	var path Path
	if address == "" {
		path = Path{}
	} else {
		addr, err := ParseAddress(address)
		if err != nil {
			return Path{}, nil, fmt.Errorf("invalid address: %w", err)
		}
		path = Path{Mailbox: addr}
	}

	var params map[string]string
	if paramStr != "" {
		params = make(map[string]string)
		for param := range strings.FieldsSeq(paramStr) {
			var key, value string
			if before, after, found := strings.Cut(param, "="); found {
				key = strings.ToUpper(before)
				value = after
			} else {
				key = strings.ToUpper(param)
				value = ""
			}
			if _, exists := params[key]; exists {
				return Path{}, nil, fmt.Errorf("duplicate parameter: %s", key)
			}
			params[key] = value
		}
	}

	return path, params, nil
}
