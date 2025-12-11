package io

import (
	"bufio"
	"errors"
)

var (
	ErrLineTooLong    = errors.New("smtp: line too long")
	ErrBadLineEnding  = errors.New("smtp: line not terminated by CRLF")
	Err8BitIn7BitMode = errors.New("smtp: 8-bit data in 7BIT mode")
)

// readLine reads a single SMTP line with strict CRLF, length enforcement,
// and 7-bit ASCII validation.
func ReadLine(reader *bufio.Reader, max int, enforce bool) (string, error) {
	// FAST PATH: Try to read the full line in one go (zero-copy view).
	line, err := reader.ReadSlice('\n')
	if err == nil {
		if !isASCII(line) && enforce {
			return "", ErrLineTooLong
		}
		return validateAndConvert(line, max)
	}

	// If it's not ErrBufferFull, it's a read error (EOF, etc).
	if err != bufio.ErrBufferFull {
		return "", err
	}

	// SLOW PATH: The line is larger than the bufio buffer.
	// We must accumulate chunks.
	var buf []byte

	// Copy the first chunk immediately because the next ReadSlice will overwrite it.
	// We can validate this chunk immediately to fail early.
	if !isASCII(line) && enforce {
		return "", Err8BitIn7BitMode
	}
	buf = append(buf, line...)

	for {
		// Read the next chunk
		line, err = reader.ReadSlice('\n')

		if len(buf)+len(line) > max {
			// Drain the rest of the line so the next read starts fresh
			drainLine(reader)
			return "", ErrLineTooLong
		}

		if !isASCII(line) && enforce {
			return "", Err8BitIn7BitMode
		}

		buf = append(buf, line...)

		if err == nil {
			break
		}

		if err != bufio.ErrBufferFull {
			return "", err
		}
	}

	return validateAndConvert(buf, max)
}

// validateAndConvert checks length, CRLF, and converts to string.
func validateAndConvert(b []byte, max int) (string, error) {
	if len(b) > max {
		// No need to drain here; if we have the whole line in 'b',
		// we have already read it from the wire.
		return "", ErrLineTooLong
	}

	// Check CRLF (Strict SMTP requirement)
	// We know b ends in '\n' because ReadSlice returned nil error.
	if len(b) < 2 || b[len(b)-2] != '\r' {
		return "", ErrBadLineEnding
	}

	return string(b[:len(b)-2]), nil
}

// isASCII checks if the byte array contains any octet is not US-ASCII
func isASCII(b []byte) bool {
	for _, c := range b {
		if c > 127 {
			return false
		}
	}
	return true
}

// drainLine discards the rest of the current line to recover protocol synchronization.
func drainLine(reader *bufio.Reader) {
	for {
		_, err := reader.ReadSlice('\n')
		if err == nil {
			return // Found the newline
		}
		if err != bufio.ErrBufferFull {
			return // EOF or other error, stop draining
		}
	}
}
