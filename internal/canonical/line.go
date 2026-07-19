// Package canonical contains allocation-conscious primitives shared by message
// canonicalizers.
package canonical

import (
	"bufio"
	"io"
)

// LineReader reads newline-terminated records without copying records that fit
// in the bufio.Reader buffer. The returned slice is valid only until the next
// call to ReadLine.
type LineReader struct {
	reader  *bufio.Reader
	scratch []byte
}

// NewLineReader returns a reusable line reader for r.
func NewLineReader(r io.Reader) *LineReader {
	if reader, ok := r.(*bufio.Reader); ok {
		return &LineReader{reader: reader}
	}
	return &LineReader{reader: bufio.NewReader(r)}
}

// ReadLine returns the next line, including its trailing newline. Long lines
// are assembled in reusable scratch storage.
func (r *LineReader) ReadLine() ([]byte, error) {
	line, err := r.reader.ReadSlice('\n')
	if err != bufio.ErrBufferFull {
		return line, err
	}

	r.scratch = append(r.scratch[:0], line...)
	for err == bufio.ErrBufferFull {
		line, err = r.reader.ReadSlice('\n')
		r.scratch = append(r.scratch, line...)
	}
	return r.scratch, err
}

// CompressWhitespace replaces each run of spaces and tabs with one space. It
// reuses line's backing array and returns the resulting subslice.
func CompressWhitespace(line []byte) []byte {
	write := 0
	previousWhitespace := false
	for _, b := range line {
		if b == ' ' || b == '\t' {
			if previousWhitespace {
				continue
			}
			b = ' '
			previousWhitespace = true
		} else {
			previousWhitespace = false
		}
		line[write] = b
		write++
	}
	return line[:write]
}
