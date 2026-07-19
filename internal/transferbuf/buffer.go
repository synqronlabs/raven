// Package transferbuf provides bounded scratch-buffer pools for streaming
// message data.
package transferbuf

import "sync"

const (
	// ReadSize is the standard size for streaming reads.
	ReadSize = 32 * 1024
	// DotStuffSize holds the worst-case expansion of a ReadSize DATA chunk.
	DotStuffSize = 48 * 1024
	// ChunkSize is the default client BDAT chunk size.
	ChunkSize = 64 * 1024
)

var (
	readPool     = newPool(ReadSize)
	dotStuffPool = newPool(DotStuffSize)
	chunkPool    = newPool(ChunkSize)
)

func newPool(size int) *sync.Pool {
	return &sync.Pool{New: func() any {
		buffer := make([]byte, size)
		return &buffer
	}}
}

// Buffer owns borrowed scratch bytes. Release must be called when the transfer
// finishes. Buffers larger than ChunkSize are allocated exactly and discarded
// by Release rather than retained.
type Buffer struct {
	Bytes  []byte
	holder *[]byte
	pool   *sync.Pool
}

// Get returns a buffer of exactly size bytes from the smallest sufficient size
// class. Non-positive sizes return an empty buffer.
func Get(size int) Buffer {
	if size <= 0 {
		return Buffer{}
	}

	switch {
	case size <= ReadSize:
		return getPooled(readPool, size)
	case size <= DotStuffSize:
		return getPooled(dotStuffPool, size)
	case size <= ChunkSize:
		return getPooled(chunkPool, size)
	default:
		return Buffer{Bytes: make([]byte, size)}
	}
}

func getPooled(pool *sync.Pool, size int) Buffer {
	holder := pool.Get().(*[]byte)
	return Buffer{
		Bytes:  (*holder)[:size],
		holder: holder,
		pool:   pool,
	}
}

// Release returns a pooled buffer to its size class. It is safe to call more
// than once.
func (b *Buffer) Release() {
	if b == nil {
		return
	}
	if b.pool != nil {
		*b.holder = (*b.holder)[:cap(*b.holder)]
		b.pool.Put(b.holder)
	}
	b.Bytes = nil
	b.holder = nil
	b.pool = nil
}
