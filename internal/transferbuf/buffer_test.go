package transferbuf

import "testing"

func TestGetUsesBoundedSizeClasses(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantCap int
		pooled  bool
	}{
		{name: "empty", size: 0},
		{name: "read", size: ReadSize, wantCap: ReadSize, pooled: true},
		{name: "dot stuff", size: ReadSize + 1, wantCap: DotStuffSize, pooled: true},
		{name: "chunk", size: DotStuffSize + 1, wantCap: ChunkSize, pooled: true},
		{name: "oversized", size: ChunkSize + 1, wantCap: ChunkSize + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buffer := Get(tt.size)
			if got := len(buffer.Bytes); got != tt.size {
				t.Fatalf("len(Get(%d).Bytes) = %d, want %d", tt.size, got, tt.size)
			}
			if got := cap(buffer.Bytes); got != tt.wantCap {
				t.Fatalf("cap(Get(%d).Bytes) = %d, want %d", tt.size, got, tt.wantCap)
			}
			if got := buffer.pool != nil; got != tt.pooled {
				t.Fatalf("Get(%d) pooled = %v, want %v", tt.size, got, tt.pooled)
			}
			buffer.Release()
			if buffer.Bytes != nil {
				t.Fatal("Release() retained the caller's byte slice")
			}
			buffer.Release()
		})
	}
}

func TestPooledGetAndReleaseDoNotAllocateAfterWarmup(t *testing.T) {
	buffer := Get(ReadSize)
	buffer.Release()

	allocations := testing.AllocsPerRun(100, func() {
		buffer := Get(ReadSize)
		buffer.Release()
	})
	if allocations != 0 {
		t.Fatalf("Get/Release allocations = %v, want 0", allocations)
	}
}
