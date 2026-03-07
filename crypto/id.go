package crypto

import (
	"math/rand/v2"
	"time"

	"github.com/oklog/ulid/v2"
)

type fastEntropy struct{}

func (fastEntropy) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(rand.Uint32())
	}
	return len(p), nil
}

var entropy = ulid.Monotonic(fastEntropy{}, 0)

// GenerateID creates a unique identifier using ULID.
func GenerateID() string {
	return ulid.MustNew(ulid.Timestamp(time.Now()), entropy).String()
}
