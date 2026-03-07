package crypto

import "testing"

func TestGenerateID(t *testing.T) {
	id := GenerateID()
	if id == "" {
		t.Error("GenerateID() returned empty string")
	}

	if len(id) != 26 {
		t.Errorf("GenerateID() returned string of length %d, want %d", len(id), 26)
	}

	for _, c := range id {
		if !isULIDChar(c) {
			t.Errorf("GenerateID() returned invalid ULID character: %c", c)
			break
		}
	}

	ids := make(map[string]bool)
	for range 100 {
		newID := GenerateID()
		if ids[newID] {
			t.Errorf("GenerateID() returned duplicate ID: %s", newID)
		}
		ids[newID] = true
	}
}

func isULIDChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'H') || (c >= 'J' && c <= 'K') ||
		(c >= 'M' && c <= 'N') || (c >= 'P' && c <= 'T') || (c >= 'V' && c <= 'Z')
}
