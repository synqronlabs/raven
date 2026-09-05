package mail

import "testing"

func TestParseDSNXText(t *testing.T) {
	value, err := ParseDSNXText("one+20two+2Bthree+3Dfour")
	if err != nil {
		t.Fatal(err)
	}
	if value.Decoded != "one two+three=four" {
		t.Fatalf("Decoded = %q", value.Decoded)
	}
	if value.Wire != "one+20two+2Bthree+3Dfour" {
		t.Fatalf("Wire = %q", value.Wire)
	}
}

func TestParseDSNXTextRejectsMalformedEscapes(t *testing.T) {
	for _, value := range []string{"+", "+2", "+2f", "+GG", "raw=value", "raw value"} {
		t.Run(value, func(t *testing.T) {
			if _, err := ParseDSNXText(value); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
