package mail

import (
	"testing"
	"time"
)

func TestParseDate_ObsoleteForms(t *testing.T) {
	valid := []struct {
		value string
		want  time.Time
	}{
		{"Thu, 12 Dec 2024 10:00:00 +0000", time.Date(2024, 12, 12, 10, 0, 0, 0, time.UTC)},
		{"12 Dec 2024 10:00 +0000", time.Date(2024, 12, 12, 10, 0, 0, 0, time.UTC)},
		{"Thu, 2 Dec 2024 1:2:3 +0000", time.Date(2024, 12, 2, 1, 2, 3, 0, time.UTC)},
		{"Thu, 12 Dec 49 10:00:00 +0000", time.Date(2049, 12, 12, 10, 0, 0, 0, time.UTC)},
		{"Thu, 12 Dec 50 10:00:00 +0000", time.Date(1950, 12, 12, 10, 0, 0, 0, time.UTC)},
		{"Thu, 12 Dec 2024 10:00:00 -0730", time.Date(2024, 12, 12, 10, 0, 0, 0, time.FixedZone("", -7*3600-30*60))},
		{"Thu, 12 Dec 2024 10:00:00 UT", time.Date(2024, 12, 12, 10, 0, 0, 0, time.UTC)},
		{"Thu, 12 Dec 2024 10:00:00 GMT", time.Date(2024, 12, 12, 10, 0, 0, 0, time.UTC)},
		{"Thu, 12 Dec 2024 10:00:00 EST", time.Date(2024, 12, 12, 10, 0, 0, 0, time.FixedZone("", -5*3600))},
		{"Thu, 12 Dec 2024 10:00:00 PDT", time.Date(2024, 12, 12, 10, 0, 0, 0, time.FixedZone("", -7*3600))},
		{"Thu, 12 Dec 2024 10:00:00 Z", time.Date(2024, 12, 12, 10, 0, 0, 0, time.UTC)},
		{"Thu, 12 Dec 2024 10:00:00 A", time.Date(2024, 12, 12, 10, 0, 0, 0, time.FixedZone("", 3600))},
		{"Thu, 12 Dec 2024 10:00:00 M", time.Date(2024, 12, 12, 10, 0, 0, 0, time.FixedZone("", 12*3600))},
		{"Thu, 12 Dec 2024 10:00:00 N", time.Date(2024, 12, 12, 10, 0, 0, 0, time.FixedZone("", -3600))},
		{"Thu, 12 Dec 2024 10:00:00 Y", time.Date(2024, 12, 12, 10, 0, 0, 0, time.FixedZone("", -12*3600))},
		{"Thu,(c) 12 Dec 2024 10 : 00 : 00 +0000", time.Date(2024, 12, 12, 10, 0, 0, 0, time.UTC)},
		{"Thu, 12 Dec 2024 10:00:00 +0000 (comment)", time.Date(2024, 12, 12, 10, 0, 0, 0, time.UTC)},
		{"thu, 12 dec 2024 10:00:00 +0000", time.Date(2024, 12, 12, 10, 0, 0, 0, time.UTC)},
	}

	for _, tt := range valid {
		t.Run(tt.value, func(t *testing.T) {
			got, err := ParseDate(tt.value)
			if err != nil {
				t.Fatalf("ParseDate(%q) error: %v", tt.value, err)
			}
			if !got.Equal(tt.want) {
				t.Errorf("ParseDate(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestParseDate_Invalid(t *testing.T) {
	invalid := []string{
		"",
		"not a date",
		"Thu, 12 Dec 2024",
		"Thu, 12 Dec 2024 10:00:00",
		"Thu, 12 Dec 2024 10:00:00 +00",
		"Thu, 12 Dec 2024 10:00:00 +00000",
		"Thu, 12 Dec 2024 10:00:00 +9900",
		"Thu, 12 Dec 2024 10:00:00 +0060",
		"Thu, 12 Dec 2024 25:00:00 +0000",
		"Thu, 12 Dec 2024 10:60:00 +0000",
		"Thu, 12 Dec 2024 10:00:61 +0000",
		"Thu, 0 Dec 2024 10:00:00 +0000",
		"Thu, 32 Dec 2024 10:00:00 +0000",
		"Thu, 12 Foo 2024 10:00:00 +0000",
		"Xyz, 12 Dec 2024 10:00:00 +0000",
		"Thu, 12 Dec 2024 10:00:00 J",
		"Thu, 12 Dec 2024 10:00:00 XYZ",
		"Thu, 12 Dec 2024 10:00:00 +0000 extra",
		"Thu, 12 Dec 2024 10:00:00 +0000 (unclosed",
		"Thu, 12 Dec 2024 10:00:00",
	}

	for _, value := range invalid {
		if _, err := ParseDate(value); err == nil {
			t.Errorf("ParseDate(%q) = nil error, want error", value)
		}
	}
}

func TestParseDate_MonthNames(t *testing.T) {
	months := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	for i, month := range months {
		value := "1 " + month + " 2024 00:00:00 +0000"
		got, err := ParseDate(value)
		if err != nil {
			t.Fatalf("ParseDate(%q) error: %v", value, err)
		}
		if got.Month() != time.Month(i+1) {
			t.Errorf("ParseDate(%q).Month() = %v, want %v", value, got.Month(), time.Month(i+1))
		}
	}
}

func TestParseDate_MalformedComments(t *testing.T) {
	inputs := []string{
		"(unclosed",
		"Mon (unclosed",
		"Mon, (unclosed",
		"12 Dec 2024 (unclosed",
		"12 Dec 2024 10: (unclosed",
		"12 Dec 2024 10:00 (unclosed",
		"12 Dec 2024 10:00: (unclosed",
		"12 Dec 2024 10:00:00 (unclosed",
	}
	for _, input := range inputs {
		if _, err := ParseDate(input); err == nil {
			t.Errorf("ParseDate(%q) = nil error, want error", input)
		}
	}
}

func TestParseDate_ComponentErrors(t *testing.T) {
	inputs := []string{
		"12 Dec 2024 10::00 +0000",   // missing minute
		"12 Dec 2024 10:00:xx +0000", // non-numeric second
		"12 Dec 2024 10:xx:00 +0000", // non-numeric minute
		"12 Dec 2024 10:00:00 +00x0", // non-numeric zone digit
	}
	for _, input := range inputs {
		if _, err := ParseDate(input); err == nil {
			t.Errorf("ParseDate(%q) = nil error, want error", input)
		}
	}
}
