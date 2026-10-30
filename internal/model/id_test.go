package model

import (
	"strings"
	"testing"
)

func TestValidID(t *testing.T) {
	for _, test := range []struct {
		name string
		id   string
		want bool
	}{
		{name: "mixed lowercase hex", id: "0123456789abcdef0123456789abcdef", want: true},
		{name: "all digits", id: strings.Repeat("0", 32), want: true},
		{name: "all letters", id: strings.Repeat("f", 32), want: true},
		{name: "empty"},
		{name: "too short", id: strings.Repeat("0", 31)},
		{name: "too long", id: strings.Repeat("0", 33)},
		{name: "uppercase", id: strings.Repeat("A", 32)},
		{name: "non-hex letter", id: strings.Repeat("0", 31) + "g"},
		{name: "before digit", id: strings.Repeat("0", 31) + "/"},
		{name: "after digit", id: strings.Repeat("0", 31) + ":"},
		{name: "before lowercase", id: strings.Repeat("0", 31) + "`"},
		{name: "whitespace", id: strings.Repeat("0", 31) + " "},
		{name: "non-ASCII", id: strings.Repeat("0", 30) + "é"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ValidID(test.id); got != test.want {
				t.Fatalf("ValidID(%q) = %v, want %v", test.id, got, test.want)
			}
		})
	}
}
