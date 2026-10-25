package logger

import "testing"

func TestNew(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		log, err := New(level)
		if err != nil {
			t.Fatal(err)
		}
		if log.Core().Enabled(-1) != (level == "debug") {
			t.Fatalf("level %s", level)
		}
		_ = log.Sync()
	}
	if _, err := New("invalid"); err == nil {
		t.Fatal("accepted invalid level")
	}
}
