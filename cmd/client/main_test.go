package main

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBuiltClientReportsInjectedVersionAndDate(t *testing.T) {
	name := "client"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(t.TempDir(), name)
	build := exec.Command("go", "build", "-ldflags", "-X main.version=v1.2.3-test -X main.buildDate=2026-10-18T12:00:00Z", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build stamped client: %v\n%s", err, output)
	}
	output, err := exec.Command(binary, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Version   string `json:"version"`
		BuildDate string `json:"build_date"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("version output is not JSON: %v: %s", err, output)
	}
	if result.Version != "v1.2.3-test" || result.BuildDate != "2026-10-18T12:00:00Z" {
		t.Fatalf("lost link-time metadata: %+v", result)
	}
}
