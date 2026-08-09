package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnableFileLoggingReplacesAndClosesPreviousFile(t *testing.T) {
	first := filepath.Join(t.TempDir(), "first.log")
	second := filepath.Join(t.TempDir(), "second.log")
	if err := EnableFileLogging(first); err != nil {
		t.Fatal(err)
	}
	Info("first message")
	if err := EnableFileLogging(second); err != nil {
		t.Fatal(err)
	}
	defer CloseFile()
	data, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "first message") {
		t.Fatalf("previous writer was not flushed: %q", data)
	}
}
