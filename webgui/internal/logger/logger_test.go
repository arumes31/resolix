package logger

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLevelsAndFiltering(t *testing.T) {
	t.Cleanup(func() {
		SetLevel("INFO")
		stdLogger.SetOutput(os.Stderr)
	})

	tests := []struct {
		input string
		want  Level
	}{
		{input: "debug", want: LevelDebug},
		{input: " INFO ", want: LevelInfo},
		{input: "warning", want: LevelWarning},
		{input: "warn", want: LevelWarning},
		{input: "error", want: LevelError},
		{input: "unknown", want: LevelInfo},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			SetLevel(test.input)
			if got := GetLevel(); got != test.want {
				t.Fatalf("GetLevel() = %v, want %v", got, test.want)
			}
		})
	}

	var output bytes.Buffer
	stdLogger.SetOutput(&output)
	SetLevel("WARNING")
	Debug("hidden debug")
	Info("hidden info")
	Warning("visible warning %d", 1)
	Warn("visible alias")
	Error("visible error")
	Printf("visible printf")
	Println("visible", " println")
	text := output.String()
	for _, hidden := range []string{"hidden debug", "hidden info", "visible printf", "visible println"} {
		if strings.Contains(text, hidden) {
			t.Fatalf("filtered message %q was written: %q", hidden, text)
		}
	}
	for _, visible := range []string{"visible warning 1", "visible alias", "visible error"} {
		if !strings.Contains(text, visible) {
			t.Fatalf("message %q missing from %q", visible, text)
		}
	}
}

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
	data, err := os.ReadFile(first) // #nosec G304 -- test reads a file it just created under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "first message") {
		t.Fatalf("previous writer was not flushed: %q", data)
	}
}

func TestFileLoggingWritesAndHandlesInvalidPath(t *testing.T) {
	CloseFile()
	Flush()
	if err := EnableFileLogging(filepath.Join(t.TempDir(), "missing", "resolix.log")); err == nil {
		t.Fatal("EnableFileLogging unexpectedly accepted a missing parent directory")
	}

	path := filepath.Join(t.TempDir(), "resolix.log")
	if err := EnableFileLogging(path); err != nil {
		t.Fatal(err)
	}
	SetLevel("DEBUG")
	Debug("debug %d", 1)
	Info("info")
	Warning("warning")
	Error("error")
	Printf("printf")
	Println("print", "ln")
	Flush()
	CloseFile()
	t.Cleanup(func() { SetLevel("INFO") })

	data, err := os.ReadFile(path) // #nosec G304 -- test reads a path created under t.TempDir().
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range []string{"debug 1", "info", "warning", "error", "printf", "println"} {
		if !strings.Contains(string(data), message) {
			t.Errorf("log file missing %q: %q", message, data)
		}
	}
}
