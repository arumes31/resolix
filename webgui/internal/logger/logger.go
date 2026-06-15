// Package logger provides a level-aware logging facility with support for
// optional file-based output using buffered writers. Log levels (DEBUG,
// INFO, WARNING, ERROR) are enforced atomically for thread safety.
// When a LOG_FILE environment variable is set, logs are written to both
// stderr and the specified file using a buffered writer for performance.
package logger

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// Level represents a logging severity level.
type Level int32

const (
	// LevelDebug is the most verbose level, including function entry/exit and data flow details.
	LevelDebug Level = iota
	// LevelInfo is for normal operational messages (startup, shutdown, connections).
	LevelInfo
	// LevelWarning is for recoverable issues (rate limits, retry attempts, slow queries).
	LevelWarning
	// LevelError is for failures that affect functionality.
	LevelError
)

var (
	// currentLevel is the active log level, accessed atomically for thread safety.
	currentLevel atomic.Int32
	// stdLogger is the standard library logger used for stderr output.
	stdLogger = log.New(os.Stderr, "", log.LstdFlags)
	// fileWriter holds the buffered file writer if file logging is enabled.
	fileWriter *bufio.Writer
	// fileLogger is the standard library logger used for file output.
	fileLogger *log.Logger
	// fileMu protects file writer flush operations.
	fileMu sync.Mutex
	// fileCloser holds the underlying file so we can close it on shutdown.
	fileCloser io.Closer
)

// SetLevel updates the current log level from a string representation.
// Valid values (case-insensitive): DEBUG, INFO, WARNING, ERROR.
// Defaults to INFO for unrecognized values.
func SetLevel(levelStr string) {
	l := parseLevel(levelStr)
	currentLevel.Store(int32(l))
}

// GetLevel returns the current log level.
func GetLevel() Level {
	return Level(currentLevel.Load())
}

// parseLevel converts a string to a Level, defaulting to INFO.
func parseLevel(levelStr string) Level {
	switch strings.ToUpper(strings.TrimSpace(levelStr)) {
	case "DEBUG":
		return LevelDebug
	case "INFO":
		return LevelInfo
	case "WARNING", "WARN":
		return LevelWarning
	case "ERROR":
		return LevelError
	default:
		return LevelInfo
	}
}

// EnableFileLogging opens the specified file for appending and creates a
// buffered writer (8KB buffer) for file-based log output. All subsequent
// log messages are written to both stderr and the file.
func EnableFileLogging(path string) error {
	fileMu.Lock()
	defer fileMu.Unlock()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file %s: %w", path, err)
	}

	fileWriter = bufio.NewWriterSize(f, 8192) // 8KB buffer
	fileLogger = log.New(fileWriter, "", log.LstdFlags)
	fileCloser = f

	log.Printf("[INFO] File logging enabled: %s", path)
	return nil
}

// Flush forces any buffered log data to be written to the log file.
// This should be called periodically or on application shutdown.
func Flush() {
	fileMu.Lock()
	defer fileMu.Unlock()

	if fileWriter != nil {
		_ = fileWriter.Flush()
	}
}

// CloseFile flushes and closes the log file, releasing all resources.
// After calling CloseFile, file logging is disabled.
func CloseFile() {
	fileMu.Lock()
	defer fileMu.Unlock()

	if fileWriter != nil {
		_ = fileWriter.Flush()
		fileWriter = nil
	}
	if fileCloser != nil {
		_ = fileCloser.Close()
		fileCloser = nil
	}
	fileLogger = nil
}

// writeLog writes a formatted message to both stderr and the file (if enabled).
func writeLog(prefix, format string, args ...interface{}) {
	msg := fmt.Sprintf(prefix+format, args...)
	stdLogger.Print(msg)

	fileMu.Lock()
	defer fileMu.Unlock()
	if fileLogger != nil {
		fileLogger.Print(msg)
	}
}

// Debug logs a message at DEBUG level.
// Verbose output including function entry/exit, data flow details.
func Debug(format string, args ...interface{}) {
	if Level(currentLevel.Load()) <= LevelDebug {
		writeLog("[DEBUG] ", format, args...)
	}
}

// Info logs a message at INFO level.
// Normal operational messages (startup, shutdown, connections).
func Info(format string, args ...interface{}) {
	if Level(currentLevel.Load()) <= LevelInfo {
		writeLog("[INFO] ", format, args...)
	}
}

// Warning logs a message at WARNING level.
// Recoverable issues (rate limits, retry attempts, slow queries).
func Warning(format string, args ...interface{}) {
	if Level(currentLevel.Load()) <= LevelWarning {
		writeLog("[WARN] ", format, args...)
	}
}

// Warn is an alias for Warning.
func Warn(format string, args ...interface{}) {
	Warning(format, args...)
}

// Error logs a message at ERROR level.
// Failures that affect functionality.
func Error(format string, args ...interface{}) {
	if Level(currentLevel.Load()) <= LevelError {
		writeLog("[ERROR] ", format, args...)
	}
}

// Fatal logs a message at FATAL level and exits with code 1.
func Fatal(format string, args ...interface{}) {
	msg := fmt.Sprintf("[FATAL] "+format, args...)

	fileMu.Lock()
	if fileLogger != nil {
		fileLogger.Print(msg)
		_ = fileWriter.Flush()
	}
	fileMu.Unlock()

	stdLogger.Fatal(msg)
}

// Fatalf is an alias for Fatal.
func Fatalf(format string, args ...interface{}) {
	Fatal(format, args...)
}

// Printf provides a compatibility shim for code using log.Printf.
// It logs at INFO level.
func Printf(format string, args ...interface{}) {
	Info(format, args...)
}

// Println provides a compatibility shim for code using log.Println.
// It logs at INFO level.
func Println(args ...interface{}) {
	Info(fmt.Sprint(args...))
}
