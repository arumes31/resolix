package errors

import (
	stderrors "errors"
	"testing"
)

func TestStructuredErrors(t *testing.T) {
	cause := stderrors.New("root cause")
	tests := []struct {
		name string
		code string
		new  func(string, error) error
	}{
		{name: "database busy", code: "DATABASE_BUSY", new: func(message string, err error) error { return NewErrDatabaseBusy(message, err) }},
		{name: "invalid config", code: "INVALID_CONFIG", new: func(message string, err error) error { return NewErrInvalidConfig(message, err) }},
		{name: "parse failed", code: "PARSE_FAILED", new: func(message string, err error) error { return NewErrParseFailed(message, err) }},
		{name: "forward failed", code: "FORWARD_FAILED", new: func(message string, err error) error { return NewErrForwardFailed(message, err) }},
		{name: "auth failed", code: "AUTH_FAILED", new: func(message string, err error) error { return NewErrAuthFailed(message, err) }},
		{name: "rate limited", code: "RATE_LIMITED", new: func(message string, err error) error { return NewErrRateLimited(message, err) }},
		{name: "csrf mismatch", code: "CSRF_MISMATCH", new: func(message string, err error) error { return NewErrCSRFMismatch(message, err) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withCause := test.new("operation failed", cause)
			if got := withCause.Error(); got != test.code+": operation failed: root cause" {
				t.Fatalf("Error() = %q", got)
			}
			if !stderrors.Is(withCause, cause) {
				t.Fatal("wrapped cause is not discoverable with errors.Is")
			}

			withoutCause := test.new("operation failed", nil)
			if got := withoutCause.Error(); got != test.code+": operation failed" {
				t.Fatalf("Error() without cause = %q", got)
			}
			if stderrors.Unwrap(withoutCause) != nil {
				t.Fatal("nil cause unexpectedly unwraps to an error")
			}
		})
	}
}
