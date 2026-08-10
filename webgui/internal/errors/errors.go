// Package errors defines custom structured error types used throughout the
// Resolix application. Each error type carries a machine-readable
// code, a human-readable message, and an optional wrapped underlying error.
package errors

// AppError is the base type for all custom application errors.
// It implements the error interface and provides structured error information.
type AppError struct {
	// Code is a machine-readable error code (e.g., "DATABASE_BUSY").
	Code string
	// Message is a human-readable error description.
	Message string
	// Err is the wrapped underlying error, if any.
	Err error
}

// Error returns the error message, including the code and any wrapped error.
func (e *AppError) Error() string {
	if e.Err != nil {
		return e.Code + ": " + e.Message + ": " + e.Err.Error()
	}
	return e.Code + ": " + e.Message
}

// Unwrap returns the wrapped underlying error, supporting errors.Is/As.
func (e *AppError) Unwrap() error {
	return e.Err
}

// ErrDatabaseBusy indicates the database is locked or busy.
type ErrDatabaseBusy struct{ AppError }

// NewErrDatabaseBusy creates a new ErrDatabaseBusy error.
func NewErrDatabaseBusy(msg string, err error) *ErrDatabaseBusy {
	return &ErrDatabaseBusy{AppError{
		Code:    "DATABASE_BUSY",
		Message: msg,
		Err:     err,
	}}
}

// ErrInvalidConfig indicates a configuration validation failure.
type ErrInvalidConfig struct{ AppError }

// NewErrInvalidConfig creates a new ErrInvalidConfig error.
func NewErrInvalidConfig(msg string, err error) *ErrInvalidConfig {
	return &ErrInvalidConfig{AppError{
		Code:    "INVALID_CONFIG",
		Message: msg,
		Err:     err,
	}}
}

// ErrParseFailed indicates a log line parsing failure.
type ErrParseFailed struct{ AppError }

// NewErrParseFailed creates a new ErrParseFailed error.
func NewErrParseFailed(msg string, err error) *ErrParseFailed {
	return &ErrParseFailed{AppError{
		Code:    "PARSE_FAILED",
		Message: msg,
		Err:     err,
	}}
}

// ErrForwardFailed indicates a log forwarding failure.
type ErrForwardFailed struct{ AppError }

// NewErrForwardFailed creates a new ErrForwardFailed error.
func NewErrForwardFailed(msg string, err error) *ErrForwardFailed {
	return &ErrForwardFailed{AppError{
		Code:    "FORWARD_FAILED",
		Message: msg,
		Err:     err,
	}}
}

// ErrAuthFailed indicates an authentication failure.
type ErrAuthFailed struct{ AppError }

// NewErrAuthFailed creates a new ErrAuthFailed error.
func NewErrAuthFailed(msg string, err error) *ErrAuthFailed {
	return &ErrAuthFailed{AppError{
		Code:    "AUTH_FAILED",
		Message: msg,
		Err:     err,
	}}
}

// ErrRateLimited indicates a rate limit was exceeded.
type ErrRateLimited struct{ AppError }

// NewErrRateLimited creates a new ErrRateLimited error.
func NewErrRateLimited(msg string, err error) *ErrRateLimited {
	return &ErrRateLimited{AppError{
		Code:    "RATE_LIMITED",
		Message: msg,
		Err:     err,
	}}
}

// ErrCSRFMismatch indicates a CSRF token mismatch.
type ErrCSRFMismatch struct{ AppError }

// NewErrCSRFMismatch creates a new ErrCSRFMismatch error.
func NewErrCSRFMismatch(msg string, err error) *ErrCSRFMismatch {
	return &ErrCSRFMismatch{AppError{
		Code:    "CSRF_MISMATCH",
		Message: msg,
		Err:     err,
	}}
}
