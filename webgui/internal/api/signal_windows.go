package api

import (
	"errors"
	"os"
)

// sendCacheClearSignal is not supported on Windows.
func sendCacheClearSignal(_ *os.Process) error {
	return errors.New("SIGUSR1 is not supported on Windows")
}
