//go:build !windows

package api

import (
	"os"
	"syscall"
)

// sendCacheClearSignal sends SIGUSR1 to the process with the given PID to clear its DNS cache.
func sendCacheClearSignal(proc *os.Process) error {
	return proc.Signal(syscall.SIGUSR1)
}
