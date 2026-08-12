//go:build !windows

package forwarder

import "os"

func replaceBacklogFile(source, destination string) error {
	return os.Rename(source, destination)
}
