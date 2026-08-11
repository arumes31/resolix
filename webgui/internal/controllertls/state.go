package controllertls

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const maxStateFileBytes = 1024 * 1024

var managedStateFiles = [...]string{caFileName, DefaultPinFile}

// MigrateLegacyState copies generated TLS state out of the legacy history/tls
// directory without deleting the recovery copy. Existing destination files
// always win so an established CA or pin can never be replaced implicitly.
func MigrateLegacyState(legacyDir, stateDir string) (int, error) {
	if err := secureStateDir(stateDir); err != nil {
		return 0, fmt.Errorf("secure TLS state directory: %w", err)
	}
	legacyPath, err := filepath.Abs(legacyDir)
	if err != nil {
		return 0, fmt.Errorf("resolve legacy TLS state directory: %w", err)
	}
	statePath, err := filepath.Abs(stateDir)
	if err != nil {
		return 0, fmt.Errorf("resolve TLS state directory: %w", err)
	}
	if filepath.Clean(legacyPath) == filepath.Clean(statePath) {
		return 0, nil
	}

	migrated := 0
	for _, name := range managedStateFiles {
		copied, copyErr := copyLegacyStateFile(
			filepath.Join(legacyPath, name),
			filepath.Join(statePath, name),
		)
		if copyErr != nil {
			return migrated, fmt.Errorf("migrate legacy TLS state %s: %w", name, copyErr)
		}
		if copied {
			migrated++
		}
	}
	return migrated, nil
}

func secureStateDir(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("TLS state directory is empty")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return os.Chmod(path, 0o700) // #nosec G302 -- a private directory requires owner execute permission for traversal.
}

func copyLegacyStateFile(source, destination string) (bool, error) {
	sourceInfo, err := os.Lstat(source)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !sourceInfo.Mode().IsRegular() {
		return false, errors.New("source is not a regular file")
	}
	if sourceInfo.Size() > maxStateFileBytes {
		return false, fmt.Errorf("source exceeds %d bytes", maxStateFileBytes)
	}

	destinationInfo, err := os.Lstat(destination)
	if err == nil {
		if !destinationInfo.Mode().IsRegular() {
			return false, errors.New("destination is not a regular file")
		}
		return false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}

	data, err := os.ReadFile(source) // #nosec G304 -- both paths use fixed filenames below administrator-controlled state directories.
	if err != nil {
		return false, err
	}
	if err := secureStateDir(filepath.Dir(destination)); err != nil {
		return false, err
	}
	if err := writeNewFile(destination, data); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
