package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const maxManagedConfigFileBytes = 512 * 1024 * 1024

// MigrateLegacyState copies controller-managed settings from HistoryDir into
// ConfigDir without removing the recovery copies. Existing destination files
// always win so startup can never replace newer configuration implicitly.
func MigrateLegacyState(cfg *Config) (int, error) {
	if cfg == nil {
		return 0, errors.New("config is nil")
	}
	if strings.TrimSpace(cfg.HistoryDir) == "" {
		return 0, errors.New("history directory is empty")
	}
	if err := ensureConfigDir(cfg.FullConfigDir()); err != nil {
		return 0, fmt.Errorf("prepare config directory: %w", err)
	}

	legacyDir, err := filepath.Abs(cfg.HistoryDir)
	if err != nil {
		return 0, fmt.Errorf("resolve legacy config directory: %w", err)
	}
	configDir, err := filepath.Abs(cfg.FullConfigDir())
	if err != nil {
		return 0, fmt.Errorf("resolve config directory: %w", err)
	}
	if filepath.Clean(legacyDir) == filepath.Clean(configDir) {
		return 0, nil
	}

	names, err := managedConfigFiles(cfg)
	if err != nil {
		return 0, err
	}
	migrated := 0
	for _, name := range names {
		copied, copyErr := copyLegacyConfigFile(
			filepath.Join(legacyDir, name),
			filepath.Join(configDir, name),
		)
		if copyErr != nil {
			return migrated, fmt.Errorf("migrate managed config %s: %w", name, copyErr)
		}
		if copied {
			migrated++
		}
	}
	return migrated, nil
}

func managedConfigFiles(cfg *Config) ([]string, error) {
	names := []string{"filter-subscriptions.json", "user_rules.txt"}
	seen := map[string]struct{}{
		"filter-subscriptions.json": {},
		"user_rules.txt":            {},
	}
	for _, configured := range []string{
		cfg.UpstreamsFile,
		cfg.DNSRoutesFile,
		cfg.RewritesFile,
		cfg.ClientsFile,
		cfg.BlocklistFile,
	} {
		configured = strings.TrimSpace(configured)
		if configured == "" || filepath.IsAbs(configured) {
			continue
		}
		name := filepath.Clean(configured)
		if !filepath.IsLocal(name) {
			return nil, fmt.Errorf("managed config path %q must be local or absolute", configured)
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names, nil
}

func ensureConfigDir(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("config directory is empty")
	}
	return os.MkdirAll(path, 0o750)
}

func copyLegacyConfigFile(source, destination string) (bool, error) {
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
	if sourceInfo.Size() > maxManagedConfigFileBytes {
		return false, fmt.Errorf("source exceeds %d bytes", maxManagedConfigFileBytes)
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

	sourceFile, err := os.Open(source) // #nosec G304 -- source is a validated local name below the administrator-controlled history directory.
	if err != nil {
		return false, err
	}
	defer func() { _ = sourceFile.Close() }()
	openedInfo, err := sourceFile.Stat()
	if err != nil {
		return false, err
	}
	if !sameConfigFileInfo(sourceInfo, openedInfo) {
		return false, errors.New("source changed while it was being opened")
	}

	if err := ensureConfigDir(filepath.Dir(destination)); err != nil {
		return false, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".resolix-config-*")
	if err != nil {
		return false, err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return false, err
	}
	written, err := io.Copy(temporary, io.LimitReader(sourceFile, maxManagedConfigFileBytes+1))
	if err != nil {
		return false, err
	}
	if written > maxManagedConfigFileBytes {
		return false, fmt.Errorf("source exceeds %d bytes", maxManagedConfigFileBytes)
	}
	finalInfo, err := sourceFile.Stat()
	if err != nil {
		return false, err
	}
	if !sameConfigFileInfo(sourceInfo, finalInfo) {
		return false, errors.New("source changed while it was being copied")
	}
	if err := temporary.Sync(); err != nil {
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Link(temporaryPath, destination); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func sameConfigFileInfo(before, after fs.FileInfo) bool {
	return os.SameFile(before, after) &&
		before.Name() == after.Name() &&
		before.Size() == after.Size() &&
		before.Mode() == after.Mode() &&
		before.ModTime().Equal(after.ModTime())
}
