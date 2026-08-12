package config

import (
	"path/filepath"
	"strings"
)

func isValidControllerURL(rawURL string) bool {
	return strings.HasPrefix(rawURL, "https://")
}

// FullDBPath returns the complete database path by joining HistoryDir and DBPath.
// If DBPath is an absolute path, it is returned as-is.
func (c *Config) FullDBPath() string {
	if filepath.IsAbs(c.DBPath) {
		return c.DBPath
	}
	return filepath.Join(c.HistoryDir, c.DBPath)
}

// FullConfigDir returns the persistent managed-configuration directory. The
// HistoryDir fallback preserves manually constructed Config values and older
// embedders that have not set ConfigDir yet.
func (c *Config) FullConfigDir() string {
	if c.ConfigDir != "" {
		return c.ConfigDir
	}
	return c.HistoryDir
}

// FullUpstreamsPath returns the complete upstreams file path.
func (c *Config) FullUpstreamsPath() string {
	if c.UpstreamsFile == "" {
		return ""
	}
	if filepath.IsAbs(c.UpstreamsFile) {
		return c.UpstreamsFile
	}
	return filepath.Join(c.FullConfigDir(), c.UpstreamsFile)
}

// FullDNSRoutesPath returns the complete DNS routes file path.
func (c *Config) FullDNSRoutesPath() string {
	if c.DNSRoutesFile == "" {
		return ""
	}
	if filepath.IsAbs(c.DNSRoutesFile) {
		return c.DNSRoutesFile
	}
	return filepath.Join(c.FullConfigDir(), c.DNSRoutesFile)
}

// FullRewritesPath returns the complete rewrites file path.
func (c *Config) FullRewritesPath() string {
	if c.RewritesFile == "" {
		return ""
	}
	if filepath.IsAbs(c.RewritesFile) {
		return c.RewritesFile
	}
	return filepath.Join(c.FullConfigDir(), c.RewritesFile)
}

// FullClientsPath returns the complete clients registry file path.
func (c *Config) FullClientsPath() string {
	if c.ClientsFile == "" {
		return ""
	}
	if filepath.IsAbs(c.ClientsFile) {
		return c.ClientsFile
	}
	return filepath.Join(c.FullConfigDir(), c.ClientsFile)
}

// FullBlocklistPath returns the complete blocklist file path.
func (c *Config) FullBlocklistPath() string {
	if c.BlocklistFile == "" {
		return ""
	}
	if filepath.IsAbs(c.BlocklistFile) {
		return c.BlocklistFile
	}
	return filepath.Join(c.FullConfigDir(), c.BlocklistFile)
}

// FullUserRulesPath returns the controller-managed custom rules path.
func (c *Config) FullUserRulesPath() string {
	return filepath.Join(c.FullConfigDir(), "user_rules.txt")
}

// FullFilterSubscriptionsPath returns the managed filter-subscription path.
func (c *Config) FullFilterSubscriptionsPath() string {
	return filepath.Join(c.FullConfigDir(), "filter-subscriptions.json")
}

// FullDNSSettingsPath returns the controller-managed live DNS policy path.
func (c *Config) FullDNSSettingsPath() string {
	return filepath.Join(c.FullConfigDir(), "dns-settings.json")
}

// FullMagicDNSStatePath returns the persisted last-good MagicDNS snapshot path.
func (c *Config) FullMagicDNSStatePath() string {
	if c.MagicDNSStateFile == "" {
		return ""
	}
	if filepath.IsAbs(c.MagicDNSStateFile) {
		return c.MagicDNSStateFile
	}
	return filepath.Join(c.FullConfigDir(), c.MagicDNSStateFile)
}

// FullTLSStateDir returns the generated TLS state directory. The history/tls
// fallback preserves manually constructed Config values and older embedders.
func (c *Config) FullTLSStateDir() string {
	if c.TLSStateDir != "" {
		return c.TLSStateDir
	}
	return filepath.Join(c.HistoryDir, "tls")
}

// FullControllerTLSPinPath returns the configured controller CA pin path.
func (c *Config) FullControllerTLSPinPath() string {
	if c.ControllerTLSPinFile == "" {
		return ""
	}
	if filepath.IsAbs(c.ControllerTLSPinFile) {
		return c.ControllerTLSPinFile
	}
	if c.TLSStateDir == "" {
		return filepath.Join(c.HistoryDir, c.ControllerTLSPinFile)
	}
	return filepath.Join(c.FullTLSStateDir(), c.ControllerTLSPinFile)
}
