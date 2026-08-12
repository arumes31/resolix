package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/arumes31/resolix/webgui/internal/controllertls"
)

// VerifyConfig checks critical configuration values before the server starts.
// It returns critical failures separately from startup warnings.
//
//nolint:gocyclo // Each independent validation is retained so all startup errors can be reported together.
func (c *Config) VerifyConfig() ([]string, []string) {
	var errs []string
	var warnings []string

	// 1. Database path is writable
	dbDir := filepath.Dir(c.FullDBPath())
	if err := os.MkdirAll(dbDir, 0750); err != nil {
		errs = append(errs, fmt.Sprintf("Cannot create database directory %s: %v", dbDir, err))
	} else {
		// CreateTemp picks a random name inside the trusted config directory,
		// avoiding a predictable-path write (gosec G304).
		if f, err := os.CreateTemp(dbDir, ".write_test*"); err != nil {
			errs = append(errs, fmt.Sprintf("Database directory %s is not writable: %v", dbDir, err))
		} else {
			testFile := f.Name()
			_ = f.Close()
			_ = os.Remove(testFile)
		}
	}

	// 2. CONTROLLER_URL schema validation (if set)
	if c.ControllerURL != "" && !isValidControllerURL(c.ControllerURL) {
		errs = append(errs, fmt.Sprintf("CONTROLLER_URL must start with https:// (got: %s)", c.ControllerURL))
	}
	switch c.WebTLSMode {
	case "", controllertls.WebTLSOff:
	case controllertls.WebTLSAuto:
		if c.Mode != "" && c.Mode != ModeController {
			errs = append(errs, "WEB_TLS_MODE=auto is supported only in controller mode")
		}
		if _, err := controllertls.ParseTailnetIPv4(c.WebTLSIP); err != nil {
			errs = append(errs, "WEB_TLS_MODE=auto requires WEB_TLS_IP or TAILSCALE_IP in 100.64.0.0/10")
		}
	default:
		errs = append(errs, "WEB_TLS_MODE must be off or auto")
	}
	switch c.ControllerTLSTrust {
	case "", controllertls.TrustSystem:
	case controllertls.TrustTOFUTailnet:
		if c.Mode != ModeAgent {
			errs = append(errs, "CONTROLLER_TLS_TRUST=tofu-tailnet is supported only in agent mode")
		}
		if err := controllertls.ValidateTOFUControllerURL(c.ControllerURL); err != nil {
			errs = append(errs, "CONTROLLER_TLS_TRUST=tofu-tailnet requires CONTROLLER_URL to use a 100.64.0.0/10 address")
		}
		if c.FullControllerTLSPinPath() == "" {
			errs = append(errs, "CONTROLLER_TLS_PIN_FILE is required for tofu-tailnet trust")
		}
	default:
		errs = append(errs, "CONTROLLER_TLS_TRUST must be system or tofu-tailnet")
	}

	// 3. Authentication must be either fully configured or explicitly backed
	// by an ingest secret. Internal endpoints must never silently fail open.
	if (c.WebUsername == "") != (c.WebPassword == "") {
		errs = append(errs, "WEB_USERNAME and WEB_PASSWORD must be configured together")
	}
	if c.WebUsername == "" && c.WebPassword == "" && c.IngestSecret == "" {
		errs = append(errs, "configure WEB_USERNAME/WEB_PASSWORD or INGEST_SECRET; internal endpoints may not run without authentication")
	}
	if c.Mode == ModeAgent && strings.TrimSpace(c.IngestSecret) == "" {
		errs = append(errs, "INGEST_SECRET is required in agent mode for authenticated controller communication")
	}

	// 4. Port number validation
	if p, err := strconv.Atoi(c.Port); err != nil || p < 1 || p > 65535 {
		errs = append(errs, fmt.Sprintf("Invalid PORT '%s' — must be a number between 1 and 65535", c.Port))
	}
	if strings.ContainsAny(c.WebListenAddr, "\r\n\x00") {
		errs = append(errs, "WEB_LISTEN_ADDR contains invalid characters")
	}

	// 4b. DNSMASQ_PID_FILE deprecation notice (non-critical warning)
	if os.Getenv("DNSMASQ_PID_FILE") != "" {
		warnings = append(warnings, "DNSMASQ_PID_FILE is deprecated and ignored: cache clearing is handled by the in-process DNS server")
	}

	// 4c. DoT requires TLS certificates (critical failure)
	if c.DoTEnabled && (c.TLSCertFile == "" || c.TLSKeyFile == "") {
		errs = append(errs, "DOT_ENABLED requires TLS_CERT_FILE and TLS_KEY_FILE")
	}
	if c.DoTEnabled && (c.DoTPort < 1 || c.DoTPort > 65535) {
		errs = append(errs, "DOT_PORT must be between 1 and 65535")
	}
	if c.DoHEnabled && !validDoHPath(c.DoHPath) {
		errs = append(errs, "DOH_PATH must be a non-conflicting literal HTTP path")
	}

	for _, setting := range []struct {
		name string
		raw  string
	}{
		{name: "DNS_ALLOWED_CLIENTS", raw: c.DNSAllowedClients},
		{name: "DNS_DISALLOWED_CLIENTS", raw: c.DNSDisallowedClients},
	} {
		for _, value := range splitConfigList(setting.raw) {
			if !validIPOrCIDR(value) {
				errs = append(errs, fmt.Sprintf("%s contains an invalid IP or CIDR", setting.name))
				break
			}
		}
	}

	if c.DNS64 {
		for _, value := range splitConfigList(c.DNS64Prefixes) {
			ip, network, err := net.ParseCIDR(value)
			ones, bits := 0, 0
			if err == nil {
				ones, bits = network.Mask.Size()
			}
			if err != nil || ip.To4() != nil || bits != 128 || ones != 96 {
				errs = append(errs, "DNS64_PREFIXES must contain only IPv6 /96 prefixes")
				break
			}
		}
	}

	for _, setting := range []struct {
		name string
		raw  string
	}{
		{name: "BLOCKLIST_URLS", raw: c.BlocklistURLs},
		{name: "ALLOWLIST_URLS", raw: c.AllowlistURLs},
	} {
		for _, value := range splitConfigList(setting.raw) {
			u, err := url.Parse(value)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
				errs = append(errs, fmt.Sprintf("%s contains an invalid URL (only http/https without embedded credentials is allowed)", setting.name))
				break
			}
		}
	}

	// 5. Client aliases file check (non-critical warning)
	if c.ClientAliasesFile != "" {
		if _, err := os.Stat(c.ClientAliasesFile); os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("CLIENT_ALIASES_FILE '%s' does not exist (will be watched for creation)", c.ClientAliasesFile))
		}
	}

	// 6. Blocklist file check (non-critical warning)
	if c.BlocklistFile != "" {
		if _, err := os.Stat(c.FullBlocklistPath()); os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("BLOCKLIST_FILE '%s' does not exist (will be watched for creation)", c.FullBlocklistPath()))
		}
	}

	// 7. DNS routes file check (non-critical warning)
	if c.DNSRoutesFile != "" {
		if _, err := os.Stat(c.FullDNSRoutesPath()); os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("DNS_ROUTES_FILE '%s' does not exist (will be created on first save)", c.FullDNSRoutesPath()))
		}
	}

	return errs, warnings
}

func splitConfigList(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}

func validIPOrCIDR(value string) bool {
	if net.ParseIP(value) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(value)
	return err == nil
}
