package controllertls

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	pinVersion   = 1
	maxPinBytes  = 4096
	defaultHTTPS = "443"
)

type pinRecord struct {
	Version      int    `json:"version"`
	Origin       string `json:"origin"`
	CASPKISHA256 string `json:"ca_spki_sha256"`
}

type tofuVerifier struct {
	mu          sync.Mutex
	origin      string
	serverIP    string
	pinPath     string
	pin         [sha256.Size]byte
	hasPin      bool
	currentTime func() time.Time
}

// ValidateTOFUControllerURL requires HTTPS to an exact Tailscale IPv4 address.
func ValidateTOFUControllerURL(rawURL string) error {
	_, _, err := tofuOrigin(rawURL)
	return err
}

// NewTOFUTransport creates an HTTP transport that pins the first valid CA seen
// over a direct Tailscale IPv4 path and rejects every later mismatch.
func NewTOFUTransport(controllerURL, pinPath string) (*http.Transport, error) {
	if pinPath == "" {
		return nil, errors.New("controller TLS pin file is required")
	}
	origin, serverIP, err := tofuOrigin(controllerURL)
	if err != nil {
		return nil, err
	}
	verifier := &tofuVerifier{
		origin:      origin,
		serverIP:    serverIP,
		pinPath:     pinPath,
		currentTime: time.Now,
	}
	if err := verifier.loadPin(); err != nil {
		return nil, fmt.Errorf("load controller CA pin: %w", err)
	}

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("default HTTP transport has an unexpected type")
	}
	transport := base.Clone()
	// A TOFU enrollment must reach the tailnet peer directly. Inheriting an
	// HTTPS_PROXY setting would move the first-use trust boundary to that proxy.
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverIP,
		// #nosec G402 -- normal verification is deliberately replaced by
		// VerifyConnection, which validates the full chain, IP SAN, validity,
		// server-auth usage, and the persisted CA SPKI pin.
		InsecureSkipVerify: true,
		VerifyConnection:   verifier.verifyConnection,
	}
	return transport, nil
}

func tofuOrigin(rawURL string) (string, string, error) {
	controller, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return "", "", fmt.Errorf("parse controller URL for TOFU: %w", err)
	}
	if !strings.EqualFold(controller.Scheme, "https") || controller.Host == "" {
		return "", "", errors.New("TOFU controller URL must use HTTPS")
	}
	if controller.User != nil || controller.RawQuery != "" || controller.Fragment != "" {
		return "", "", errors.New("TOFU controller URL must not contain credentials, a query, or a fragment")
	}
	addr, err := ParseTailnetIPv4(controller.Hostname())
	if err != nil {
		return "", "", fmt.Errorf("validate TOFU controller address: %w", err)
	}
	port := controller.Port()
	if port == "" {
		port = defaultHTTPS
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", "", errors.New("TOFU controller URL has an invalid port")
	}
	return "https://" + net.JoinHostPort(addr.String(), port), addr.String(), nil
}

func (v *tofuVerifier) verifyConnection(state tls.ConnectionState) error {
	if state.Version < tls.VersionTLS13 {
		return errors.New("controller requires TLS 1.3 or newer")
	}
	if len(state.PeerCertificates) < 2 {
		return errors.New("controller did not present a leaf and CA certificate")
	}
	leaf := state.PeerCertificates[0]
	root := state.PeerCertificates[len(state.PeerCertificates)-1]
	if leaf.IsCA {
		return errors.New("controller leaf certificate is a CA")
	}
	if !root.IsCA || root.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("controller trust anchor is not a certificate authority")
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("verify self-signed controller CA: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1 : len(state.PeerCertificates)-1] {
		intermediates.AddCert(certificate)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       v.serverIP,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   v.currentTime(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("verify controller certificate: %w", err)
	}

	digest := sha256.Sum256(root.RawSubjectPublicKeyInfo)
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.hasPin {
		if subtle.ConstantTimeCompare(v.pin[:], digest[:]) != 1 {
			return errors.New("controller CA pin mismatch; refusing automatic replacement")
		}
		return nil
	}
	if err := v.persistPin(digest); err != nil {
		return fmt.Errorf("persist first controller CA pin: %w", err)
	}
	v.pin = digest
	v.hasPin = true
	return nil
}

func (v *tofuVerifier) loadPin() error {
	record, err := readPin(v.pinPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if record.Version != pinVersion {
		return fmt.Errorf("unsupported pin version %d", record.Version)
	}
	if record.Origin != v.origin {
		return fmt.Errorf("pin belongs to %q, not %q", record.Origin, v.origin)
	}
	digest, err := hex.DecodeString(record.CASPKISHA256)
	if err != nil || len(digest) != sha256.Size {
		return errors.New("controller CA pin fingerprint is invalid")
	}
	copy(v.pin[:], digest)
	v.hasPin = true
	return os.Chmod(v.pinPath, 0o600)
}

func (v *tofuVerifier) persistPin(digest [sha256.Size]byte) error {
	record := pinRecord{
		Version:      pinVersion,
		Origin:       v.origin,
		CASPKISHA256: hex.EncodeToString(digest[:]),
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encode controller CA pin: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(v.pinPath), 0o700); err != nil {
		return err
	}
	if err := writeNewFile(v.pinPath, data); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrExist) {
		return err
	}

	recordOnDisk, err := readPin(v.pinPath)
	if err != nil {
		return err
	}
	if recordOnDisk.Version != record.Version || recordOnDisk.Origin != record.Origin ||
		recordOnDisk.CASPKISHA256 != record.CASPKISHA256 {
		return errors.New("a different controller CA pin was created concurrently")
	}
	return nil
}

func readPin(path string) (pinRecord, error) {
	file, err := os.Open(path) // #nosec G304 -- path is an administrator-controlled configuration value.
	if err != nil {
		return pinRecord{}, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxPinBytes+1))
	if err != nil {
		return pinRecord{}, err
	}
	if len(data) > maxPinBytes {
		return pinRecord{}, errors.New("controller CA pin file is too large")
	}
	var record pinRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return pinRecord{}, fmt.Errorf("decode controller CA pin: %w", err)
	}
	return record, nil
}
