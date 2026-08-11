// Package controllertls manages the private certificate authority used for
// direct controller-to-agent HTTPS inside a Tailscale network.
package controllertls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// WebTLSOff leaves the web listener on HTTP for an external reverse proxy.
	WebTLSOff = "off"
	// WebTLSAuto serves HTTPS with an automatically managed private CA.
	WebTLSAuto = "auto"

	// TrustSystem validates the controller with the operating system trust store.
	TrustSystem = "system"
	// TrustTOFUTailnet pins the first CA seen over a direct Tailscale IPv4 path.
	TrustTOFUTailnet = "tofu-tailnet"

	// DefaultPinFile is the agent-side controller CA pin file.
	DefaultPinFile = "controller-ca-pin.json"

	caFileName    = "controller-ca.pem"
	rotationLead  = 30 * 24 * time.Hour
	rotationCheck = 24 * time.Hour
	clockSkew     = 5 * time.Minute
)

var tailnetIPv4Prefix = netip.MustParsePrefix("100.64.0.0/10")

// Manager owns the persistent controller CA and the current in-memory leaf
// certificate. Persisting only the CA lets leaf keys rotate without additional
// disk writes or agent re-enrollment.
type Manager struct {
	mu        sync.RWMutex
	tailnetIP netip.Addr
	caCert    *x509.Certificate
	caKey     *rsa.PrivateKey
	leaf      tls.Certificate
	leafCert  *x509.Certificate
}

// NewManager loads or creates the controller CA and issues the first leaf.
func NewManager(tlsStateDir, rawTailnetIP string) (*Manager, error) {
	tailnetIP, err := ParseTailnetIPv4(rawTailnetIP)
	if err != nil {
		return nil, err
	}
	if err := secureStateDir(tlsStateDir); err != nil {
		return nil, fmt.Errorf("create controller TLS directory: %w", err)
	}

	caPath := filepath.Join(tlsStateDir, caFileName)
	caCert, caKey, err := loadOrCreateCA(caPath, time.Now())
	if err != nil {
		return nil, fmt.Errorf("load controller CA: %w", err)
	}

	manager := &Manager{
		tailnetIP: tailnetIP,
		caCert:    caCert,
		caKey:     caKey,
	}
	if _, err := manager.rotateIfNeeded(time.Now()); err != nil {
		return nil, fmt.Errorf("issue controller certificate: %w", err)
	}
	return manager, nil
}

// ParseTailnetIPv4 validates a direct Tailscale CGNAT address.
func ParseTailnetIPv4(raw string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse Tailscale IPv4 address: %w", err)
	}
	addr = addr.Unmap()
	if !addr.Is4() || !tailnetIPv4Prefix.Contains(addr) {
		return netip.Addr{}, fmt.Errorf("address %q is outside Tailscale IPv4 range %s", raw, tailnetIPv4Prefix)
	}
	return addr, nil
}

// TLSConfig returns a server configuration that always serves the current leaf.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			m.mu.RLock()
			certificate := m.leaf
			m.mu.RUnlock()
			if len(certificate.Certificate) == 0 {
				return nil, errors.New("controller TLS certificate is unavailable")
			}
			return &certificate, nil
		},
	}
}

// CAFingerprint returns the SHA-256 fingerprint of the CA public key.
func (m *Manager) CAFingerprint() string {
	digest := sha256.Sum256(m.caCert.RawSubjectPublicKeyInfo)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// Run rotates the in-memory server certificate before it expires. Rotation
// errors are reported and retried on the next interval.
func (m *Manager) Run(ctx context.Context, report func(error)) {
	ticker := time.NewTicker(rotationCheck)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if _, err := m.rotateIfNeeded(now); err != nil && report != nil {
				report(err)
			}
		}
	}
}

func (m *Manager) rotateIfNeeded(now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.leafCert != nil && m.leafCert.NotAfter.After(now.Add(rotationLead)) {
		return false, nil
	}

	leaf, parsed, err := issueServerCertificate(m.caCert, m.caKey, m.tailnetIP, now)
	if err != nil {
		return false, err
	}
	m.leaf = leaf
	m.leafCert = parsed
	return true, nil
}

func loadOrCreateCA(path string, now time.Time) (*x509.Certificate, *rsa.PrivateKey, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is derived from the trusted TLS_STATE_DIR and a constant filename.
	if err == nil {
		if chmodErr := os.Chmod(path, 0o600); chmodErr != nil {
			return nil, nil, fmt.Errorf("secure controller CA file: %w", chmodErr)
		}
		return parseCA(data, now)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, err
	}

	certificate, privateKey, encoded, err := createCA(now)
	if err != nil {
		return nil, nil, err
	}
	if err := writeNewFile(path, encoded); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return nil, nil, fmt.Errorf("persist controller CA: %w", err)
		}
		data, readErr := os.ReadFile(path) // #nosec G304 -- same trusted CA path after a concurrent create.
		if readErr != nil {
			return nil, nil, fmt.Errorf("read concurrently created controller CA: %w", readErr)
		}
		return parseCA(data, now)
	}
	return certificate, privateKey, nil
}

func createCA(now time.Time) (*x509.Certificate, *rsa.PrivateKey, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate controller CA key: %w", err)
	}
	publicKey := &privateKey.PublicKey
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal controller CA public key: %w", err)
	}
	subjectKeyID := sha256.Sum256(publicKeyDER)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Resolix Controller CA", Organization: []string{"Resolix"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.AddDate(100, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          subjectKeyID[:],
		AuthorityKeyId:        subjectKeyID[:],
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create controller CA certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse generated controller CA: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal controller CA key: %w", err)
	}
	encoded := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})...,
	)
	return certificate, privateKey, encoded, nil
}

func parseCA(data []byte, now time.Time) (*x509.Certificate, *rsa.PrivateKey, error) {
	certificateBlock, remainder := pem.Decode(data)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" {
		return nil, nil, errors.New("controller CA certificate PEM is missing")
	}
	privateKeyBlock, trailing := pem.Decode(remainder)
	if privateKeyBlock == nil || privateKeyBlock.Type != "PRIVATE KEY" || len(trailing) != 0 {
		return nil, nil, errors.New("controller CA private key PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse controller CA certificate: %w", err)
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse controller CA private key: %w", err)
	}
	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("controller CA key is not RSA")
	}
	if err := privateKey.Validate(); err != nil {
		return nil, nil, fmt.Errorf("validate controller CA private key: %w", err)
	}
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || !publicKey.Equal(privateKey.Public()) {
		return nil, nil, errors.New("controller CA certificate and key do not match")
	}
	if !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, errors.New("controller CA certificate cannot sign certificates")
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		return nil, nil, fmt.Errorf("verify self-signed controller CA: %w", err)
	}
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return nil, nil, errors.New("controller CA certificate is not currently valid")
	}
	return certificate, privateKey, nil
}

func issueServerCertificate(
	caCert *x509.Certificate,
	caKey *rsa.PrivateKey,
	tailnetIP netip.Addr,
	now time.Time,
) (tls.Certificate, *x509.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("generate controller server key: %w", err)
	}
	publicKey := &privateKey.PublicKey
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	notAfter := now.AddDate(1, 0, 0)
	if caCert.NotAfter.Before(notAfter) {
		notAfter = caCert.NotAfter
	}
	if !notAfter.After(now.Add(rotationLead)) {
		return tls.Certificate{}, nil, errors.New("controller CA expires too soon to issue a server certificate")
	}
	template := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        pkix.Name{CommonName: "Resolix Controller", Organization: []string{"Resolix"}},
		NotBefore:      now.Add(-clockSkew),
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:    []net.IP{net.IP(tailnetIP.AsSlice())},
		AuthorityKeyId: caCert.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, publicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("create controller server certificate: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("parse generated controller server certificate: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der, caCert.Raw},
		PrivateKey:  privateKey,
		Leaf:        parsed,
	}, parsed, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	return serial, nil
}

func writeNewFile(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".resolix-tls-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return err
	}
	return nil
}
