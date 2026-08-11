package controllertls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestNewManagerPersistsCAAndRotatesLeaf(t *testing.T) {
	tlsStateDir := t.TempDir()
	manager, err := NewManager(tlsStateDir, "100.64.12.34")
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	caPath := filepath.Join(tlsStateDir, caFileName)
	info, err := os.Stat(caPath)
	if err != nil {
		t.Fatalf("stat generated CA: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("CA permissions = %o, want 600", info.Mode().Perm())
	}

	first := currentCertificate(t, manager)
	leaf := first.Leaf
	if err := leaf.VerifyHostname("100.64.12.34"); err != nil {
		t.Fatalf("leaf IP SAN verification failed: %v", err)
	}
	if lifetime := leaf.NotAfter.Sub(leaf.NotBefore); lifetime < 364*24*time.Hour || lifetime > 367*24*time.Hour {
		t.Fatalf("leaf lifetime = %s, want about one year", lifetime)
	}
	ca, err := x509.ParseCertificate(first.Certificate[1])
	if err != nil {
		t.Fatalf("parse generated CA: %v", err)
	}
	if ca.NotAfter.Before(time.Now().AddDate(99, 11, 0)) {
		t.Fatalf("CA expires too early: %s", ca.NotAfter)
	}

	reloaded, err := NewManager(tlsStateDir, "100.64.12.34")
	if err != nil {
		t.Fatalf("reload NewManager() error = %v", err)
	}
	if manager.CAFingerprint() != reloaded.CAFingerprint() {
		t.Fatal("reloaded manager did not retain the controller CA")
	}
	second := currentCertificate(t, reloaded)
	if bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("server leaf was persisted instead of being reissued")
	}

	originalSerial := second.Leaf.SerialNumber.String()
	rotationTime := second.Leaf.NotAfter.Add(-rotationLead + time.Second)
	rotated, err := reloaded.rotateIfNeeded(rotationTime)
	if err != nil {
		t.Fatalf("rotateIfNeeded() error = %v", err)
	}
	if !rotated {
		t.Fatal("rotateIfNeeded() did not rotate inside the renewal window")
	}
	if currentCertificate(t, reloaded).Leaf.SerialNumber.String() == originalSerial {
		t.Fatal("rotated leaf retained the previous serial number")
	}
}

func TestParseTailnetIPv4(t *testing.T) {
	tests := []struct {
		name    string
		address string
		wantErr bool
	}{
		{name: "lower boundary", address: "100.64.0.0"},
		{name: "upper boundary", address: "100.127.255.255"},
		{name: "public IPv4", address: "203.0.113.10", wantErr: true},
		{name: "private IPv4", address: "192.168.1.10", wantErr: true},
		{name: "Tailscale IPv6", address: "fd7a:115c:a1e0::1", wantErr: true},
		{name: "hostname", address: "controller.example", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseTailnetIPv4(test.address)
			if (err != nil) != test.wantErr {
				t.Fatalf("ParseTailnetIPv4(%q) error = %v, wantErr %v", test.address, err, test.wantErr)
			}
		})
	}
}

func TestNewManagerRejectsCorruptPersistentCA(t *testing.T) {
	tlsStateDir := t.TempDir()
	if _, err := NewManager(tlsStateDir, "100.64.1.1"); err != nil {
		t.Fatalf("NewManager() setup error = %v", err)
	}
	caPath := filepath.Join(tlsStateDir, caFileName)
	if err := os.WriteFile(caPath, []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("corrupt CA fixture: %v", err)
	}
	if _, err := NewManager(tlsStateDir, "100.64.1.1"); err == nil {
		t.Fatal("NewManager() accepted a corrupt persistent CA")
	}
}

func currentCertificate(t *testing.T, manager *Manager) *tls.Certificate {
	t.Helper()
	certificate, err := manager.TLSConfig().GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}
	return certificate
}
