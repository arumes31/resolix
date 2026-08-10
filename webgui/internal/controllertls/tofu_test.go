package controllertls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTOFUVerifierPinsCAAndAllowsLeafRotation(t *testing.T) {
	controller, err := NewManager(t.TempDir(), "100.64.8.9")
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	pinPath := filepath.Join(t.TempDir(), DefaultPinFile)
	transport, err := NewTOFUTransport("https://100.64.8.9:35353", pinPath)
	if err != nil {
		t.Fatalf("NewTOFUTransport() error = %v", err)
	}
	if err := transport.TLSClientConfig.VerifyConnection(connectionState(t, controller)); err != nil {
		t.Fatalf("first VerifyConnection() error = %v", err)
	}
	if _, err := os.Stat(pinPath); err != nil {
		t.Fatalf("first connection did not persist pin: %v", err)
	}

	reloaded, err := NewTOFUTransport("https://100.64.8.9:35353", pinPath)
	if err != nil {
		t.Fatalf("reload NewTOFUTransport() error = %v", err)
	}
	controller.mu.Lock()
	controller.leafCert = nil
	controller.mu.Unlock()
	if _, err := controller.rotateIfNeeded(time.Now()); err != nil {
		t.Fatalf("rotateIfNeeded() error = %v", err)
	}
	if err := reloaded.TLSClientConfig.VerifyConnection(connectionState(t, controller)); err != nil {
		t.Fatalf("rotated leaf VerifyConnection() error = %v", err)
	}
}

func TestTOFUTransportPinsBeforeAuthenticatedRequest(t *testing.T) {
	controller, err := NewManager(t.TempDir(), "100.64.44.55")
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	pinPath := filepath.Join(t.TempDir(), DefaultPinFile)
	pinPresent := make(chan bool, 1)
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, statErr := os.Stat(pinPath)
			pinPresent <- statErr == nil && r.Header.Get("Authorization") == "Bearer test-secret"
			w.WriteHeader(http.StatusNoContent)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsListener := tls.NewListener(listener, controller.TLSConfig())
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(tlsListener) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		<-serverDone
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	transport, err := NewTOFUTransport(
		fmt.Sprintf("https://100.64.44.55:%d", port),
		pinPath,
	)
	if err != nil {
		t.Fatalf("NewTOFUTransport() error = %v", err)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, listener.Addr().String())
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://100.64.44.55:%d/", port), nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	request.Header.Set("Authorization", "Bearer test-secret")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("TOFU request error = %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("response status = %d, want 204", response.StatusCode)
	}
	if !<-pinPresent {
		t.Fatal("authenticated request arrived before the controller CA pin was persisted")
	}
}

func TestTOFUVerifierRejectsChangedCA(t *testing.T) {
	pinPath := filepath.Join(t.TempDir(), DefaultPinFile)
	first, err := NewManager(t.TempDir(), "100.70.1.2")
	if err != nil {
		t.Fatalf("first NewManager() error = %v", err)
	}
	transport, err := NewTOFUTransport("https://100.70.1.2", pinPath)
	if err != nil {
		t.Fatalf("NewTOFUTransport() error = %v", err)
	}
	if err := transport.TLSClientConfig.VerifyConnection(connectionState(t, first)); err != nil {
		t.Fatalf("first VerifyConnection() error = %v", err)
	}

	replacement, err := NewManager(t.TempDir(), "100.70.1.2")
	if err != nil {
		t.Fatalf("replacement NewManager() error = %v", err)
	}
	if err := transport.TLSClientConfig.VerifyConnection(connectionState(t, replacement)); err == nil {
		t.Fatal("VerifyConnection() accepted a changed controller CA")
	}
}

func TestTOFUVerifierRejectsWrongIPSANBeforePinning(t *testing.T) {
	controller, err := NewManager(t.TempDir(), "100.64.9.10")
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	pinPath := filepath.Join(t.TempDir(), DefaultPinFile)
	transport, err := NewTOFUTransport("https://100.64.9.11", pinPath)
	if err != nil {
		t.Fatalf("NewTOFUTransport() error = %v", err)
	}
	if err := transport.TLSClientConfig.VerifyConnection(connectionState(t, controller)); err == nil {
		t.Fatal("VerifyConnection() accepted a certificate for another Tailscale IP")
	}
	if _, err := os.Stat(pinPath); !os.IsNotExist(err) {
		t.Fatalf("invalid first certificate created a pin: %v", err)
	}
}

func TestValidateTOFUControllerURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{name: "tailnet HTTPS", url: "https://100.64.0.1:35353"},
		{name: "tailnet default port", url: "https://100.127.255.254"},
		{name: "plain HTTP", url: "http://100.64.0.1", wantErr: true},
		{name: "public address", url: "https://203.0.113.10", wantErr: true},
		{name: "private address", url: "https://192.168.1.10", wantErr: true},
		{name: "hostname", url: "https://controller.example", wantErr: true},
		{name: "zero port", url: "https://100.64.0.1:0", wantErr: true},
		{name: "oversized port", url: "https://100.64.0.1:70000", wantErr: true},
		{name: "credentials", url: "https://user@100.64.0.1", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateTOFUControllerURL(test.url)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateTOFUControllerURL(%q) error = %v, wantErr %v", test.url, err, test.wantErr)
			}
		})
	}
}

func TestNewTOFUTransportRejectsPinForDifferentOrigin(t *testing.T) {
	pinPath := filepath.Join(t.TempDir(), "pin.json")
	data, err := json.Marshal(pinRecord{
		Version:      pinVersion,
		Origin:       "https://100.64.1.1:443",
		CASPKISHA256: "0000000000000000000000000000000000000000000000000000000000000000",
	})
	if err != nil {
		t.Fatalf("marshal pin fixture: %v", err)
	}
	if err := os.WriteFile(pinPath, data, 0o600); err != nil {
		t.Fatalf("write pin fixture: %v", err)
	}
	if _, err := NewTOFUTransport("https://100.64.1.2", pinPath); err == nil {
		t.Fatal("NewTOFUTransport() accepted a pin for another origin")
	}
}

func connectionState(t *testing.T, manager *Manager) tls.ConnectionState {
	t.Helper()
	certificate := currentCertificate(t, manager)
	peerCertificates := make([]*x509.Certificate, 0, len(certificate.Certificate))
	for _, raw := range certificate.Certificate {
		parsed, err := x509.ParseCertificate(raw)
		if err != nil {
			t.Fatalf("parse peer certificate: %v", err)
		}
		peerCertificates = append(peerCertificates, parsed)
	}
	return tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: peerCertificates,
	}
}
