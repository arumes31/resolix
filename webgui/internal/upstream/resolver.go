package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
)

const (
	// exchangeTimeout bounds a single UDP/TCP/DoT exchange.
	exchangeTimeout = 5 * time.Second
	// dohTimeout bounds a DoH request (RFC 8484 over HTTP).
	dohTimeout = 20 * time.Second
)

// Resolver resolves a single DNS query against one upstream.
type Resolver interface {
	Exchange(m *dns.Msg) (*dns.Msg, error)
	// String returns the original upstream spec (for events and metrics).
	String() string
}

// testTLSConfig, when set, overrides the TLS configuration of new DoT/DoH
// resolvers. Test-only hook; never set in production code.
var testTLSConfig *tls.Config

// testHTTPClient, when set, is used by DoH resolvers instead of building a
// default client. Test-only hook for httptest TLS servers.
var testHTTPClient *http.Client

// tlsConfigFor returns the TLS config for a hostname-based upstream: system
// roots, ServerName from the spec host. InsecureSkipVerify is never set in
// production; tests may override via testTLSConfig.
func tlsConfigFor(host string) *tls.Config {
	if testTLSConfig != nil {
		return testTLSConfig
	}
	return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
}

// dnsResolver handles udp/tcp/tls specs via miekg/dns clients.
type dnsResolver struct {
	spec Spec
	boot *bootstrapper
}

func (r *dnsResolver) String() string { return r.spec.Raw }

func (r *dnsResolver) Exchange(m *dns.Msg) (*dns.Msg, error) {
	addrs, err := r.spec.dialAddrs(r.boot)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, addr := range addrs {
		resp, err := r.exchange(addr, m)
		if err == nil && resp != nil {
			return resp, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("upstream %q: no dial addresses", r.spec.Raw)
	}
	return nil, lastErr
}

// exchange performs one exchange against a concrete dial address.
func (r *dnsResolver) exchange(addr string, m *dns.Msg) (*dns.Msg, error) {
	client := &dns.Client{Timeout: exchangeTimeout}
	switch r.spec.Scheme {
	case SchemeTCP:
		client.Net = "tcp"
	case SchemeTLS:
		client.Net = "tcp-tls"
		client.TLSConfig = tlsConfigFor(r.spec.Host)
	default: // udp with TCP fallback on truncation
		client.Net = "udp"
	}
	resp, _, err := client.Exchange(m, addr)
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.Truncated && client.Net == "udp" {
		tcpClient := &dns.Client{Net: "tcp", Timeout: exchangeTimeout}
		if tm, _, terr := tcpClient.Exchange(m, addr); terr == nil && tm != nil {
			return tm, nil
		}
	}
	return resp, nil
}

// dohResolver handles https:// specs per RFC 8484 (wire-format POST). The
// URL keeps the original hostname (correct TLS ServerName and Host header);
// dialing is redirected to literal or bootstrap-resolved IPs.
type dohResolver struct {
	spec   Spec
	boot   *bootstrapper
	client *http.Client
}

func (r *dohResolver) String() string { return r.spec.Raw }

func (r *dohResolver) Exchange(m *dns.Msg) (*dns.Msg, error) {
	wire, err := m.Pack()
	if err != nil {
		return nil, err
	}

	u := url.URL{Scheme: "https", Host: net.JoinHostPort(r.spec.Host, r.spec.Port), Path: r.spec.Path}
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH %s: status %d", r.spec.Raw, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("DoH %s: invalid response: %w", r.spec.Raw, err)
	}
	out.Id = m.Id
	return out, nil
}

// httpClient returns the DoH HTTP client, building the default one lazily.
// The dial redirect maps the URL hostname to the literal/bootstrapped IPs.
func (r *dohResolver) httpClient() *http.Client {
	if r.client != nil {
		return r.client
	}
	if testHTTPClient != nil {
		return testHTTPClient
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfigFor(r.spec.Host),
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			addrs, err := r.spec.dialAddrs(r.boot)
			if err != nil {
				return nil, err
			}
			d := net.Dialer{}
			return d.DialContext(ctx, network, addrs[0])
		},
	}
	r.client = &http.Client{Timeout: dohTimeout, Transport: transport}
	return r.client
}
