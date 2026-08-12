package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
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
	spec      Spec
	boot      *bootstrapper
	runtimeMu sync.RWMutex
	endpoint  string
}

func (r *dnsResolver) String() string { return r.spec.Raw }

func (r *dnsResolver) Exchange(m *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.spec.TimeoutDuration())
	defer cancel()
	return r.ExchangeContext(ctx, m)
}

func (r *dnsResolver) ExchangeContext(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	addrs, err := r.spec.dialAddrs(r.boot)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, addr := range addrs {
		resp, err := r.exchange(ctx, addr, m)
		if err == nil && resp != nil {
			r.runtimeMu.Lock()
			r.endpoint = addr
			r.runtimeMu.Unlock()
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
func (r *dnsResolver) exchange(ctx context.Context, addr string, m *dns.Msg) (*dns.Msg, error) {
	client := &dns.Client{Timeout: r.spec.TimeoutDuration()}
	switch r.spec.Scheme {
	case SchemeTCP:
		client.Net = "tcp"
	case SchemeTLS:
		client.Net = "tcp-tls"
		client.TLSConfig = tlsConfigFor(r.spec.Host)
	default: // udp with TCP fallback on truncation
		client.Net = "udp"
	}
	resp, _, err := client.ExchangeContext(ctx, m, addr)
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.Truncated && client.Net == "udp" {
		tcpClient := &dns.Client{Net: "tcp", Timeout: r.spec.TimeoutDuration()}
		if tm, _, terr := tcpClient.ExchangeContext(ctx, m, addr); terr == nil && tm != nil {
			return tm, nil
		}
	}
	return resp, nil
}

// dohResolver handles https:// specs per RFC 8484 (wire-format POST). The
// URL keeps the original hostname (correct TLS ServerName and Host header);
// dialing is redirected to literal or bootstrap-resolved IPs.
type dohResolver struct {
	spec       Spec
	boot       *bootstrapper
	clientOnce sync.Once
	client     *http.Client
	reused     atomic.Int64
	fresh      atomic.Int64
	runtimeMu  sync.RWMutex
	endpoint   string
	tlsIssuer  string
	tlsExpiry  time.Time
}

func (r *dohResolver) String() string { return r.spec.Raw }

func (r *dohResolver) Exchange(m *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.spec.TimeoutDuration())
	defer cancel()
	return r.ExchangeContext(ctx, m)
}

func (r *dohResolver) ExchangeContext(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	wire, err := m.Pack()
	if err != nil {
		return nil, err
	}

	u := url.URL{Scheme: "https", Host: net.JoinHostPort(r.spec.Host, r.spec.Port), Path: r.spec.Path, RawQuery: r.spec.Query}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Reused {
				r.reused.Add(1)
			} else {
				r.fresh.Add(1)
			}
			r.runtimeMu.Lock()
			r.endpoint = info.Conn.RemoteAddr().String()
			r.runtimeMu.Unlock()
		},
	}))

	resp, err := r.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH %s: status %d", r.spec.Raw, resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/dns-message") {
		return nil, fmt.Errorf("DoH %s: invalid content type %q", r.spec.Raw, resp.Header.Get("Content-Type"))
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		certificate := resp.TLS.PeerCertificates[0]
		r.runtimeMu.Lock()
		r.tlsIssuer = certificate.Issuer.String()
		r.tlsExpiry = certificate.NotAfter
		r.runtimeMu.Unlock()
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("DoH %s: invalid response: %w", r.spec.Raw, err)
	}
	if !out.Response {
		return nil, fmt.Errorf("DoH %s: message is not a DNS response", r.spec.Raw)
	}
	if out.Id != m.Id {
		return nil, fmt.Errorf("DoH %s: response message ID mismatch", r.spec.Raw)
	}
	return out, nil
}

// httpClient returns the DoH HTTP client, building the default one lazily.
// The dial redirect maps the URL hostname to the literal/bootstrapped IPs.
func (r *dohResolver) httpClient() *http.Client {
	if testHTTPClient != nil {
		return testHTTPClient
	}
	r.clientOnce.Do(func() {
		transport := &http.Transport{
			TLSClientConfig: tlsConfigFor(r.spec.Host),
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				addrs, err := r.spec.dialAddrs(r.boot)
				if err != nil {
					return nil, err
				}
				d := net.Dialer{}
				var lastErr error
				for _, addr := range addrs {
					conn, dialErr := d.DialContext(ctx, network, addr)
					if dialErr == nil {
						return conn, nil
					}
					lastErr = dialErr
				}
				return nil, lastErr
			},
		}
		r.client = &http.Client{Timeout: dohTimeout, Transport: transport}
		r.client.Timeout = r.spec.TimeoutDuration()
	})
	return r.client
}

type resolverRuntime struct {
	Endpoint  string
	Reused    int64
	Fresh     int64
	TLSIssuer string
	TLSExpiry time.Time
}

func (r *dnsResolver) runtimeInfo() resolverRuntime {
	r.runtimeMu.RLock()
	defer r.runtimeMu.RUnlock()
	return resolverRuntime{Endpoint: r.endpoint}
}

func (r *dohResolver) runtimeInfo() resolverRuntime {
	r.runtimeMu.RLock()
	defer r.runtimeMu.RUnlock()
	return resolverRuntime{
		Endpoint: r.endpoint, Reused: r.reused.Load(), Fresh: r.fresh.Load(),
		TLSIssuer: r.tlsIssuer, TLSExpiry: r.tlsExpiry,
	}
}

func (r *dohResolver) closeIdleConnections() {
	r.httpClient().CloseIdleConnections()
}

// Probe performs a protocol-aware DNS health exchange for one upstream.
func Probe(ctx context.Context, raw, domain string, bootstrapServers []string) error {
	spec, err := Parse(raw)
	if err != nil {
		return err
	}
	boot := newBootstrapper(bootstrapServers)
	var resolver Resolver
	if spec.Scheme == SchemeHTTPS {
		doh := &dohResolver{spec: spec, boot: boot}
		defer doh.closeIdleConnections()
		resolver = doh
	} else {
		resolver = &dnsResolver{spec: spec, boot: boot}
	}
	return probeResolver(ctx, resolver, domain)
}

func probeResolver(ctx context.Context, resolver Resolver, domain string) error {
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	var (
		response *dns.Msg
		err      error
	)
	if contextual, ok := resolver.(interface {
		ExchangeContext(context.Context, *dns.Msg) (*dns.Msg, error)
	}); ok {
		response, err = contextual.ExchangeContext(ctx, query)
	} else {
		response, err = resolver.Exchange(query)
	}
	if err != nil {
		return err
	}
	if response == nil {
		return fmt.Errorf("empty DNS response")
	}
	if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
		return fmt.Errorf("DNS health probe for %q returned RCODE %d", resolver.String(), response.Rcode)
	}
	return nil
}
