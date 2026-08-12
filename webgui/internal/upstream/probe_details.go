package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http/httptrace"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ProbeFailure gives operators a stable failure phase and category while the
// message retains enough context to diagnose the endpoint.
type ProbeFailure struct {
	Phase   string `json:"phase"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ProbeReport is returned by the configuration test endpoint.
type ProbeReport struct {
	Spec             string             `json:"spec"`
	NormalizedSpec   string             `json:"normalized_spec"`
	Healthy          bool               `json:"healthy"`
	Endpoint         string             `json:"resolved_endpoint,omitempty"`
	TimingsMS        map[string]float64 `json:"timings_ms"`
	TLSIssuer        string             `json:"tls_issuer,omitempty"`
	TLSServerName    string             `json:"tls_server_name,omitempty"`
	TLSExpiresAt     time.Time          `json:"tls_expires_at,omitempty"`
	HTTPStatus       int                `json:"http_status,omitempty"`
	ContentType      string             `json:"content_type,omitempty"`
	DNSMessageID     uint16             `json:"dns_message_id,omitempty"`
	ConnectionReused bool               `json:"connection_reused"`
	Bootstrap        []BootstrapStatus  `json:"bootstrap_cache,omitempty"`
	Failure          *ProbeFailure      `json:"failure,omitempty"`
}

// ProbeDetailed checks an upstream while preserving the bootstrap boundary:
// hostname resolution is performed only by the configured bootstrapper and
// all subsequent connections dial the pinned literal endpoint.
func ProbeDetailed(ctx context.Context, raw, domain string, bootstrapServers []string) (ProbeReport, error) {
	started := time.Now()
	spec, err := Parse(raw)
	if err != nil {
		return ProbeReport{}, err
	}
	report := ProbeReport{Spec: raw, NormalizedSpec: spec.NormalizedKey(), TimingsMS: make(map[string]float64)}
	boot := newBootstrapper(bootstrapServers)
	bootstrapStarted := time.Now()
	addresses, err := spec.dialAddrs(boot)
	report.TimingsMS["bootstrap"] = millisecondsSince(bootstrapStarted)
	report.Bootstrap = boot.snapshot()
	if err != nil {
		report.fail("bootstrap", err)
		report.TimingsMS["total"] = millisecondsSince(started)
		return report, nil
	}
	if len(addresses) == 0 {
		report.fail("bootstrap", errors.New("no resolved endpoint addresses"))
		return report, nil
	}
	report.Endpoint = addresses[0]

	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	probeCtx, cancel := context.WithTimeout(ctx, spec.TimeoutDuration())
	defer cancel()
	var response *dns.Msg
	switch spec.Scheme {
	case SchemeTLS:
		response, err = probeDoTDetailed(probeCtx, spec, addresses, query, &report)
	case SchemeHTTPS:
		response, err = probeDoHDetailed(probeCtx, spec, boot, query, &report)
	default:
		dnsStarted := time.Now()
		resolver := &dnsResolver{spec: spec, boot: boot}
		for _, address := range addresses {
			response, err = resolver.exchange(probeCtx, address, query)
			if err == nil && response != nil {
				report.Endpoint = address
				break
			}
		}
		report.TimingsMS["dns"] = millisecondsSince(dnsStarted)
	}
	report.TimingsMS["total"] = millisecondsSince(started)
	if err != nil {
		report.fail(failurePhase(err), err)
		return report, nil
	}
	if err := validateProbeResponse(raw, response); err != nil {
		report.fail("dns", err)
		return report, nil
	}
	report.Healthy = true
	report.DNSMessageID = response.Id
	return report, nil
}

func probeDoTDetailed(ctx context.Context, spec Spec, addresses []string, query *dns.Msg, report *ProbeReport) (*dns.Msg, error) {
	dialer := net.Dialer{}
	var connection net.Conn
	var err error
	connectStarted := time.Now()
	for _, address := range addresses {
		connection, err = dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			report.Endpoint = connection.RemoteAddr().String()
			break
		}
	}
	report.TimingsMS["tcp"] = millisecondsSince(connectStarted)
	if err != nil {
		return nil, fmt.Errorf("TCP connect: %w", err)
	}
	defer func() { _ = connection.Close() }()
	tlsConnection := tls.Client(connection, tlsConfigFor(spec.Host))
	handshakeStarted := time.Now()
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	report.TimingsMS["tls"] = millisecondsSince(handshakeStarted)
	state := tlsConnection.ConnectionState()
	report.TLSServerName = spec.Host
	if len(state.PeerCertificates) > 0 {
		report.TLSIssuer = state.PeerCertificates[0].Issuer.String()
		report.TLSExpiresAt = state.PeerCertificates[0].NotAfter
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConnection.SetDeadline(deadline)
	}
	dnsStarted := time.Now()
	dnsConnection := &dns.Conn{Conn: tlsConnection}
	if err := dnsConnection.WriteMsg(query); err != nil {
		return nil, fmt.Errorf("DNS write: %w", err)
	}
	response, err := dnsConnection.ReadMsg()
	report.TimingsMS["dns"] = millisecondsSince(dnsStarted)
	return response, err
}

func probeDoHDetailed(ctx context.Context, spec Spec, boot *bootstrapper, query *dns.Msg, report *ProbeReport) (*dns.Msg, error) {
	var connectStarted, tlsStarted, requestWritten time.Time
	trace := &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) { connectStarted = time.Now() },
		ConnectDone: func(_, _ string, _ error) {
			if !connectStarted.IsZero() {
				report.TimingsMS["tcp"] = millisecondsSince(connectStarted)
			}
		},
		TLSHandshakeStart: func() { tlsStarted = time.Now() },
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			if !tlsStarted.IsZero() {
				report.TimingsMS["tls"] = millisecondsSince(tlsStarted)
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			report.ConnectionReused = info.Reused
			report.Endpoint = info.Conn.RemoteAddr().String()
		},
		WroteRequest: func(httptrace.WroteRequestInfo) { requestWritten = time.Now() },
		GotFirstResponseByte: func() {
			if !requestWritten.IsZero() {
				report.TimingsMS["http"] = millisecondsSince(requestWritten)
			}
		},
	}
	resolver := &dohResolver{spec: spec, boot: boot}
	dnsStarted := time.Now()
	response, err := resolver.ExchangeContext(httptrace.WithClientTrace(ctx, trace), query)
	report.TimingsMS["dns"] = millisecondsSince(dnsStarted)
	runtime := resolver.runtimeInfo()
	report.TLSIssuer = runtime.TLSIssuer
	report.TLSExpiresAt = runtime.TLSExpiry
	report.TLSServerName = spec.Host
	if err == nil {
		report.HTTPStatus = 200
		report.ContentType = "application/dns-message"
	}
	resolver.closeIdleConnections()
	return response, err
}

func validateProbeResponse(raw string, response *dns.Msg) error {
	if response == nil {
		return errors.New("empty DNS response")
	}
	if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
		return fmt.Errorf("DNS health probe for %q returned DNS rcode %s", raw, dns.RcodeToString[response.Rcode])
	}
	return nil
}

func (r *ProbeReport) fail(phase string, err error) {
	r.Healthy = false
	r.Failure = &ProbeFailure{Phase: phase, Code: failureCode(err), Message: err.Error()}
}

func failurePhase(err error) string {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "bootstrap"), strings.Contains(message, "resolve"):
		return "bootstrap"
	case strings.Contains(message, "tls"), strings.Contains(message, "certificate"):
		return "tls"
	case strings.Contains(message, "http"), strings.Contains(message, "doh"):
		return "http"
	case strings.Contains(message, "connect"), strings.Contains(message, "dial"):
		return "tcp"
	default:
		return "dns"
	}
}

func failureCode(err error) string {
	message := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(message, "timeout"):
		return "timeout"
	case strings.Contains(message, "certificate"):
		return "certificate"
	case strings.Contains(message, "content type"):
		return "content_type"
	case strings.Contains(message, "message id"):
		return "message_id"
	case strings.Contains(message, "status"):
		return "http_status"
	case strings.Contains(message, "rcode"):
		return "dns_rcode"
	case strings.Contains(message, "resolve"), strings.Contains(message, "bootstrap"):
		return "resolution"
	default:
		return "network"
	}
}

func millisecondsSince(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000
}
