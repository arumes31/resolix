package health

import (
	"context"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/arumes31/resolix/webgui/internal/config"
)

func TestCheckerUsesConfiguredProtocolAndPort(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: packetConn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.1"),
		})
		_ = w.WriteMsg(response)
	})}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = server.Shutdown()
		<-done
	})

	checker := &Checker{cfg: &config.Config{HealthDomain: "health.test"}}
	deadline := time.Now().Add(2 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		ok, latency := checker.CheckUpstream(ctx, packetConn.LocalAddr().String())
		cancel()
		if ok {
			if latency < 0 {
				t.Fatalf("latency = %f", latency)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("health server did not become ready")
		}
	}

	checker.UpdateUpstreams([]string{"127.0.0.1"})
	if got := checker.upstreams; len(got) != 1 || got[0] != "127.0.0.1" {
		t.Fatalf("updated upstreams = %v", got)
	}
}

func TestUpdateUpstreamsRemovesStaleHealthyServers(t *testing.T) {
	checker := &Checker{
		upstreams: []string{"removed", "retained"},
		healthy:   []string{"removed", "retained"},
		latencies: map[string]float64{"removed": 1, "retained": 2},
	}
	replacement := []string{"retained", "new"}
	checker.UpdateUpstreams(replacement)
	replacement[0] = "caller-mutated"

	if got := checker.GetHealthy(); len(got) != 1 || got[0] != "retained" {
		t.Fatalf("healthy upstreams = %v, want [retained]", got)
	}
	if got := checker.upstreams; len(got) != 2 || got[0] != "retained" || got[1] != "new" {
		t.Fatalf("replacement upstreams = %v", got)
	}
	if latency := checker.Status()["new"].LatencyMS; latency != -1 {
		t.Fatalf("new upstream latency = %v, want unknown (-1)", latency)
	}
}

func TestUpdateUpstreamsFallsBackWhenNoHealthyServersRemain(t *testing.T) {
	checker := &Checker{
		upstreams: []string{"192.0.2.1"},
		healthy:   []string{"192.0.2.1"},
		latencies: make(map[string]float64),
	}
	replacement := []string{"198.51.100.1", "203.0.113.1"}
	checker.UpdateUpstreams(replacement)

	checker.mu.RLock()
	healthy := append([]string(nil), checker.healthy...)
	checker.mu.RUnlock()
	if !slices.Equal(healthy, replacement) {
		t.Fatalf("healthy = %v, want %v", healthy, replacement)
	}
}

func TestUpdateBootstrapServersDefensivelyCopies(t *testing.T) {
	checker := &Checker{}
	servers := []string{"192.0.2.53"}
	checker.UpdateBootstrapServers(servers)
	servers[0] = "caller-mutated"

	checker.mu.RLock()
	got := append([]string(nil), checker.bootstrapServers...)
	checker.mu.RUnlock()
	if !slices.Equal(got, []string{"192.0.2.53"}) {
		t.Fatalf("bootstrap servers = %v", got)
	}
}

func TestStatusReportsHealthStateAndReturnsCopy(t *testing.T) {
	checker := &Checker{
		upstreams: []string{"healthy", "failed"},
		healthy:   []string{"healthy"},
		latencies: map[string]float64{"healthy": 1.5, "failed": -1},
		states: map[string]*probeState{
			"failed": {consecutiveFailures: 3, consecutiveSuccesses: 1, lastFailure: "timeout"},
		},
	}
	status := checker.Status()
	if !status["healthy"].Healthy || status["healthy"].LatencyMS != 1.5 {
		t.Fatalf("healthy status = %+v", status["healthy"])
	}
	failed := status["failed"]
	if failed.Healthy || failed.ConsecutiveFailures != 3 || failed.ConsecutiveSuccesses != 1 || failed.LastFailure != "timeout" {
		t.Fatalf("failed status = %+v", failed)
	}
	status["healthy"] = UpstreamStatus{}
	if !checker.Status()["healthy"].Healthy {
		t.Fatal("Status returned mutable internal state")
	}
}

func TestStartStopsWithCanceledContextAndIntervalBounds(t *testing.T) {
	checker := &Checker{
		cfg:       &config.Config{HealthDomain: "health.test"},
		latencies: make(map[string]float64),
		states:    make(map[string]*probeState),
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	callbacks := 0
	checker.Start(ctx, func([]string, map[string]float64) { callbacks++ })
	if callbacks != 0 {
		t.Fatalf("canceled health loop callbacks = %d, want 0", callbacks)
	}
	interval := nextHealthInterval()
	if interval < 13*time.Second || interval > 17*time.Second {
		t.Fatalf("nextHealthInterval() = %s", interval)
	}
}

func TestCheckerUsesInstalledPoolProbe(t *testing.T) {
	checker := &Checker{
		cfg:              &config.Config{HealthDomain: "health.test"},
		bootstrapServers: []string{"192.0.2.53"},
	}
	var gotServer, gotDomain string
	checker.SetProbeFunc(func(_ context.Context, server, domain string) error {
		gotServer, gotDomain = server, domain
		return nil
	})

	ok, latency := checker.CheckUpstream(context.Background(), "tls://dns.example")
	if !ok || latency < 0 {
		t.Fatalf("health result = %v/%f", ok, latency)
	}
	if gotServer != "tls://dns.example" || gotDomain != "health.test" {
		t.Fatalf("probe arguments = %q/%q", gotServer, gotDomain)
	}
}

func TestCheckerReportsBootstrapHealthUsingUpstreamHostname(t *testing.T) {
	questions := make(chan string, 1)
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: packetConn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		question := request.Question[0].Name
		questions <- question
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: question, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.1").To4(),
		}}
		_ = w.WriteMsg(response)
	})}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = server.Shutdown()
		<-done
	})

	bootstrap := packetConn.LocalAddr().String()
	checker := NewChecker(
		&config.Config{HealthDomain: "fallback-health.test"},
		"tls://dns.example",
		[]string{bootstrap},
	)
	checker.SetProbeFunc(func(_ context.Context, _, _ string) error { return nil })
	var health map[string]float64
	checker.runChecks(context.Background(), func(_ []string, latencies map[string]float64) {
		health = latencies
	})

	question := <-questions
	if question != "dns.example." {
		t.Fatalf("bootstrap question = %q, want encrypted upstream hostname", question)
	}
	if latency, ok := health[bootstrapLabel+bootstrap]; !ok || latency < 0 {
		t.Fatalf("bootstrap health = %v", health)
	}
}
