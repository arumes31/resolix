package dnsserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

func newTCPServer(network string, handler dns.Handler, cfg Config) *dns.Server {
	server := &dns.Server{Net: network, Handler: handler, MaxTCPQueries: cfg.TCPMaxQueries}
	if cfg.TCPIdleTimeout > 0 {
		idleTimeout := cfg.TCPIdleTimeout
		server.IdleTimeout = func() time.Duration { return idleTimeout }
	}
	return server
}

// ListenAddr returns the host:port the server binds to.
func (s *Server) ListenAddr() string {
	return net.JoinHostPort(s.cfg.Addr, fmt.Sprintf("%d", s.cfg.Port))
}

// resetTolerantConn wraps a UDP socket to ignore spurious
// "connection reset" read errors. On Windows, an ICMP port-unreachable
// (e.g. from a client that already closed its socket) surfaces as
// WSAECONNRESET on the next ReadFrom and would otherwise kill the listener.
type resetTolerantConn struct {
	net.PacketConn
}

func (c resetTolerantConn) ReadFrom(p []byte) (int, net.Addr, error) {
	const maxConsecutiveResets = 8
	for resets := 0; ; resets++ {
		n, addr, err := c.PacketConn.ReadFrom(p)
		reset := errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.Errno(10054))
		if reset && resets < maxConsecutiveResets {
			continue
		}
		return n, addr, err
	}
}

// connectionLimitListener rejects connections above a shared fixed limit.
// The slot is released exactly once when the accepted connection closes.
type connectionLimitListener struct {
	net.Listener
	slots chan struct{}
}

func (l connectionLimitListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &slotConn{Conn: conn, release: func() { <-l.slots }}, nil
		default:
			_ = conn.Close()
		}
	}
}

type slotConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *slotConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (s *Server) limitTCPListener(listener net.Listener) net.Listener {
	if listener == nil || s.tcpSlots == nil {
		return listener
	}
	return connectionLimitListener{Listener: listener, slots: s.tcpSlots}
}

// Start binds the configured address and runs the listeners until ctx is
// canceled or a listener fails, then shuts everything down gracefully. When
// DoT is enabled, certificates are validated before anything is bound.
func (s *Server) Start(ctx context.Context) error {
	// DoT requires certificates — fail fast before binding anything.
	var tlsConfig *tls.Config
	if s.cfg.DoTEnabled {
		if s.cfg.TLSCertFile == "" || s.cfg.TLSKeyFile == "" {
			return fmt.Errorf("DOT_ENABLED requires TLS_CERT_FILE and TLS_KEY_FILE")
		}
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("DoT TLS keypair: %w", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}

	udpConn, err := net.ListenPacket("udp", s.ListenAddr())
	if err != nil {
		return fmt.Errorf("DNS UDP listener on %s: %w", s.ListenAddr(), err)
	}
	tcpLn, err := net.Listen("tcp", s.ListenAddr())
	if err != nil {
		_ = udpConn.Close()
		return fmt.Errorf("DNS TCP listener on %s: %w", s.ListenAddr(), err)
	}

	var dotLn net.Listener
	if tlsConfig != nil {
		port := s.cfg.DoTPort
		if port == 0 {
			port = 853
		}
		dotAddr := net.JoinHostPort(s.cfg.Addr, fmt.Sprintf("%d", port))
		raw, err := net.Listen("tcp", dotAddr)
		if err != nil {
			_ = udpConn.Close()
			_ = tcpLn.Close()
			return fmt.Errorf("DNS DoT listener on %s: %w", dotAddr, err)
		}
		dotLn = tls.NewListener(raw, tlsConfig)
	}
	return s.startOn(ctx, udpConn, tcpLn, dotLn)
}

// StartOn runs the UDP and TCP listeners on pre-bound sockets until ctx is
// canceled or a listener fails. Tests use it with :0 sockets to avoid
// port-reservation races.
func (s *Server) StartOn(ctx context.Context, udpConn net.PacketConn, tcpLn net.Listener) error {
	return s.startOn(ctx, udpConn, tcpLn, nil)
}

// startOn serves all bound listeners until ctx is canceled or one fails.
func (s *Server) startOn(ctx context.Context, udpConn net.PacketConn, tcpLn, dotLn net.Listener) error {
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	s.udp.PacketConn = resetTolerantConn{udpConn}
	s.tcp.Listener = s.limitTCPListener(tcpLn)
	servers := []*dns.Server{s.udp, s.tcp}
	if dotLn != nil {
		s.dot = newTCPServer("tcp-tls", dns.HandlerFunc(s.ServeDNS), s.cfg)
		s.dot.Listener = s.limitTCPListener(dotLn)
		servers = append(servers, s.dot)
	}

	if s.rateLimiter != nil {
		go s.rateLimiter.rateLimitCleanupLoop(serveCtx.Done())
	}

	errCh := make(chan error, len(servers))
	for _, srv := range servers {
		go func(srv *dns.Server) { errCh <- srv.ActivateAndServe() }(srv)
	}
	s.ready.Store(true)
	defer s.ready.Store(false)

	shutdown := func() {
		for _, srv := range servers {
			_ = srv.Shutdown()
		}
	}
	select {
	case <-ctx.Done():
		shutdown()
		return nil
	case err := <-errCh:
		shutdown()
		return fmt.Errorf("DNS listener on %s: %w", s.ListenAddr(), err)
	}
}

// resolution describes how a query was answered, for event emission.

func clientIPFromRemote(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
