package api

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// StartDNSLoopDetection begins periodic DNS loop detection checks.
func (s *Server) StartDNSLoopDetection(ctx context.Context) {
	// Check immediately on startup
	s.checkDNSLoop()

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.checkDNSLoop()
			}
		}
	}()
}

// checkDNSLoop checks if the server's own IP is configured as an upstream.
func (s *Server) checkDNSLoop() {
	localAddrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("[WARN] Failed to get local interface addresses: %v", err)
		return
	}

	localIPs := make(map[string]bool)
	for _, addr := range localAddrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		if !ip.IsLoopback() && !ip.IsUnspecified() {
			localIPs[ip.String()] = true
		}
	}

	// Get upstream IPs from the UPSTREAM_DNS config
	upstreamIPs := make(map[string]bool)
	if s.cfg.UpstreamDNS != "" {
		for _, u := range strings.Fields(s.cfg.UpstreamDNS) {
			// Strip port if present
			host := u
			if h, _, err := net.SplitHostPort(u); err == nil {
				host = h
			}
			upstreamIPs[host] = true
		}
	}

	// Also check upstreams file
	s.fieldsMu.RLock()
	dnsRoutes := s.dnsRoutes
	s.fieldsMu.RUnlock()
	if dnsRoutes != nil {
		// Check routes for loop patterns
		routes := dnsRoutes.GetRoutesMap()
		for _, upstream := range routes {
			host := upstream
			if h, _, err := net.SplitHostPort(upstream); err == nil {
				host = h
			}
			upstreamIPs[host] = true
		}
	}

	// Check for overlap
	var loopIPs []string
	for localIP := range localIPs {
		if upstreamIPs[localIP] {
			loopIPs = append(loopIPs, localIP)
		}
	}

	s.dnsLoopMu.Lock()
	defer s.dnsLoopMu.Unlock()
	if len(loopIPs) > 0 {
		s.dnsLoopDetected = true
		s.dnsLoopDetails = fmt.Sprintf("Local IP(s) %s found in upstream configuration", strings.Join(loopIPs, ", "))
		log.Printf("[WARN] DNS loop detected: %s", s.dnsLoopDetails)
	} else {
		s.dnsLoopDetected = false
		s.dnsLoopDetails = ""
	}
}

// maxBytesMiddleware limits the size of request bodies for POST endpoints.
// It uses http.MaxBytesReader to enforce the configured maximum body size.
