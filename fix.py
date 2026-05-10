import os
import re

def fix_env():
    c = open('.env.example').read()
    c = c.replace(
        '# URL of the Master node (Required for slave mode)\n# MASTER_URL=http://master-ip:35353',
        '# URL of the Master node (Required for slave mode)\n# NOTE: HTTPS is strongly preferred (use https:// with valid TLS certificates) to encrypt\n# master/slave communication. Plain HTTP transmits data unencrypted and should only be\n# used on trusted/private networks (e.g., Tailscale).\n# Example: MASTER_URL=https://master-node:443\n# MASTER_URL=http://master-ip:35353'
    )
    open('.env.example', 'w').write(c)

def fix_dockerfile():
    c = open('Dockerfile').read()
    c = c.replace('FROM golang:1.26-alpine AS builder', 'FROM golang:1.22-alpine AS builder')
    c = c.replace('RUN mkdir -p /var/lib/tailscale-dnsrewrite && chmod 750 /var/lib/tailscale-dnsrewrite\n', 'RUN mkdir -p /var/lib/tailscale-dnsrewrite && chmod 750 /var/lib/tailscale-dnsrewrite \\\n    && mkdir -p /var/lib/tailscale && chmod 750 /var/lib/tailscale\n')
    c = c.replace('ENV MODE=master', 'RUN mkdir -p /var/run/tailscale && chmod 750 /var/run/tailscale\n\nENV MODE=master')
    open('Dockerfile', 'w').write(c)

def fix_readme():
    c = open('README.md').read()
    c = c.replace('4. **Zero Disk Write**: No logs are written to physical storage, preserving disk health while maintaining full visibility via `docker logs`.', '4. **Persistent Logging**: History is stored on disk and periodically archived, preserving visibility while allowing retention policies to manage disk usage.')
    c = c.replace('volumes for data persistence (Improvement 70).', 'volumes for data persistence.')
    c = c.replace('### Performance Optimization (Improvement 75)', '### Performance Optimization')
    c = c.replace('### 3. Deploy', '### 1. Deploy')
    open('README.md', 'w').write(c)

def fix_docker_compose():
    c = open('docker-compose.yaml').read()
    c = c.replace('      - PORT=${PORT:-35353}\n', '')
    c = c.replace('- "127.0.0.1:${PORT:-35353}:${PORT:-35353}"', '- "127.0.0.1:${PORT:-35353}:35353"')
    open('docker-compose.yaml', 'w').write(c)

def fix_entrypoint():
    c = open('entrypoint.sh').read()
    old_loop = '''    for server in $UPSTREAM_DNS; do
        echo "Adding upstream: $server"
        echo "server=$server" >> /etc/dnsmasq.conf
    done'''
    new_loop = '''    for server in $UPSTREAM_DNS; do
        server=$(echo "$server" | tr -d '[:space:]')
        if [[ ! "$server" =~ ^[a-zA-Z0-9.:-]+$ ]]; then
            echo "Warning: Skipping invalid upstream: $server"
            continue
        fi
        echo "Adding upstream: $server"
        echo "server=$server" >> /etc/dnsmasq.conf
    done'''
    c = c.replace(old_loop, new_loop)
    open('entrypoint.sh', 'w').write(c)

def fix_api():
    c = open('webgui/internal/api/api.go').read()
    c = c.replace('	subscribers map[chan models.QueryEvent]bool\n	subMu       sync.Mutex', '	subscribers map[chan models.QueryEvent]int\n	subMu       sync.Mutex')
    c = c.replace('subscribers: make(map[chan models.QueryEvent]bool),', 'subscribers: make(map[chan models.QueryEvent]int),')
    old_broadcast = '''	for ch := range s.subscribers {
		select {
		case ch <- e:
		default:
			// Buffer full, skip or drop client
		}
	}'''
    new_broadcast = '''	for ch, drops := range s.subscribers {
		select {
		case ch <- e:
			if drops > 0 {
				s.subscribers[ch] = 0
			}
		default:
			s.subscribers[ch]++
			if s.subscribers[ch] > 10 {
				log.Printf("Dropping slow subscriber")
				delete(s.subscribers, ch)
				close(ch)
			}
		}
	}'''
    c = c.replace(old_broadcast, new_broadcast)
    c = c.replace('s.subscribers[ch] = true', 's.subscribers[ch] = 0')
    old_sim = '''func (s *Server) handleSimulate(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Missing domain parameter", http.StatusBadRequest)
		return
	}
	ips, err := net.LookupIP(domain)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "error": err.Error()})
		return
	}
	res := make([]string, 0, len(ips))
	for _, ip := range ips {
		res = append(res, ip.String())
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "ips": res})
}'''
    new_sim = '''func (s *Server) handleSimulate(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Missing domain parameter", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	
	ips, err := (&net.Resolver{}).LookupIPAddr(ctx, domain)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			w.WriteHeader(http.StatusGatewayTimeout)
		} else {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) {
				w.WriteHeader(http.StatusBadGateway)
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "error": err.Error()})
		return
	}
	res := make([]string, 0, len(ips))
	for _, ip := range ips {
		res = append(res, ip.String())
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "ips": res})
}'''
    c = c.replace(old_sim, new_sim)
    if '"errors"' not in c:
        c = c.replace('"encoding/json"', '"encoding/json"\n\t"errors"\n\t"context"')
    
    old_server = '''		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,'''
    new_server = '''		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,'''
    c = c.replace(old_server, new_server)
    
    old_start = '''func (s *Server) Start() error {
	server := &http.Server{
		Addr:         ":" + s.cfg.Port,
		Handler:      s.SetupMux(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return err
	}

	log.Printf("Starting Advanced Web GUI on %s", server.Addr)
	return server.Serve(ln)
}'''
    new_start = '''func (s *Server) Start(ctx context.Context) error {
	server := &http.Server{
		Addr:         ":" + s.cfg.Port,
		Handler:      s.SetupMux(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	log.Printf("Starting Advanced Web GUI on %s", server.Addr)
	return server.Serve(ln)
}'''
    c = c.replace(old_start, new_start)
    open('webgui/internal/api/api.go', 'w').write(c)

def fix_config():
    c = open('webgui/internal/config/config.go').read()
    if '"strconv"' not in c:
        c = c.replace('"os"', '"os"\n\t"strconv"\n\t"log"')
    
    old_mode = '''	mode := strings.ToLower(os.Getenv("MODE"))
	if mode == "" {
		mode = "master"
	}'''
    new_mode = '''	mode := strings.ToLower(os.Getenv("MODE"))
	if mode == "" {
		mode = "master"
	}
	if mode != "master" && mode != "slave" {
		log.Printf("Warning: Invalid MODE '%s', falling back to master", mode)
		mode = "master"
	}'''
    c = c.replace(old_mode, new_mode)

    old_host = '''	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		nodeName, _ = os.Hostname()
	}'''
    new_host = '''	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		host, err := os.Hostname()
		if err != nil {
			log.Printf("Error getting hostname: %v", err)
			nodeName = "unknown-node"
		} else {
			nodeName = host
		}
	}'''
    c = c.replace(old_host, new_host)

    old_port = '''	port := os.Getenv("PORT")
	if port == "" {
		port = DefaultPort
	}'''
    new_port = '''	port := os.Getenv("PORT")
	if port == "" {
		port = DefaultPort
	} else if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		log.Printf("Warning: Invalid PORT '%s', falling back to %s", port, DefaultPort)
		port = DefaultPort
	}'''
    c = c.replace(old_port, new_port)

    c = c.replace('	return &Config{', '	cfg := &Config{')
    
    old_end_ret = '''		IngestSecret:     os.Getenv("INGEST_SECRET"),
	}
}'''
    new_end_ret = '''		IngestSecret:     os.Getenv("INGEST_SECRET"),
	}

	if cfg.Mode == "slave" && cfg.MasterURL == "" {
		log.Fatal("MASTER_URL is required when MODE is slave")
	}

	return cfg
}'''
    c = c.replace(old_end_ret, new_end_ret)
    open('webgui/internal/config/config.go', 'w').write(c)

def fix_encryption():
    c = '''package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const saltSize = 16
const iterCount = 100000

func Encrypt(plaintext []byte, password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("encryption password required")
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	key := pbkdf2.Key([]byte(password), salt, iterCount, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	
	finalData := append(salt, ciphertext...)
	return base64.StdEncoding.EncodeToString(finalData), nil
}

func Decrypt(encodedCiphertext string, password string) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("encryption password required")
	}

	data, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return nil, err
	}

	if len(data) < saltSize {
		return nil, errors.New("ciphertext too short")
	}

	salt, ciphertext := data[:saltSize], data[saltSize:]

	key := pbkdf2.Key([]byte(password), salt, iterCount, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
'''
    open('webgui/internal/encryption/encryption.go', 'w').write(c)

def fix_forwarder():
    c = open('webgui/internal/forwarder/forwarder.go').read()
    c = c.replace('	forwardChan      chan string\n', '')
    c = c.replace('		forwardChan: make(chan string, 10000),\n', '')
    c = c.replace('	cfg              *config.Config', '	cfg              *config.Config\n\tstopChan         chan struct{}')
    c = c.replace('	return &Forwarder{', '	return &Forwarder{\n\t\tstopChan: make(chan struct{}),')
    
    old_loop = '''	for {
		var lines []string
		f.backlogMu.Lock()
		if len(f.backlog) == 0 {
			f.backlogMu.Unlock()
			time.Sleep(100 * time.Millisecond)
			continue
		}
		batchSize := 100
		if len(f.backlog) < batchSize {
			batchSize = len(f.backlog)
		}
		lines = append([]string(nil), f.backlog[:batchSize]...)
		f.backlogMu.Unlock()

		err := f.sendBatch(client, lines)
		if err == nil {
			f.backlogMu.Lock()
			if len(f.backlog) >= len(lines) {
				for i := 0; i < len(lines); i++ {
					f.backlogTotalSize -= int64(len(f.backlog[i]))
				}
				f.backlog = f.backlog[len(lines):]
			}
			f.backlogMu.Unlock()
			backoff = 1 * time.Second
		} else {
			log.Printf("Error sending batch to master: %v", err)
			time.Sleep(backoff)
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}'''
    new_loop = '''	for {
		select {
		case <-f.stopChan:
			return
		default:
		}

		f.backlogMu.Lock()
		if len(f.backlog) == 0 {
			f.backlogMu.Unlock()
			select {
			case <-time.After(100 * time.Millisecond):
			case <-f.stopChan:
				return
			}
			continue
		}
		batchSize := 100
		if len(f.backlog) < batchSize {
			batchSize = len(f.backlog)
		}
		lines := append([]string(nil), f.backlog[:batchSize]...)
		
		for i := 0; i < len(lines); i++ {
			f.backlogTotalSize -= int64(len(f.backlog[i]))
		}
		f.backlog = f.backlog[batchSize:]
		f.backlogMu.Unlock()

		err := f.sendBatch(client, lines)
		if err == nil {
			backoff = 1 * time.Second
		} else {
			log.Printf("Error sending batch to master: %v", err)
			
			f.backlogMu.Lock()
			f.backlog = append(lines, f.backlog...)
			for i := 0; i < len(lines); i++ {
				f.backlogTotalSize += int64(len(lines[i]))
			}
			f.backlogMu.Unlock()

			select {
			case <-time.After(backoff):
			case <-f.stopChan:
				return
			}
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}'''
    c = c.replace(old_loop, new_loop)
    c += '''\n// Stop cleanly shuts down the forwarder
func (f *Forwarder) Stop() {
	close(f.stopChan)
}\n'''
    open('webgui/internal/forwarder/forwarder.go', 'w').write(c)

def fix_health():
    c = open('webgui/internal/health/health.go').read()
    old_nc = '''func NewChecker(cfg *config.Config, upstreamDNS string) *Checker {
	servers := strings.Fields(upstreamDNS)
	if len(servers) == 0 {
		servers = []string{"8.8.8.8", "8.8.4.4"}
	}
	return &Checker{
		cfg:       cfg,
		upstreams: servers,
		healthy:   servers,
	}
}'''
    new_nc = '''func NewChecker(cfg *config.Config, upstreamDNS string) *Checker {
	servers := strings.Fields(upstreamDNS)
	if len(servers) == 0 {
		servers = []string{"8.8.8.8", "8.8.4.4"}
	}
	c := &Checker{
		cfg:       cfg,
		upstreams: servers,
		healthy:   servers,
	}
	var initialHealthy []string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		if c.CheckUpstream(ctx, s) {
			initialHealthy = append(initialHealthy, s)
		}
	}
	c.healthy = initialHealthy
	return c
}'''
    c = c.replace(old_nc, new_nc)
    
    old_start = '''			var wg sync.WaitGroup
			var mu sync.Mutex
			newHealthy := []string{}

			for _, ups := range c.upstreams {
				wg.Add(1)
				go func(u string) {
					defer wg.Done()
					if c.CheckUpstream(ctx, u) {
						mu.Lock()
						newHealthy = append(newHealthy, u)
						mu.Unlock()
					}
				}(ups)
			}
			wg.Wait()

			c.mu.Lock()
			changed := !equalSlices(c.healthy, newHealthy)
			if changed && len(newHealthy) > 0 {
				log.Printf("Healthy upstreams changed: %v -> %v", c.healthy, newHealthy)
				c.healthy = newHealthy
				c.mu.Unlock()

				// Reload dnsmasq configuration (Improvement 39)
				_ = exec.Command("pkill", "-HUP", "dnsmasq").Run()

				onChange(newHealthy)
			} else {
				c.mu.Unlock()
			}'''
    new_start = '''			var wg sync.WaitGroup
			results := make([]bool, len(c.upstreams))

			for i, ups := range c.upstreams {
				wg.Add(1)
				go func(idx int, u string) {
					defer wg.Done()
					results[idx] = c.CheckUpstream(ctx, u)
				}(i, ups)
			}
			wg.Wait()

			var newHealthy []string
			for i, r := range results {
				if r {
					newHealthy = append(newHealthy, c.upstreams[i])
				}
			}

			c.mu.Lock()
			changed := !equalSlices(c.healthy, newHealthy)
			if changed {
				log.Printf("Healthy upstreams changed: %v -> %v", c.healthy, newHealthy)
				c.healthy = newHealthy
				c.mu.Unlock()

				if err := exec.Command("pkill", "-HUP", "dnsmasq").Run(); err != nil {
					log.Printf("Error reloading dnsmasq: %v", err)
				}

				onChange(newHealthy)
			} else {
				c.mu.Unlock()
			}'''
    c = c.replace(old_start, new_start)
    open('webgui/internal/health/health.go', 'w').write(c)

def fix_parser():
    c = open('webgui/internal/parser/parser.go').read()
    old_ts = '''		tsStr := now.Format("Jan _2 15:04:05")
		if actionIdx >= 3 {
			tsStr = string(bytes.Join(parts[:3], []byte(" ")))
		}'''
    new_ts = '''		if actionIdx < 3 {
			return nil
		}
		tsStr := string(bytes.Join(parts[:3], []byte(" ")))'''
    c = c.replace(old_ts, new_ts)

    old_fwd = '''	if bytes.Equal(action, []byte("forwarded")) {
		if len(parts) >= actionIdx+4 {
			domain := string(parts[actionIdx+1])
			upstream := string(parts[actionIdx+3])
			p.store.SetUpstream(node, domain, upstream)
		}
		return nil
	}'''
    new_fwd = '''	if bytes.Equal(action, []byte("forwarded")) {
		if len(parts) >= actionIdx+4 && string(parts[actionIdx+2]) == "to" {
			domain := string(parts[actionIdx+1])
			upstream := string(parts[actionIdx+3])
			p.store.SetUpstream(node, domain, upstream)
		}
		return nil
	}'''
    c = c.replace(old_fwd, new_fwd)

    old_q = '''		if len(parts) < actionIdx+4 {
			return nil
		}
		domain := string(parts[actionIdx+1])
		clientIP := string(parts[actionIdx+3])'''
    new_q = '''		if len(parts) < actionIdx+4 || string(parts[actionIdx+2]) != "from" {
			return nil
		}
		domain := string(parts[actionIdx+1])
		clientIP := string(parts[actionIdx+3])'''
    c = c.replace(old_q, new_q)
    open('webgui/internal/parser/parser.go', 'w').write(c)

def fix_storage():
    c = open('webgui/internal/storage/storage.go').read()
    old_we = '''				if err := f.Sync(); err != nil {
					return err
				}
				return f.Close()
			}()

			if writeErr != nil {
				log.Printf("Error writing to history file %s: %v", path, writeErr)
				allSuccess = false
				_ = f.Close()
			}'''
    new_we = '''				return f.Sync()
			}()

			if writeErr != nil {
				log.Printf("Error writing to history file %s: %v", path, writeErr)
				allSuccess = false
			}
			_ = f.Close()'''
    c = c.replace(old_we, new_we)

    old_s = '''			for scanner.Scan() {
				line := scanner.Text()
				var e models.QueryEvent

				// Decrypt if password is set
				plain := []byte(line)
				if s.cfg.HistoryPassword != "" {
					decrypted, err := encryption.Decrypt(line, s.cfg.HistoryPassword)
					if err != nil {
						continue
					}
					plain = decrypted
				}

				if err := json.Unmarshal(plain, &e); err == nil {
					if e.UnixTime >= cutoff {
						hour := e.UnixTime / 3600
						s.statsMu.Lock()
						s.hourlyStats[hour]++
						s.statsMu.Unlock()

						if e.Latency > 0 || e.Upstream != "" {
							s.cacheMu.Lock()
							s.totalReplies++
							if e.Upstream == "System Cache" {
								s.cacheHits++
							}
							s.cacheMu.Unlock()
						}
					}
				}
			}
			_ = file.Close()'''
    new_s = '''			for scanner.Scan() {
				line := scanner.Text()
				var e models.QueryEvent

				// Decrypt if password is set
				plain := []byte(line)
				if s.cfg.HistoryPassword != "" {
					decrypted, err := encryption.Decrypt(line, s.cfg.HistoryPassword)
					if err != nil {
						continue
					}
					plain = decrypted
				}

				if err := json.Unmarshal(plain, &e); err == nil {
					if e.UnixTime >= cutoff {
						hour := e.UnixTime / 3600
						s.statsMu.Lock()
						s.hourlyStats[hour]++
						s.statsMu.Unlock()

						if e.Latency > 0 || e.Upstream != "" {
							s.cacheMu.Lock()
							s.totalReplies++
							if e.Upstream == "System Cache" {
								s.cacheHits++
							}
							s.cacheMu.Unlock()
						}
					}
				}
			}
			if err := scanner.Err(); err != nil {
				log.Printf("Error scanning history file %s: %v", path, err)
			}
			if err := file.Close(); err != nil {
				log.Printf("Error closing history file %s: %v", path, err)
			}'''
    c = c.replace(old_s, new_s)
    open('webgui/internal/storage/storage.go', 'w').write(c)

def fix_main():
    c = open('webgui/main.go').read()
    old_scan = '''		for scanner.Scan() {
			buf := scanner.Bytes()
			line := make([]byte, len(buf))
			copy(line, buf)

			if cfg.Mode == "slave" {
				fwd.Enqueue(string(line))
			}
			ev := prs.ParseLogBytes(line, cfg.NodeName)
			if ev != nil {
				srv.Broadcast(*ev)
			}
		}
	}()'''
    new_scan = '''		for scanner.Scan() {
			buf := scanner.Bytes()
			line := make([]byte, len(buf))
			copy(line, buf)

			if cfg.Mode == "slave" {
				fwd.Enqueue(string(line))
			}
			ev := prs.ParseLogBytes(line, cfg.NodeName)
			if ev != nil {
				srv.Broadcast(*ev)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Printf("stdin scan error: %v", err)
		}
	}()'''
    c = c.replace(old_scan, new_scan)

    old_sd = '''	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, shutting down", sig)
		cancel()
		os.Exit(0)
	}()

	if err := srv.Start(); err != nil {
		log.Printf("Server error: %v", err)
	}'''
    new_sd = '''	errChan := make(chan error, 1)
	go func() {
		if err := srv.Start(ctx); err != nil {
			errChan <- err
		}
	}()

	select {
	case sig := <-sigChan:
		log.Printf("Received signal %v, shutting down", sig)
		cancel()
	case err := <-errChan:
		log.Printf("Server error: %v", err)
		cancel()
	}

	fwd.Stop()
	time.Sleep(1 * time.Second)'''
    c = c.replace(old_sd, new_sd)
    open('webgui/main.go', 'w').write(c)

def fix_main_test():
    c = open('webgui/main_test.go').read()
    c = c.replace('	if resp["total"].(float64) != 3 {\n		t.Errorf("Expected total 3, got %v", resp["total"])\n	}', '	val, ok := resp["total"].(float64)\n	if !ok {\n		t.Fatalf("Expected float64 for total, got %T", resp["total"])\n	}\n	if val != 3 {\n		t.Errorf("Expected total 3, got %v", val)\n	}')
    c = c.replace('	if len(events) < workers*iterations {\n		t.Errorf("Expected at least %d events, got %d", workers*iterations, len(events))\n	}', '	expected := workers * iterations * 2\n	if len(events) < expected {\n		t.Errorf("Expected at least %d events, got %d", expected, len(events))\n	}')
    open('webgui/main_test.go', 'w').write(c)

def fix_html():
    c = open('webgui/templates/index.html').read()
    old_sse = '''        function startStream() {
            const eventSource = new EventSource('/api/stream');
            eventSource.onmessage = (event) => {
                const newEvent = JSON.parse(event.data);
                allEvents = [newEvent, ...allEvents].slice(0, 1000);
                renderEvents();
            };'''
    new_sse = '''        function startStream() {
            const eventSource = new EventSource('/api/stream');
            eventSource.onmessage = (event) => {
                try {
                    const newEvent = JSON.parse(event.data);
                    allEvents = [newEvent, ...allEvents].slice(0, 1000);
                    renderEvents();
                } catch (e) {
                    console.error("Failed to parse SSE event:", e, event.data);
                }
            };'''
    c = c.replace(old_sse, new_sse)

    c = c.replace('        let allEvents = [];', '''        function escapeHtml(unsafe) {
            if (unsafe == null) return '';
            const el = document.createElement('div');
            el.textContent = unsafe;
            return el.innerHTML;
        }

        let allEvents = [];''')
    
    old_node = '''                if (stats.nodes) {
                    nodeStats.innerHTML = Object.entries(stats.nodes).map(([name, s]) => `
                        <li class="top-item">
                            <span>${name}</span>
                            <span><span class="top-count">${s.rpm}</span> <span class="top-count" style="background: rgba(129, 140, 248, 0.1); color: #818cf8;">${s.rph}</span></span>
                        </li>
                    `).join('');'''
    new_node = '''                if (stats.nodes) {
                    nodeStats.innerHTML = Object.entries(stats.nodes).map(([name, s]) => `
                        <li class="top-item">
                            <span>${escapeHtml(name)}</span>
                            <span><span class="top-count">${s.rpm}</span> <span class="top-count" style="background: rgba(129, 140, 248, 0.1); color: #818cf8;">${s.rph}</span></span>
                        </li>
                    `).join('');'''
    c = c.replace(old_node, new_node)

    old_rend = '''                    <tr>
                        <td class="timestamp">${new Date(e.unix_time * 1000).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false})}</td>
                        <td><span class="badge" style="background: rgba(255,255,255,0.1); font-size: 0.7rem;">${e.node || 'local'}</span></td>
                        <td><span class="badge badge-type">${e.type}</span></td>
                        <td class="domain">${e.domain}</td>
                        <td><span class="badge badge-ip">${e.client_ip}</span></td>
                        <td>${e.upstream ? `<span class="upstream-badge">${e.upstream}</span>` : '-'}</td>
                        <td class="latency-cell ${latencyClass}">${e.latency_ms ? e.latency_ms.toFixed(1) + 'ms' : '-'}</td>
                    </tr>'''
    new_rend = '''                    <tr>
                        <td class="timestamp">${escapeHtml(new Date(e.unix_time * 1000).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false}))}</td>
                        <td><span class="badge" style="background: rgba(255,255,255,0.1); font-size: 0.7rem;">${escapeHtml(e.node || 'local')}</span></td>
                        <td><span class="badge badge-type">${escapeHtml(e.type)}</span></td>
                        <td class="domain">${escapeHtml(e.domain)}</td>
                        <td><span class="badge badge-ip">${escapeHtml(e.client_ip)}</span></td>
                        <td>${e.upstream ? `<span class="upstream-badge">${escapeHtml(e.upstream)}</span>` : '-'}</td>
                        <td class="latency-cell ${latencyClass}">${e.latency_ms ? escapeHtml(e.latency_ms.toFixed(1)) + 'ms' : '-'}</td>
                    </tr>'''
    c = c.replace(old_rend, new_rend)

    old_tl = '''        function renderTopList(id, list) {
            const el = document.getElementById(id);
            el.innerHTML = list.map(item => `
                <li class="top-item">
                    <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 200px;">${item.key}</span>
                    <span class="top-count">${item.count}</span>
                </li>
            `).join('');
        }'''
    new_tl = '''        function renderTopList(id, list) {
            const el = document.getElementById(id);
            el.innerHTML = list.map(item => `
                <li class="top-item">
                    <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 200px;">${escapeHtml(item.key)}</span>
                    <span class="top-count">${item.count}</span>
                </li>
            `).join('');
        }'''
    c = c.replace(old_tl, new_tl)
    open('webgui/templates/index.html', 'w').write(c)

def main():
    fix_env()
    fix_dockerfile()
    fix_readme()
    fix_docker_compose()
    fix_entrypoint()
    fix_api()
    fix_config()
    fix_encryption()
    fix_forwarder()
    fix_health()
    fix_parser()
    fix_storage()
    fix_main()
    fix_main_test()
    fix_html()

if __name__ == "__main__":
    main()
