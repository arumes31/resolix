package forwarder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"tailscale-dnsrewrite/webgui/internal/config"
)

// Forwarder handles sending batches of logs from slave to master.
type Forwarder struct {
	cfg              *config.Config
	stopChan         chan struct{}
	stopOnce         sync.Once
	backlogMu        sync.Mutex
	backlog          []string
	backlogTotalSize int64
}

// NewForwarder creates a new log forwarder for slave nodes.
func NewForwarder(cfg *config.Config) *Forwarder {
	return &Forwarder{
		stopChan: make(chan struct{}),
		cfg:      cfg,
	}
}

// Enqueue adds a log line to the forwarding queue.
func (f *Forwarder) Enqueue(line string) {
	if f.cfg.Mode != "slave" || f.cfg.MasterURL == "" {
		return
	}
	f.backlogMu.Lock()
	defer f.backlogMu.Unlock()

	// Enforce a maximum backlog size to prevent OOM
	if f.backlogTotalSize > f.cfg.MaxBacklogSize {
		return
	}

	f.backlog = append(f.backlog, line)
	f.backlogTotalSize += int64(len(line))
}

func (f *Forwarder) sendBatch(client *http.Client, lines []string) error {
	data, err := json.Marshal(map[string]interface{}{"node": f.cfg.NodeName, "batch": lines})
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", f.cfg.MasterURL+"/api/ingest", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if f.cfg.IngestSecret != "" {
		req.Header.Set("Authorization", "Bearer "+f.cfg.IngestSecret)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	return nil
}

// Start begins the forwarding worker loop.
func (f *Forwarder) Start() error {
	if f.cfg.Mode != "slave" || f.cfg.MasterURL == "" {
		return nil
	}
	client := &http.Client{Timeout: 10 * time.Second}
	backoff := 1 * time.Second

	var draining bool
	var drainEnd time.Time

	for {
		if !draining {
			select {
			case <-f.stopChan:
				draining = true
				drainEnd = time.Now().Add(5 * time.Second)
			default:
			}
		}

		if draining && time.Now().After(drainEnd) {
			return nil
		}

		f.backlogMu.Lock()
		if len(f.backlog) == 0 {
			f.backlogMu.Unlock()
			if draining {
				return nil
			}
			select {
			case <-time.After(100 * time.Millisecond):
			case <-f.stopChan:
				draining = true
				drainEnd = time.Now().Add(5 * time.Second)
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
			log.Printf("Successfully sent batch of %d lines to master", len(lines))
			backoff = 1 * time.Second
		} else {
			log.Printf("Error sending batch to master: %v", err)

			f.backlogMu.Lock()
			f.backlog = append(lines, f.backlog...)
			for i := 0; i < len(lines); i++ {
				f.backlogTotalSize += int64(len(lines[i]))
			}
			f.backlogMu.Unlock()

			waitDur := backoff
			if draining {
				rem := time.Until(drainEnd)
				if rem <= 0 {
					return nil
				}
				if rem < waitDur {
					waitDur = rem
				}
			}

			if draining {
				time.Sleep(waitDur)
			} else {
				select {
				case <-time.After(waitDur):
				case <-f.stopChan:
					draining = true
					drainEnd = time.Now().Add(5 * time.Second)
				}
			}

			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

// Stop cleanly shuts down the forwarder
func (f *Forwarder) Stop() {
	f.stopOnce.Do(func() {
		close(f.stopChan)
	})
}
