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

type Forwarder struct {
	cfg              *config.Config
	forwardChan      chan string
	backlogMu        sync.Mutex
	backlog          []string
	backlogTotalSize int64
}

func NewForwarder(cfg *config.Config) *Forwarder {
	return &Forwarder{
		cfg:         cfg,
		forwardChan: make(chan string, 10000),
	}
}

func (f *Forwarder) Enqueue(line string) {
	if f.cfg.Mode != "slave" || f.cfg.MasterURL == "" {
		return
	}
	select {
	case f.forwardChan <- line:
	default:
		// Channel full, add to backlog directly if needed or drop
	}
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
	
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	return nil
}

func (f *Forwarder) Start() {
	if f.cfg.Mode != "slave" || f.cfg.MasterURL == "" {
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	backoff := 1 * time.Second

	for {
		var lines []string
		f.backlogMu.Lock()
		if len(f.backlog) > 0 {
			batchSize := 100
			if len(f.backlog) < batchSize {
				batchSize = len(f.backlog)
			}
			lines = append([]string(nil), f.backlog[:batchSize]...)
			f.backlogMu.Unlock()
		} else {
			f.backlogMu.Unlock()
			line, ok := <-f.forwardChan
			if !ok { return }
			lines = []string{line}
			
			collectMore := true
			for collectMore && len(lines) < 100 {
				select {
				case l := <-f.forwardChan:
					lines = append(lines, l)
				default:
					collectMore = false
				}
			}

			f.backlogMu.Lock()
			for _, l := range lines {
				f.backlog = append(f.backlog, l)
				f.backlogTotalSize += int64(len(l))
			}
			f.backlogMu.Unlock()
		}

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
			if backoff > 30*time.Second { backoff = 30 * time.Second }
		}
	}
}
