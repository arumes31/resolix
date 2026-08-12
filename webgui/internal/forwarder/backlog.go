package forwarder

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/models"
)

func (f *Forwarder) backlogPath() string {
	if f.cfg == nil || strings.TrimSpace(f.cfg.HistoryDir) == "" {
		return ""
	}
	return filepath.Join(f.cfg.HistoryDir, backlogStateFile)
}

func ensureNodeIdentity(cfg *config.Config) {
	if cfg == nil {
		return
	}
	if identity := strings.TrimSpace(cfg.NodeID); validNodeIdentity(identity) {
		cfg.NodeID = identity
		return
	}
	path := ""
	if strings.TrimSpace(cfg.HistoryDir) != "" {
		path = filepath.Join(cfg.HistoryDir, nodeIdentityFile)
		if data, err := os.ReadFile(path); err == nil { // #nosec G304 -- path is inside the configured state directory
			if identity := strings.TrimSpace(string(data)); validNodeIdentity(identity) {
				cfg.NodeID = identity
				_ = os.Chmod(path, 0o600)
				return
			}
		}
	}
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		log.Printf("[WARN] Generate stable node identity: %v", err)
		return
	}
	identity := "node-" + hex.EncodeToString(buffer)
	cfg.NodeID = identity
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		log.Printf("[WARN] Persist stable node identity: %v", err)
		return
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".node-id-*.tmp")
	if err != nil {
		log.Printf("[WARN] Persist stable node identity: %v", err)
		return
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	err = temporary.Chmod(0o600)
	if err == nil {
		_, err = temporary.WriteString(identity + "\n")
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temporaryPath, path)
	}
	if err != nil {
		log.Printf("[WARN] Persist stable node identity: %v", err)
	}
}

func validNodeIdentity(identity string) bool {
	if identity == "" || len(identity) > 128 {
		return false
	}
	for _, r := range identity {
		letter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		digit := r >= '0' && r <= '9'
		if !letter && !digit && !strings.ContainsRune("._:-", r) {
			return false
		}
	}
	return true
}

func (f *Forwarder) loadBacklog() {
	path := f.backlogPath()
	if path == "" {
		return
	}
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[WARN] Inspect persistent forwarder backlog: %v", err)
		}
		return
	}
	if !info.Mode().IsRegular() {
		log.Printf("[WARN] Ignoring non-regular persistent forwarder backlog at %s", path)
		return
	}
	maxBytes := f.cfg.MaxBacklogSize
	if maxBytes <= 0 {
		maxBytes = config.DefaultMaxBacklogSize
	}
	file, err := os.Open(path) // #nosec G304 -- path is inside the trusted history directory
	if err != nil {
		log.Printf("[WARN] Open persistent forwarder backlog: %v", err)
		return
	}
	defer func() { _ = file.Close() }()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || info.Size() != openedInfo.Size() ||
		info.Mode() != openedInfo.Mode() || !info.ModTime().Equal(openedInfo.ModTime()) {
		log.Printf("[WARN] Persistent forwarder backlog changed while opening; ignoring it")
		return
	}
	_ = os.Chmod(path, 0o600)
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1024*1024+1))
	if err != nil {
		log.Printf("[WARN] Read persistent forwarder backlog: %v", err)
		return
	}
	if int64(len(data)) > maxBytes+1024*1024 {
		f.quarantineBacklog(path, "exceeds configured limit")
		return
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return
	}
	persisted, err := decodePersistedBacklog(data)
	if err != nil {
		f.quarantineBacklog(path, "invalid or unsupported data")
		return
	}
	now := time.Now()
	for _, saved := range persisted {
		queuedAt := saved.QueuedAt
		if queuedAt.IsZero() || queuedAt.After(now.Add(time.Minute)) {
			queuedAt = now
		}
		item := backlogItem{event: saved.Event, size: eventJSONSize(saved.Event), queuedAt: queuedAt}
		if f.cfg.MaxBacklogSize > 0 && f.backlogTotalSize+item.size > f.cfg.MaxBacklogSize {
			f.dropped.Add(1)
			continue
		}
		f.backlog = append(f.backlog, item)
		f.backlogTotalSize += item.size
	}
	if len(f.backlog) > 0 {
		log.Printf("[INFO] Restored %d events from the persistent forwarder backlog", len(f.backlog))
		select {
		case f.wakeChan <- struct{}{}:
		default:
		}
	}
}

func decodePersistedBacklog(data []byte) ([]persistedBacklogItem, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var legacy []persistedBacklogItem
		return legacy, json.Unmarshal(trimmed, &legacy)
	}
	var state persistedBacklog
	if err := json.Unmarshal(trimmed, &state); err != nil {
		return nil, err
	}
	if state.Version != backlogStateVersion {
		return nil, fmt.Errorf("unsupported backlog version %d", state.Version)
	}
	return state.Items, nil
}

func (f *Forwarder) quarantineBacklog(path, reason string) {
	quarantine := fmt.Sprintf("%s.corrupt-%d", path, time.Now().Unix())
	if err := os.Rename(path, quarantine); err != nil {
		log.Printf("[WARN] Ignore persistent forwarder backlog (%s); quarantine failed: %v", reason, err)
		return
	}
	_ = os.Chmod(quarantine, 0o600)
	log.Printf("[WARN] Quarantined persistent forwarder backlog (%s)", reason)
}

func (f *Forwarder) signalBacklogPersistence() {
	if f.backlogPath() == "" {
		return
	}
	select {
	case f.persistWake <- struct{}{}:
	default:
	}
}

func (f *Forwarder) runBacklogPersistence() {
	for {
		select {
		case <-f.stopChan:
			if err := f.flushBacklog(); err != nil {
				log.Printf("[WARN] Persist forwarder backlog during shutdown: %v", err)
			}
			return
		case <-f.persistWake:
			timer := time.NewTimer(250 * time.Millisecond)
			select {
			case <-f.stopChan:
				if !timer.Stop() {
					<-timer.C
				}
			case <-timer.C:
			}
			if err := f.flushBacklog(); err != nil {
				log.Printf("[WARN] Persist forwarder backlog: %v", err)
			}
		}
	}
}

func (f *Forwarder) flushBacklog() error {
	f.persistMu.Lock()
	defer f.persistMu.Unlock()
	path := f.backlogPath()
	if path == "" {
		return nil
	}
	f.backlogMu.Lock()
	defer f.backlogMu.Unlock()
	items := make([]backlogItem, 0, len(f.inFlight)+len(f.backlog))
	items = append(items, f.inFlight...)
	items = append(items, f.backlog...)
	persisted := make([]persistedBacklogItem, len(items))
	for i, item := range items {
		persisted[i] = persistedBacklogItem{Event: item.event, QueuedAt: item.queuedAt}
	}
	data, err := json.Marshal(persistedBacklog{Version: backlogStateVersion, Items: persisted})
	if err != nil {
		return fmt.Errorf("marshal forwarder backlog: %w", err)
	}
	maxBytes := f.cfg.MaxBacklogSize
	if maxBytes <= 0 {
		maxBytes = config.DefaultMaxBacklogSize
	}
	trimmed := 0
	for int64(len(data)) > maxBytes && trimmed < len(f.backlog) {
		trimmed++
		bounded := make([]persistedBacklogItem, 0, len(persisted)-trimmed)
		bounded = append(bounded, persisted[:len(f.inFlight)]...)
		bounded = append(bounded, persisted[len(f.inFlight)+trimmed:]...)
		data, err = json.Marshal(persistedBacklog{Version: backlogStateVersion, Items: bounded})
		if err != nil {
			return fmt.Errorf("marshal bounded forwarder backlog: %w", err)
		}
	}
	if int64(len(data)) > maxBytes {
		return fmt.Errorf("configured backlog limit %d is too small for state metadata", maxBytes)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create forwarder backlog directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".forwarder-backlog-*.tmp")
	if err != nil {
		return fmt.Errorf("create forwarder backlog temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure forwarder backlog temporary file: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write forwarder backlog temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync forwarder backlog temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close forwarder backlog temporary file: %w", err)
	}
	if err := replaceBacklogFile(temporaryPath, path); err != nil {
		return fmt.Errorf("publish forwarder backlog: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure published forwarder backlog: %w", err)
	}
	if trimmed > 0 {
		for _, item := range f.backlog[:trimmed] {
			f.backlogTotalSize -= item.size
		}
		f.backlog = f.backlog[trimmed:]
		f.dropped.Add(int64(trimmed))
		log.Printf("[WARN] Dropped %d oldest queued event(s) to keep the persistent forwarder backlog within %d bytes", trimmed, maxBytes)
	}
	return nil
}

// EnqueueEvent adds a query event to the forwarding queue.
func (f *Forwarder) EnqueueEvent(ev models.QueryEvent) {
	if f.cfg.Mode != config.ModeAgent || f.cfg.ControllerURL == "" {
		return
	}
	if ev.Node == "" {
		ev.Node = f.cfg.NodeName
	}
	item := backlogItem{event: ev, size: eventJSONSize(ev), queuedAt: time.Now()}
	f.backlogMu.Lock()

	// Enforce a maximum backlog size in bytes to prevent OOM (only when limit is configured)
	if f.cfg.MaxBacklogSize > 0 && f.backlogTotalSize+item.size > f.cfg.MaxBacklogSize {
		f.dropped.Add(1)
		f.backlogMu.Unlock()
		return
	}

	f.backlog = append(f.backlog, item)
	f.backlogTotalSize += item.size
	f.backlogMu.Unlock()
	f.signalBacklogPersistence()
	select {
	case f.wakeChan <- struct{}{}:
	default:
	}
}

func (f *Forwarder) requeueBatch(items []backlogItem) {
	f.backlogMu.Lock()
	f.inFlight = nil
	f.backlog = append(items, f.backlog...)
	f.backlogMu.Unlock()
	f.signalBacklogPersistence()
}

func (f *Forwarder) finishInFlight(requeue bool) {
	f.backlogMu.Lock()
	items := f.inFlight
	f.inFlight = nil
	if requeue {
		f.backlog = append(items, f.backlog...)
	} else {
		for _, item := range items {
			f.backlogTotalSize -= item.size
		}
	}
	f.backlogMu.Unlock()
	f.signalBacklogPersistence()
}

// startHeartbeat sends periodic heartbeats to the controller (Item 92).
