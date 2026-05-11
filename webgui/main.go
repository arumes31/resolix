package main

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"html/template"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"tailscale-dnsrewrite/webgui/internal/api"
	"tailscale-dnsrewrite/webgui/internal/config"
	"tailscale-dnsrewrite/webgui/internal/forwarder"
	"tailscale-dnsrewrite/webgui/internal/health"
	"tailscale-dnsrewrite/webgui/internal/parser"
	"tailscale-dnsrewrite/webgui/internal/storage"
)

// Version represents the current application version.
const Version = "2.0.0"

//go:embed templates/*
var templates embed.FS

func main() {
	cfg := config.LoadConfig()
	log.Printf("Tailscale DNS Monitor v%s starting in %s mode", Version, cfg.Mode)

	store := storage.NewStore(cfg)
	store.Init()

	tmpl, err := template.ParseFS(templates, "templates/index.html")
	if err != nil {
		log.Fatalf("Fatal error parsing templates: %v", err)
	}

	prs := parser.NewParser(store, cfg.Debug)
	srv := api.NewServer(cfg, store, prs, tmpl)
	fwd := forwarder.NewForwarder(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Improvement 39: Move health checks to Go
	checker := health.NewChecker(cfg, cfg.UpstreamDNS)
	go checker.Start(ctx, func(healthy []string) {
		log.Printf("Health status changed. New upstreams: %v", healthy)
		cmd := exec.Command("pkill", "-HUP", "dnsmasq")
		if err := cmd.Run(); err != nil {
			log.Printf("Error reloading dnsmasq from main: %v", err)
		} else {
			log.Printf("Successfully reloaded dnsmasq")
		}
	})

	// History Archiver
	go func() {
		ticker := time.NewTicker(cfg.ArchiveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				store.ArchiveStep(time.Now())
			}
		}
	}()

	// Cleanup
	go func() {
		ticker := time.NewTicker(cfg.CleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				store.CleanupPending(time.Now())
			}
		}
	}()

	errChan := make(chan error, 2)

	// Start Forwarder for Slave mode
	go func() {
		if err := fwd.Start(); err != nil {
			errChan <- err
		}
	}()

	// Log Ingestion
	go func() {
		linesCh := make(chan []byte)
		go func() {
			log.Println("Log ingestion scanner started on stdin")
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				buf := scanner.Bytes()
				line := make([]byte, len(buf))
				copy(line, buf)
				linesCh <- line
			}
			if err := scanner.Err(); err != nil {
				log.Printf("stdin scan error: %v", err)
			}
			log.Println("Log ingestion scanner reached EOF")
			close(linesCh)
		}()

		for {
			select {
			case <-ctx.Done():
				return
			case line, ok := <-linesCh:
				if !ok {
					log.Println("Log ingestion loop exiting: channel closed")
					return
				}
				if cfg.Debug {
					if bytes.Contains(line, []byte("query[")) || bytes.Contains(line, []byte("reply")) {
						// Use a prefix to distinguish from other logs
						log.Printf("[INGEST] %s", string(line))
					} else {
						// Fallback: print everything for now to debug
						log.Printf("[DEBUG] %s", string(line))
					}
				}

				if cfg.Mode == "slave" {
					fwd.Enqueue(string(line))
				}
				ev := prs.ParseLogBytes(line, cfg.NodeName)
				if ev != nil {
					srv.Broadcast(*ev)
				}
			}
		}
	}()

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
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
	time.Sleep(1 * time.Second)
}
