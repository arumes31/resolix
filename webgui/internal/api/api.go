// Package api implements the HTTP API and web GUI server for the
// Resolix application. It handles authentication, SSE
// broadcasting, Prometheus metrics, request size limiting, and all
// API endpoints.
package api

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/arumes31/resolix/webgui/internal/blocklist"
	"github.com/arumes31/resolix/webgui/internal/clients"
	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/dnsroutes"
	"github.com/arumes31/resolix/webgui/internal/dnsserver"
	"github.com/arumes31/resolix/webgui/internal/dnssettings"
	"github.com/arumes31/resolix/webgui/internal/filter"
	"github.com/arumes31/resolix/webgui/internal/forwarder"
	"github.com/arumes31/resolix/webgui/internal/models"
	"github.com/arumes31/resolix/webgui/internal/parser"
	"github.com/arumes31/resolix/webgui/internal/resolver"
	"github.com/arumes31/resolix/webgui/internal/rewrites"
	"github.com/arumes31/resolix/webgui/internal/storage"
	"github.com/arumes31/resolix/webgui/internal/upstream"
)

const (
	sessionCookieName   = "ts_dns_session"
	csrfCookieName      = "ts_dns_csrf"
	csrfTokenBytes      = 32
	sessionTokenBytes   = 32
	sessionLifetime     = 7 * 24 * time.Hour
	maxIngestFutureSkew = 5 * time.Minute
	statsResponseTTL    = 5 * time.Second
	staticAssetCaching  = "public, max-age=300"
)

var userRulesMu sync.Mutex

// Server handles HTTP API and Web GUI requests.
type Server struct {
	cfg    *config.Config
	store  *storage.Store
	parser *parser.Parser
	tmpl   *template.Template

	// SSE Broadcaster
	subscribers map[chan models.QueryEvent]int
	subMu       sync.RWMutex
	subDropCnt  atomic.Int64

	// Static file handler and nonce function (set via SetStaticHandler)
	staticHandler http.Handler
	cspMiddleware func(http.Handler) http.Handler
	nonceFromCtx  func(context.Context) string

	// Rate limiter for login attempts (per-IP)
	rateLimits map[string]*rateLimitEntry
	rateMu     sync.Mutex

	// Hashed password (bcrypt) — populated at startup
	hashedPassword string
	sessions       map[string]time.Time
	sessionMu      sync.Mutex

	// Reverse DNS resolver (Item 59)
	resolver *resolver.Resolver

	// Blocklist (Item 61)
	blocklist *blocklist.Blocklist

	// Filter engine (Step 2: rule-based filtering with subscriptions)
	filterEngine      *filter.Engine
	subscriptionStore *filter.SubscriptionStore

	// Typed rewrites store (Step 3) and DNS server (pipeline metrics)
	rewritesStore *rewrites.Store
	dnsServer     *dnsserver.Server

	// Per-client registry (Step 5)
	clientsRegistry *clients.Registry

	// upstreamReloadFn reloads the upstream pool after upstreams.json saves
	upstreamReloadFn func()
	upstreamPool     *upstream.Pool
	forwarder        *forwarder.Forwarder

	// DNS routes (Item 66)
	dnsRoutes *dnsroutes.DNSRoutes
	// dnsSettings contains controller-managed behavior that is safe to update
	// without rebinding DNS or HTTP listeners.
	dnsSettings        *dnssettings.Store
	dnsSettingsApplyFn func(dnssettings.Settings)

	// Mutex protecting resolver, blocklist, and dnsRoutes fields
	fieldsMu sync.RWMutex
	// configApplyMu serializes multi-store snapshot application and rollback.
	configApplyMu sync.Mutex
	// syncRequestMu protects controller-issued cluster and per-node sync epochs.
	syncRequestMu         sync.RWMutex
	clusterSyncGeneration uint64
	nodeSyncGenerations   map[string]uint64

	// DNS loop detection (Item 65)
	dnsLoopDetected bool
	dnsLoopMu       sync.Mutex
	dnsLoopDetails  string

	// Short-lived response cache coalesces expensive SQLite stats aggregation
	// across dashboard clients while keeping live counters reasonably fresh.
	statsCacheMu   sync.Mutex
	statsCacheBody []byte
	statsCacheAt   time.Time

	// Prometheus metrics (Item 77)
	metrics   *Metrics
	webReady  atomic.Bool
	version   string
	buildInfo string
}

// SetBuildInfo publishes build metadata through the API and node status.
func (s *Server) SetBuildInfo(version, buildInfo string) {
	s.fieldsMu.Lock()
	s.version = version
	s.buildInfo = buildInfo
	s.fieldsMu.Unlock()
}

func (s *Server) buildMetadata() (version, buildInfo string) {
	s.fieldsMu.RLock()
	defer s.fieldsMu.RUnlock()
	return s.version, s.buildInfo
}

// NewServer initializes a new API server.
func NewServer(cfg *config.Config, store *storage.Store, prs *parser.Parser, tmpl *template.Template) *Server {
	s := &Server{
		cfg:                 cfg,
		store:               store,
		parser:              prs,
		tmpl:                tmpl,
		subscribers:         make(map[chan models.QueryEvent]int),
		rateLimits:          make(map[string]*rateLimitEntry),
		sessions:            make(map[string]time.Time),
		metrics:             &Metrics{StartTime: time.Now()},
		nodeSyncGenerations: make(map[string]uint64),
	}

	// Hash the configured password at startup if auth is enabled
	if cfg.WebPassword != "" {
		if isBcryptHash(cfg.WebPassword) {
			s.hashedPassword = cfg.WebPassword
		} else {
			hash, err := bcrypt.GenerateFromPassword([]byte(cfg.WebPassword), bcrypt.DefaultCost)
			if err != nil {
				log.Fatalf("Failed to hash password: %v", err)
			}
			s.hashedPassword = string(hash)
			log.Println("Password auto-hashed with bcrypt at startup")
		}
	}

	// Start stale rate-limit entry cleanup goroutine
	go s.cleanupRateLimits()

	return s
}

// SetResolver configures the reverse DNS resolver for enriching events with hostnames.
func (s *Server) SetResolver(r *resolver.Resolver) {
	s.fieldsMu.Lock()
	defer s.fieldsMu.Unlock()
	s.resolver = r
}

// SetBlocklist configures the blocklist for checking blocked domains.
func (s *Server) SetBlocklist(bl *blocklist.Blocklist) {
	s.fieldsMu.Lock()
	defer s.fieldsMu.Unlock()
	s.blocklist = bl
}

// SetDNSRoutes configures the domain-specific DNS routing rules.
func (s *Server) SetDNSRoutes(dr *dnsroutes.DNSRoutes) {
	s.fieldsMu.Lock()
	defer s.fieldsMu.Unlock()
	s.dnsRoutes = dr
}

// SetFilter configures the filter engine for status/pause endpoints and metrics.
func (s *Server) SetFilter(eng *filter.Engine) {
	s.fieldsMu.Lock()
	s.filterEngine = eng
	store := s.subscriptionStore
	s.fieldsMu.Unlock()
	if eng != nil {
		eng.SetRulesChangedCallback(s.clearDNSCache)
		if store != nil {
			eng.SetHistoryDir(store.HistoryDir())
		}
	}
}

// SetSubscriptionStore configures persistent URL filter subscriptions.
func (s *Server) SetSubscriptionStore(store *filter.SubscriptionStore) {
	s.fieldsMu.Lock()
	s.subscriptionStore = store
	engine := s.filterEngine
	s.fieldsMu.Unlock()
	if store != nil && engine != nil {
		engine.SetHistoryDir(store.HistoryDir())
	}
}

// SetRewritesStore configures the typed-rewrites store for the CRUD API.
func (s *Server) SetRewritesStore(store *rewrites.Store) {
	s.fieldsMu.Lock()
	defer s.fieldsMu.Unlock()
	s.rewritesStore = store
}

// SetDNSServer configures the DNS server for pipeline metrics.
func (s *Server) SetDNSServer(srv *dnsserver.Server) {
	s.fieldsMu.Lock()
	defer s.fieldsMu.Unlock()
	s.dnsServer = srv
}

// SetDNSSettingsStore configures persistent controller-managed DNS policy.
func (s *Server) SetDNSSettingsStore(store *dnssettings.Store) {
	s.fieldsMu.Lock()
	s.dnsSettings = store
	s.fieldsMu.Unlock()
}

// SetDNSSettingsApplyFunc configures live application after a settings file
// has been durably replaced.
func (s *Server) SetDNSSettingsApplyFunc(fn func(dnssettings.Settings)) {
	s.fieldsMu.Lock()
	s.dnsSettingsApplyFn = fn
	s.fieldsMu.Unlock()
}

func (s *Server) clearDNSCache() {
	if dnsSrv := s.getDNSServer(); dnsSrv != nil {
		dnsSrv.ClearCache()
	}
}

// SetClients configures the per-client registry for the clients API.
func (s *Server) SetClients(reg *clients.Registry) {
	s.fieldsMu.Lock()
	defer s.fieldsMu.Unlock()
	s.clientsRegistry = reg
}

// SetUpstreamReloadFunc configures the callback invoked after the upstreams
// file is saved via the API, so the pool picks up changes immediately.
func (s *Server) SetUpstreamReloadFunc(fn func()) {
	s.fieldsMu.Lock()
	defer s.fieldsMu.Unlock()
	s.upstreamReloadFn = fn
}

// SetUpstreamPool configures upstream runtime metrics.
func (s *Server) SetUpstreamPool(pool *upstream.Pool) {
	s.fieldsMu.Lock()
	s.upstreamPool = pool
	s.fieldsMu.Unlock()
}

// SetForwarder configures forwarding queue metrics.
func (s *Server) SetForwarder(fwd *forwarder.Forwarder) {
	s.fieldsMu.Lock()
	s.forwarder = fwd
	s.fieldsMu.Unlock()
}

// getFilter returns the configured filter engine (may be nil).
func (s *Server) getFilter() *filter.Engine {
	s.fieldsMu.RLock()
	defer s.fieldsMu.RUnlock()
	return s.filterEngine
}

// getDNSServer returns the configured DNS server (may be nil).
func (s *Server) getDNSServer() *dnsserver.Server {
	s.fieldsMu.RLock()
	defer s.fieldsMu.RUnlock()
	return s.dnsServer
}

// isBcryptHash returns true if the string looks like a bcrypt hash.
