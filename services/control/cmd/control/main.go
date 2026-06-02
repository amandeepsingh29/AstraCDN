package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/nats-io/nats.go"
)

type registerRequest struct {
	NodeID       string   `json:"node_id"`
	Address      string   `json:"address"`
	Capabilities []string `json:"capabilities"`
}

type cacheInvalidationRequest struct {
	Host        string   `json:"host,omitempty"`
	Keys        []string `json:"keys"`
	Prefixes    []string `json:"prefixes"`
	Tags        []string `json:"tags"`
	RequestedBy string   `json:"requested_by"`
}

type cachePrewarmRequest struct {
	Host        string   `json:"host,omitempty"`
	Paths       []string `json:"paths"`
	RequestedBy string   `json:"requested_by"`
}

type cacheInvalidationDeliveryRequest struct {
	InvalidationID int64  `json:"invalidation_id"`
	NodeID         string `json:"node_id"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
}

type originRequest struct {
	Name    string            `json:"name"`
	BaseURL string            `json:"base_url"`
	Headers map[string]string `json:"headers,omitempty"`
}

type routeRequest struct {
	Host            string              `json:"host"`
	PathPrefix      string              `json:"path_prefix"`
	OriginID        int64               `json:"origin_id"`
	CacheTTLSeconds *int                `json:"cache_ttl_seconds,omitempty"`
	CachePolicy     *cachePolicyRequest `json:"cache_policy,omitempty"`
	DeliveryRules   deliveryRulesConfig `json:"delivery_rules,omitempty"`
	WAFRules        wafRulesConfig      `json:"waf_rules,omitempty"`
	RateLimitRules  []rateLimitRule     `json:"rate_limit_rules,omitempty"`
}

type domainRequest struct {
	Host    string `json:"host"`
	RouteID *int64 `json:"route_id,omitempty"`
	TLSMode string `json:"tls_mode,omitempty"`
}

type domainVerificationRequest struct {
	Host string `json:"host"`
}

type apiKeyCreateRequest struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes,omitempty"`
}

type apiKeyRevokeRequest struct {
	ID int64 `json:"id"`
}

type tenantRequest struct {
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Status string `json:"status,omitempty"`
}

type tenantUserRequest struct {
	TenantID int64  `json:"tenant_id"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Status   string `json:"status,omitempty"`
}

type billingAccountRequest struct {
	TenantID           int64  `json:"tenant_id"`
	Provider           string `json:"provider"`
	ProviderCustomerID string `json:"provider_customer_id,omitempty"`
	Plan               string `json:"plan"`
	Status             string `json:"status,omitempty"`
}

type billingWebhookRequest struct {
	EventID            string `json:"event_id"`
	Provider           string `json:"provider"`
	TenantID           int64  `json:"tenant_id,omitempty"`
	ProviderCustomerID string `json:"provider_customer_id,omitempty"`
	Plan               string `json:"plan,omitempty"`
	Status             string `json:"status"`
}

type billingWebhookResult struct {
	Account   billingAccountRecord
	Duplicate bool
}

type cacheAnalyticsSnapshotRequest struct {
	EdgeNodeID string                       `json:"edge_node_id,omitempty"`
	Host       string                       `json:"host,omitempty"`
	Cache      cacheAnalyticsSnapshotMetric `json:"cache"`
	ObservedAt *time.Time                   `json:"observed_at,omitempty"`
}

type auditLogListRequest struct {
	Limit        int
	Action       string
	ResourceType string
}

type billingWebhookEventListRequest struct {
	Limit            int
	Provider         string
	EventID          string
	BillingAccountID int64
}

type routeRuleVersionListRequest struct {
	Limit   int
	RouteID int64
}

type cacheAnalyticsSnapshotMetric struct {
	Requests uint64                                   `json:"requests"`
	Hits     uint64                                   `json:"hits"`
	Misses   uint64                                   `json:"misses"`
	HitRatio float64                                  `json:"hit_ratio"`
	ByLayer  map[string]cacheAnalyticsLayerMetric     `json:"by_layer"`
	ByHost   map[string]cacheAnalyticsDimensionMetric `json:"by_host,omitempty"`
	ByRoute  map[string]cacheAnalyticsDimensionMetric `json:"by_route,omitempty"`
	Fill     cacheFillLatencyMetric                   `json:"cache_fill_latency,omitempty"`
}

type cacheAnalyticsLayerMetric struct {
	Result   string `json:"result"`
	Requests uint64 `json:"requests"`
}

type cacheAnalyticsDimensionMetric struct {
	Requests uint64                               `json:"requests"`
	Hits     uint64                               `json:"hits"`
	Misses   uint64                               `json:"misses"`
	HitRatio float64                              `json:"hit_ratio"`
	ByLayer  map[string]cacheAnalyticsLayerMetric `json:"by_layer"`
}

type cacheFillLatencyMetric struct {
	Count      uint64  `json:"count"`
	SumSeconds float64 `json:"sum_seconds"`
	AvgSeconds float64 `json:"avg_seconds"`
	MaxSeconds float64 `json:"max_seconds"`
}

type edgeHealth struct {
	Node                 edgeNode               `json:"node"`
	Healthy              bool                   `json:"healthy"`
	SecondsSinceLastSeen int64                  `json:"seconds_since_last_seen"`
	LastCacheObservedAt  *time.Time             `json:"last_cache_observed_at,omitempty"`
	CacheFillLatency     cacheFillLatencyMetric `json:"cache_fill_latency"`
}

type auditLogEntry struct {
	ID           int64           `json:"id"`
	Actor        string          `json:"actor"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id,omitempty"`
	RequestID    string          `json:"request_id,omitempty"`
	RemoteAddr   string          `json:"remote_addr,omitempty"`
	Metadata     json.RawMessage `json:"metadata"`
	CreatedAt    time.Time       `json:"created_at"`
}

type billingWebhookEventRecord struct {
	ID               int64           `json:"id"`
	Provider         string          `json:"provider"`
	EventID          string          `json:"event_id"`
	BillingAccountID *int64          `json:"billing_account_id,omitempty"`
	Status           string          `json:"status"`
	Payload          json.RawMessage `json:"payload"`
	ProcessedAt      time.Time       `json:"processed_at"`
	CreatedAt        time.Time       `json:"created_at"`
}

type routeRuleVersion struct {
	ID             int64               `json:"id"`
	RouteID        int64               `json:"route_id"`
	Version        int                 `json:"version"`
	DeliveryRules  deliveryRulesConfig `json:"delivery_rules"`
	WAFRules       wafRulesConfig      `json:"waf_rules"`
	RateLimitRules []rateLimitRule     `json:"rate_limit_rules"`
	ChangedBy      string              `json:"changed_by,omitempty"`
	RequestID      string              `json:"request_id,omitempty"`
	CreatedAt      time.Time           `json:"created_at"`
}

type cachePolicyRequest struct {
	Mode                        string `json:"mode,omitempty"`
	TTLSeconds                  *int   `json:"ttl_seconds,omitempty"`
	StaleWhileRevalidateSeconds *int   `json:"stale_while_revalidate_seconds,omitempty"`
}

type deliveryRulesConfig struct {
	SetHeaders    []deliveryHeaderSetRule    `json:"set_headers,omitempty"`
	RemoveHeaders []deliveryHeaderRemoveRule `json:"remove_headers,omitempty"`
	Redirects     []deliveryRedirectRule     `json:"redirects,omitempty"`
}

type deliveryHeaderSetRule struct {
	PathPrefix string `json:"path_prefix,omitempty"`
	Name       string `json:"name"`
	Value      string `json:"value"`
}

type deliveryHeaderRemoveRule struct {
	PathPrefix string `json:"path_prefix,omitempty"`
	Name       string `json:"name"`
}

type deliveryRedirectRule struct {
	PathPrefix string `json:"path_prefix,omitempty"`
	Target     string `json:"target"`
	Status     int    `json:"status"`
}

type wafRulesConfig struct {
	Enabled      *bool           `json:"enabled,omitempty"`
	Methods      []string        `json:"methods,omitempty"`
	PathPrefixes []string        `json:"path_prefixes,omitempty"`
	Headers      []wafHeaderRule `json:"headers,omitempty"`
	IPs          []string        `json:"ips,omitempty"`
}

type wafHeaderRule struct {
	Name          string `json:"name"`
	ValueContains string `json:"value_contains"`
}

type rateLimitRule struct {
	Host       string  `json:"host,omitempty"`
	PathPrefix string  `json:"path_prefix,omitempty"`
	RPS        float64 `json:"rps"`
	Burst      float64 `json:"burst"`
}

type cacheInvalidation struct {
	ID          int64     `json:"id"`
	Host        string    `json:"host,omitempty"`
	Mode        string    `json:"mode"`
	Values      []string  `json:"values"`
	RequestedBy string    `json:"requested_by,omitempty"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

type cacheInvalidationEvent struct {
	ID     int64    `json:"id"`
	Host   string   `json:"host,omitempty"`
	Mode   string   `json:"mode"`
	Values []string `json:"values"`
}

type cachePrewarmJob struct {
	ID          int64     `json:"id"`
	Host        string    `json:"host,omitempty"`
	Paths       []string  `json:"paths"`
	RequestedBy string    `json:"requested_by,omitempty"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

type cachePrewarmEvent struct {
	ID    int64    `json:"id"`
	Host  string   `json:"host,omitempty"`
	Paths []string `json:"paths"`
}

type cacheInvalidationDelivery struct {
	InvalidationID int64     `json:"invalidation_id"`
	NodeID         string    `json:"node_id"`
	Status         string    `json:"status"`
	Error          string    `json:"error,omitempty"`
	DeliveredAt    time.Time `json:"delivered_at"`
}

type configChangedEvent struct {
	Resource  string    `json:"resource"`
	ID        int64     `json:"id"`
	ChangedAt time.Time `json:"changed_at"`
}

type edgeNode struct {
	NodeID       string    `json:"node_id"`
	Address      string    `json:"address"`
	Capabilities []string  `json:"capabilities"`
	Status       string    `json:"status"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type cdnOrigin struct {
	ID        int64             `json:"id"`
	Name      string            `json:"name"`
	BaseURL   string            `json:"base_url"`
	Headers   map[string]string `json:"headers"`
	Status    string            `json:"status"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

type cdnRoute struct {
	ID              int64               `json:"id"`
	Host            string              `json:"host"`
	PathPrefix      string              `json:"path_prefix"`
	OriginID        int64               `json:"origin_id"`
	OriginName      string              `json:"origin_name"`
	OriginBaseURL   string              `json:"origin_base_url"`
	CacheTTLSeconds *int                `json:"cache_ttl_seconds,omitempty"`
	CachePolicy     cachePolicy         `json:"cache_policy"`
	DeliveryRules   deliveryRulesConfig `json:"delivery_rules,omitempty"`
	WAFRules        wafRulesConfig      `json:"waf_rules,omitempty"`
	RateLimitRules  []rateLimitRule     `json:"rate_limit_rules,omitempty"`
	Status          string              `json:"status"`
	CreatedAt       time.Time           `json:"created_at"`
	UpdatedAt       time.Time           `json:"updated_at"`
}

type cdnDomain struct {
	ID          int64      `json:"id"`
	Host        string     `json:"host"`
	RouteID     *int64     `json:"route_id,omitempty"`
	TLSMode     string     `json:"tls_mode"`
	Status      string     `json:"status"`
	DNSTXTName  string     `json:"dns_txt_name,omitempty"`
	DNSTXTValue string     `json:"dns_txt_value,omitempty"`
	VerifiedAt  *time.Time `json:"verified_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type apiKeyRecord struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	Scopes    []string   `json:"scopes"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type apiKeyCreateResponse struct {
	Status string       `json:"status"`
	Key    string       `json:"key"`
	APIKey apiKeyRecord `json:"api_key"`
}

type authDecision int

const (
	authAuthorized authDecision = iota
	authMissing
	authForbidden
)

type tenantRecord struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type tenantUserRecord struct {
	ID        int64     `json:"id"`
	TenantID  int64     `json:"tenant_id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type billingAccountRecord struct {
	ID                 int64     `json:"id"`
	TenantID           int64     `json:"tenant_id"`
	Provider           string    `json:"provider"`
	ProviderCustomerID string    `json:"provider_customer_id,omitempty"`
	Plan               string    `json:"plan"`
	Status             string    `json:"status"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type cacheAnalyticsSnapshot struct {
	ID         int64                        `json:"id"`
	EdgeNodeID string                       `json:"edge_node_id,omitempty"`
	Host       string                       `json:"host,omitempty"`
	Cache      cacheAnalyticsSnapshotMetric `json:"cache"`
	ObservedAt time.Time                    `json:"observed_at"`
	CreatedAt  time.Time                    `json:"created_at"`
}

type cachePolicy struct {
	Mode                        string `json:"mode"`
	TTLSeconds                  *int   `json:"ttl_seconds,omitempty"`
	StaleWhileRevalidateSeconds *int   `json:"stale_while_revalidate_seconds,omitempty"`
}

type server struct {
	db                       *sql.DB
	events                   *nats.Conn
	apiKey                   string
	lookupTXT                func(context.Context, string) ([]string, error)
	domainVerificationBypass bool
	limiter                  *rateLimiter
	metrics                  *controlMetrics
	auditEnabled             bool
	otlpExporter             *cacheAnalyticsOTLPExporter
	warehouseSink            *cacheAnalyticsWarehouseSink
}

type cacheAnalyticsOTLPExporter struct {
	endpoint string
	headers  map[string]string
	timeout  time.Duration
	client   *http.Client
}

type cacheAnalyticsWarehouseSink struct {
	path string
	now  func() time.Time
	mu   sync.Mutex
}

type rateLimiter struct {
	enabled bool
	rps     float64
	burst   float64
	now     func() time.Time
	mu      sync.Mutex
	buckets map[string]*rateLimitBucket
}

type rateLimitBucket struct {
	tokens float64
	last   time.Time
}

type contextKey string

const requestIDContextKey contextKey = "request_id"

type accessLogResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

type corsConfig struct {
	enabled          bool
	allowAnyOrigin   bool
	allowedOrigins   map[string]struct{}
	allowedMethods   string
	allowedHeaders   string
	allowCredentials bool
	maxAge           string
}

type controlMetrics struct {
	mu                 sync.RWMutex
	rateLimited        uint64
	invalidations      map[string]uint64
	invalidationFailed uint64
}

func main() {
	if err := validateSecureConfig(); err != nil {
		log.Fatalf("secure config: %v", err)
	}

	port := env("CONTROL_PORT", "8081")
	db, err := openDB()
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	events, err := openNATS()
	if err != nil {
		log.Fatalf("connect nats: %v", err)
	}
	defer events.Close()

	app := &server{
		db:                       db,
		events:                   events,
		apiKey:                   env("ASTRACDN_API_KEY", ""),
		lookupTXT:                net.DefaultResolver.LookupTXT,
		domainVerificationBypass: strings.ToLower(env("CONTROL_DOMAIN_VERIFICATION_BYPASS", "false")) == "true",
		limiter:                  newRateLimiterFromEnv(),
		metrics:                  newControlMetrics(),
		auditEnabled:             envBool("CONTROL_AUDIT_LOG_ENABLED", true),
		otlpExporter:             newCacheAnalyticsOTLPExporterFromEnv(),
		warehouseSink:            newCacheAnalyticsWarehouseSinkFromEnv(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler("control"))
	mux.HandleFunc("/ready", app.readyHandler)
	mux.HandleFunc("/metrics", app.metricsHandler)
	mux.HandleFunc("/v1/origins", app.originsHandler)
	mux.HandleFunc("/v1/routes", app.routesHandler)
	mux.HandleFunc("/v1/domains", app.domainsHandler)
	mux.HandleFunc("/v1/domains/verify", app.verifyDomainHandler)
	mux.HandleFunc("/v1/api-keys", app.apiKeysHandler)
	mux.HandleFunc("/v1/api-keys/revoke", app.revokeAPIKeyHandler)
	mux.HandleFunc("/v1/tenants", app.tenantsHandler)
	mux.HandleFunc("/v1/rbac/users", app.tenantUsersHandler)
	mux.HandleFunc("/v1/billing/accounts", app.billingAccountsHandler)
	mux.HandleFunc("/v1/billing/webhooks", app.billingWebhooksHandler)
	mux.HandleFunc("/v1/billing/webhook-events", app.billingWebhookEventsHandler)
	mux.HandleFunc("/v1/audit-logs", app.auditLogsHandler)
	mux.HandleFunc("/v1/route-rule-versions", app.routeRuleVersionsHandler)
	mux.HandleFunc("/v1/analytics/cache-snapshots", app.cacheAnalyticsSnapshotsHandler)
	mux.HandleFunc("/v1/analytics/cache-snapshots/prometheus", app.cacheAnalyticsPrometheusHandler)
	mux.HandleFunc("/v1/edge/register", app.registerHandler)
	mux.HandleFunc("/v1/edge/nodes", app.listEdgeNodesHandler)
	mux.HandleFunc("/v1/edge/health", app.edgeHealthHandler)
	mux.HandleFunc("/v1/cache/invalidate", app.cacheInvalidationHandler)
	mux.HandleFunc("/v1/cache/prewarm", app.cachePrewarmHandler)
	mux.HandleFunc("/v1/cache/invalidation-deliveries", app.cacheInvalidationDeliveriesHandler)

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           observabilityMiddleware("control", corsMiddleware(mux)),
		ReadHeaderTimeout: envDuration("HTTP_READ_HEADER_TIMEOUT", 5*time.Second),
		ReadTimeout:       envDuration("HTTP_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:      envDuration("HTTP_WRITE_TIMEOUT", 30*time.Second),
		IdleTimeout:       envDuration("HTTP_IDLE_TIMEOUT", 60*time.Second),
	}

	log.Printf("control service listening on :%s", port)
	if err := listenAndShutdown(server, envDuration("HTTP_SHUTDOWN_TIMEOUT", 10*time.Second)); err != nil {
		log.Fatal(err)
	}
}

func healthHandler(service string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"service": service,
			"status":  "ok",
		})
	}
}

func listenAndShutdown(server *http.Server, shutdownTimeout time.Duration) error {
	errCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)

	select {
	case err := <-errCh:
		return err
	case sig := <-stop:
		log.Printf("received %s, shutting down", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return err
	}
	return <-errCh
}

func (s *server) readyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	checks := map[string]string{}
	status := http.StatusOK
	if s.db == nil {
		checks["postgres"] = "database client missing"
		status = http.StatusServiceUnavailable
	} else if err := s.db.PingContext(r.Context()); err != nil {
		checks["postgres"] = err.Error()
		status = http.StatusServiceUnavailable
	} else {
		checks["postgres"] = "ok"
	}
	if s.events == nil || !s.events.IsConnected() {
		checks["nats"] = "not connected"
		status = http.StatusServiceUnavailable
	} else {
		checks["nats"] = "ok"
	}

	ready := status == http.StatusOK
	writeJSON(w, status, map[string]any{
		"service": "control",
		"ready":   ready,
		"checks":  checks,
	})
}

func observabilityMiddleware(service string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if requestID == "" {
			requestID = newRequestID()
		}
		w.Header().Set("X-Request-ID", requestID)

		ctx := context.WithValue(r.Context(), requestIDContextKey, requestID)
		logger := &accessLogResponseWriter{ResponseWriter: w}
		next.ServeHTTP(logger, r.WithContext(ctx))
		if logger.status == 0 {
			logger.status = http.StatusOK
		}
		logAccess(service, requestID, r, logger.status, logger.bytes, time.Since(start))
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	config := newCORSConfigFromEnv()
	if !config.enabled {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed := writeCORSHeaders(w, r, config)
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			if !allowed {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func newCORSConfigFromEnv() corsConfig {
	origins := splitCSV(env("CORS_ALLOWED_ORIGINS", "http://localhost:3000"))
	allowedOrigins := make(map[string]struct{}, len(origins))
	allowAnyOrigin := false
	for _, origin := range origins {
		if origin == "*" {
			allowAnyOrigin = true
			continue
		}
		allowedOrigins[origin] = struct{}{}
	}
	return corsConfig{
		enabled:          strings.ToLower(env("CORS_ENABLED", "false")) == "true",
		allowAnyOrigin:   allowAnyOrigin,
		allowedOrigins:   allowedOrigins,
		allowedMethods:   env("CORS_ALLOWED_METHODS", "GET,POST,OPTIONS"),
		allowedHeaders:   env("CORS_ALLOWED_HEADERS", "Authorization,Content-Type,X-AstraCDN-API-Key,X-Request-ID"),
		allowCredentials: strings.ToLower(env("CORS_ALLOW_CREDENTIALS", "false")) == "true",
		maxAge:           env("CORS_MAX_AGE", "600"),
	}
}

func writeCORSHeaders(w http.ResponseWriter, r *http.Request, config corsConfig) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}

	if config.allowAnyOrigin {
		if config.allowCredentials {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
	} else {
		if _, ok := config.allowedOrigins[origin]; !ok {
			return false
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
	}

	w.Header().Set("Access-Control-Allow-Methods", config.allowedMethods)
	w.Header().Set("Access-Control-Allow-Headers", config.allowedHeaders)
	w.Header().Set("Access-Control-Max-Age", config.maxAge)
	w.Header().Set("Access-Control-Expose-Headers", "X-Request-ID")
	if config.allowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	return true
}

func (w *accessLogResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *accessLogResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(body)
	w.bytes += n
	return n, err
}

func (w *accessLogResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func newRequestID() string {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(id[:])
}

func requestIDFromContext(ctx context.Context) string {
	requestID, _ := ctx.Value(requestIDContextKey).(string)
	return requestID
}

func logAccess(service string, requestID string, r *http.Request, status int, bytesWritten int, duration time.Duration) {
	payload := map[string]any{
		"level":       "info",
		"event":       "http_request",
		"service":     service,
		"request_id":  requestID,
		"method":      r.Method,
		"path":        r.URL.Path,
		"status":      status,
		"bytes":       bytesWritten,
		"duration_ms": duration.Milliseconds(),
		"remote_addr": r.RemoteAddr,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		log.Printf("access log encode failed: %v", err)
		return
	}
	log.Println(string(raw))
}

func (s *server) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	invalidations, invalidationFailed := s.invalidationMetricsSnapshot()
	fmt.Fprintln(w, "# HELP astracdn_control_up Service availability")
	fmt.Fprintln(w, "# TYPE astracdn_control_up gauge")
	fmt.Fprintln(w, "astracdn_control_up 1")
	fmt.Fprintln(w, "# HELP astracdn_control_rate_limit_blocks_total Control requests rejected by rate limiting")
	fmt.Fprintln(w, "# TYPE astracdn_control_rate_limit_blocks_total counter")
	fmt.Fprintf(w, "astracdn_control_rate_limit_blocks_total %d\n", s.rateLimitBlocksSnapshot())
	fmt.Fprintln(w, "# HELP astracdn_control_cache_invalidations_total Control cache invalidations published by mode")
	fmt.Fprintln(w, "# TYPE astracdn_control_cache_invalidations_total counter")
	for _, mode := range sortedMetricKeys(invalidations) {
		fmt.Fprintf(w, "astracdn_control_cache_invalidations_total{mode=\"%s\"} %d\n", mode, invalidations[mode])
	}
	fmt.Fprintln(w, "# HELP astracdn_control_cache_invalidation_failures_total Control cache invalidations that failed to publish")
	fmt.Fprintln(w, "# TYPE astracdn_control_cache_invalidation_failures_total counter")
	fmt.Fprintf(w, "astracdn_control_cache_invalidation_failures_total %d\n", invalidationFailed)
}

func (s *server) originsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listOriginsHandler(w, r)
	case http.MethodPost:
		s.upsertOriginHandler(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) upsertOriginHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r, "control:write") {
		return
	}
	if !s.allowRequest(r) {
		s.recordRateLimitBlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	var req originRequest
	if !decodeJSONBody(w, r, &req, envInt64("HTTP_MAX_REQUEST_BODY_BYTES", 1048576)) {
		return
	}
	origin, err := s.upsertOrigin(r.Context(), req)
	if err != nil {
		if errors.Is(err, errInvalidOriginRequest) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("upsert origin: %v", err)
		http.Error(w, "failed to save origin", http.StatusInternalServerError)
		return
	}
	if err := s.publishConfigChanged("origin", origin.ID); err != nil {
		log.Printf("publish origin config change: %v", err)
	}
	s.recordAuditLog(r, "upsert", "origin", strconv.FormatInt(origin.ID, 10), map[string]any{
		"name": origin.Name,
	})

	writeJSON(w, http.StatusAccepted, map[string]any{
		"status": "accepted",
		"origin": origin,
	})
}

func (s *server) listOriginsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r, "control:read") {
		return
	}
	origins, err := s.listOrigins(r.Context())
	if err != nil {
		log.Printf("list origins: %v", err)
		http.Error(w, "failed to list origins", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"origins": origins,
	})
}

func (s *server) routesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listRoutesHandler(w, r)
	case http.MethodPost:
		s.upsertRouteHandler(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) upsertRouteHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r, "control:write") {
		return
	}
	if !s.allowRequest(r) {
		s.recordRateLimitBlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	var req routeRequest
	if !decodeJSONBody(w, r, &req, envInt64("HTTP_MAX_REQUEST_BODY_BYTES", 1048576)) {
		return
	}
	route, err := s.upsertRoute(r.Context(), req)
	if err != nil {
		if errors.Is(err, errInvalidRouteRequest) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("upsert route: %v", err)
		http.Error(w, "failed to save route", http.StatusInternalServerError)
		return
	}
	if err := s.publishConfigChanged("route", route.ID); err != nil {
		log.Printf("publish route config change: %v", err)
	}
	if err := s.recordRouteRuleVersion(r.Context(), route, auditActor(r), requestIDFromContext(r.Context())); err != nil {
		log.Printf("record route rule version: %v", err)
	}
	s.recordAuditLog(r, "upsert", "route", strconv.FormatInt(route.ID, 10), map[string]any{
		"host":        route.Host,
		"path_prefix": route.PathPrefix,
		"rule_fields": []string{"delivery_rules", "waf_rules", "rate_limit_rules"},
	})

	writeJSON(w, http.StatusAccepted, map[string]any{
		"status": "accepted",
		"route":  route,
	})
}

func (s *server) routeRuleVersionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r, "control:read") {
		return
	}

	req := routeRuleVersionListRequest{Limit: 100}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		req.Limit = parsed
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("route_id")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed <= 0 {
			http.Error(w, "invalid route_id", http.StatusBadRequest)
			return
		}
		req.RouteID = parsed
	}

	versions, err := s.listRouteRuleVersions(r.Context(), req)
	if err != nil {
		log.Printf("list route rule versions: %v", err)
		http.Error(w, "failed to list route rule versions", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"route_rule_versions": versions,
	})
}

func (s *server) listRoutesHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r, "control:read") {
		return
	}
	routes, err := s.listRoutes(r.Context())
	if err != nil {
		log.Printf("list routes: %v", err)
		http.Error(w, "failed to list routes", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"routes": routes,
	})
}

func (s *server) domainsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listDomainsHandler(w, r)
	case http.MethodPost:
		s.upsertDomainHandler(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) upsertDomainHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r, "control:write") {
		return
	}
	if !s.allowRequest(r) {
		s.recordRateLimitBlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	var req domainRequest
	if !decodeJSONBody(w, r, &req, envInt64("HTTP_MAX_REQUEST_BODY_BYTES", 1048576)) {
		return
	}
	domain, err := s.upsertDomain(r.Context(), req)
	if err != nil {
		if errors.Is(err, errInvalidDomainRequest) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("upsert domain: %v", err)
		http.Error(w, "failed to save domain", http.StatusInternalServerError)
		return
	}
	if err := s.publishConfigChanged("domain", domain.ID); err != nil {
		log.Printf("publish domain config change: %v", err)
	}
	s.recordAuditLog(r, "upsert", "domain", strconv.FormatInt(domain.ID, 10), map[string]any{
		"host": domain.Host,
	})

	writeJSON(w, http.StatusAccepted, map[string]any{
		"status": "accepted",
		"domain": domain,
	})
}

func (s *server) listDomainsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r, "control:read") {
		return
	}
	domains, err := s.listDomains(r.Context())
	if err != nil {
		log.Printf("list domains: %v", err)
		http.Error(w, "failed to list domains", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"domains": domains,
	})
}

func (s *server) verifyDomainHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r, "control:write") {
		return
	}
	if !s.allowRequest(r) {
		s.recordRateLimitBlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	var req domainVerificationRequest
	if !decodeJSONBody(w, r, &req, envInt64("HTTP_MAX_REQUEST_BODY_BYTES", 1048576)) {
		return
	}
	domain, verified, err := s.verifyDomain(r.Context(), req)
	if err != nil {
		if errors.Is(err, errInvalidDomainRequest) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "domain not found", http.StatusNotFound)
			return
		}
		log.Printf("verify domain: %v", err)
		http.Error(w, "failed to verify domain", http.StatusInternalServerError)
		return
	}
	if verified {
		if err := s.publishConfigChanged("domain", domain.ID); err != nil {
			log.Printf("publish domain config change: %v", err)
		}
		s.recordAuditLog(r, "verify", "domain", strconv.FormatInt(domain.ID, 10), map[string]any{
			"host":   domain.Host,
			"status": domain.Status,
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "verified",
			"domain": domain,
		})
		return
	}

	writeJSON(w, http.StatusConflict, map[string]any{
		"status": "pending_dns",
		"domain": domain,
		"expected_record": map[string]string{
			"type":  "TXT",
			"name":  domain.DNSTXTName,
			"value": domain.DNSTXTValue,
		},
	})
}

func (s *server) apiKeysHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listAPIKeysHandler(w, r)
	case http.MethodPost:
		s.createAPIKeyHandler(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) createAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r, "control:admin") {
		return
	}
	if !s.allowRequest(r) {
		s.recordRateLimitBlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	var req apiKeyCreateRequest
	if !decodeJSONBody(w, r, &req, envInt64("HTTP_MAX_REQUEST_BODY_BYTES", 1048576)) {
		return
	}
	response, err := s.createAPIKey(r.Context(), req)
	if err != nil {
		if errors.Is(err, errInvalidAPIKeyRequest) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("create api key: %v", err)
		http.Error(w, "failed to create api key", http.StatusInternalServerError)
		return
	}
	s.recordAuditLog(r, "create", "api_key", strconv.FormatInt(response.APIKey.ID, 10), map[string]any{
		"name": response.APIKey.Name,
	})
	writeJSON(w, http.StatusCreated, response)
}

func (s *server) listAPIKeysHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r, "control:admin") {
		return
	}
	keys, err := s.listAPIKeys(r.Context())
	if err != nil {
		log.Printf("list api keys: %v", err)
		http.Error(w, "failed to list api keys", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"api_keys": keys,
	})
}

func (s *server) auditLogsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r, "control:read") {
		return
	}

	req := auditLogListRequest{Limit: 100}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		req.Limit = parsed
	}
	req.Action = strings.TrimSpace(r.URL.Query().Get("action"))
	req.ResourceType = strings.TrimSpace(r.URL.Query().Get("resource_type"))

	logs, err := s.listAuditLogs(r.Context(), req)
	if err != nil {
		log.Printf("list audit logs: %v", err)
		http.Error(w, "failed to list audit logs", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"audit_logs": logs,
	})
}

func (s *server) revokeAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r, "control:admin") {
		return
	}
	if !s.allowRequest(r) {
		s.recordRateLimitBlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	var req apiKeyRevokeRequest
	if !decodeJSONBody(w, r, &req, envInt64("HTTP_MAX_REQUEST_BODY_BYTES", 1048576)) {
		return
	}
	key, err := s.revokeAPIKey(r.Context(), req)
	if err != nil {
		if errors.Is(err, errInvalidAPIKeyRequest) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "api key not found", http.StatusNotFound)
			return
		}
		log.Printf("revoke api key: %v", err)
		http.Error(w, "failed to revoke api key", http.StatusInternalServerError)
		return
	}
	s.recordAuditLog(r, "revoke", "api_key", strconv.FormatInt(key.ID, 10), map[string]any{
		"name": key.Name,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "revoked",
		"api_key": key,
	})
}

func (s *server) tenantsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listTenantsHandler(w, r)
	case http.MethodPost:
		s.createTenantHandler(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) createTenantHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r, "control:write") {
		return
	}
	if !s.allowRequest(r) {
		s.recordRateLimitBlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	var req tenantRequest
	if !decodeJSONBody(w, r, &req, envInt64("HTTP_MAX_REQUEST_BODY_BYTES", 1048576)) {
		return
	}
	tenant, err := s.upsertTenant(r.Context(), req)
	if err != nil {
		if errors.Is(err, errInvalidTenantRequest) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("upsert tenant: %v", err)
		http.Error(w, "failed to save tenant", http.StatusInternalServerError)
		return
	}
	s.recordAuditLog(r, "upsert", "tenant", strconv.FormatInt(tenant.ID, 10), map[string]any{
		"slug": tenant.Slug,
	})
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status": "accepted",
		"tenant": tenant,
	})
}

func (s *server) listTenantsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r, "control:read") {
		return
	}
	tenants, err := s.listTenants(r.Context())
	if err != nil {
		log.Printf("list tenants: %v", err)
		http.Error(w, "failed to list tenants", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": tenants})
}

func (s *server) tenantUsersHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listTenantUsersHandler(w, r)
	case http.MethodPost:
		s.upsertTenantUserHandler(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) upsertTenantUserHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r, "control:write") {
		return
	}
	if !s.allowRequest(r) {
		s.recordRateLimitBlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	var req tenantUserRequest
	if !decodeJSONBody(w, r, &req, envInt64("HTTP_MAX_REQUEST_BODY_BYTES", 1048576)) {
		return
	}
	user, err := s.upsertTenantUser(r.Context(), req)
	if err != nil {
		if errors.Is(err, errInvalidTenantUserRequest) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("upsert tenant user: %v", err)
		http.Error(w, "failed to save tenant user", http.StatusInternalServerError)
		return
	}
	s.recordAuditLog(r, "upsert", "tenant_user", strconv.FormatInt(user.ID, 10), map[string]any{
		"tenant_id": user.TenantID,
		"email":     user.Email,
		"role":      user.Role,
	})
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted", "user": user})
}

func (s *server) listTenantUsersHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r, "control:read") {
		return
	}
	tenantID, err := optionalPositiveInt64(r.URL.Query().Get("tenant_id"))
	if err != nil {
		http.Error(w, "invalid tenant_id", http.StatusBadRequest)
		return
	}
	users, err := s.listTenantUsers(r.Context(), tenantID)
	if err != nil {
		log.Printf("list tenant users: %v", err)
		http.Error(w, "failed to list tenant users", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *server) billingAccountsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listBillingAccountsHandler(w, r)
	case http.MethodPost:
		s.upsertBillingAccountHandler(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) upsertBillingAccountHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r, "control:write") {
		return
	}
	if !s.allowRequest(r) {
		s.recordRateLimitBlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	var req billingAccountRequest
	if !decodeJSONBody(w, r, &req, envInt64("HTTP_MAX_REQUEST_BODY_BYTES", 1048576)) {
		return
	}
	account, err := s.upsertBillingAccount(r.Context(), req)
	if err != nil {
		if errors.Is(err, errInvalidBillingAccountRequest) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("upsert billing account: %v", err)
		http.Error(w, "failed to save billing account", http.StatusInternalServerError)
		return
	}
	s.recordAuditLog(r, "upsert", "billing_account", strconv.FormatInt(account.ID, 10), map[string]any{
		"tenant_id": account.TenantID,
		"provider":  account.Provider,
		"plan":      account.Plan,
	})
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted", "billing_account": account})
}

func (s *server) listBillingAccountsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r, "control:read") {
		return
	}
	tenantID, err := optionalPositiveInt64(r.URL.Query().Get("tenant_id"))
	if err != nil {
		http.Error(w, "invalid tenant_id", http.StatusBadRequest)
		return
	}
	accounts, err := s.listBillingAccounts(r.Context(), tenantID)
	if err != nil {
		log.Printf("list billing accounts: %v", err)
		http.Error(w, "failed to list billing accounts", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"billing_accounts": accounts})
}

func (s *server) billingWebhooksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r, "control:write") {
		return
	}
	if !s.allowRequest(r) {
		s.recordRateLimitBlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	var req billingWebhookRequest
	if !decodeBillingWebhookBody(w, r, &req, envInt64("HTTP_MAX_REQUEST_BODY_BYTES", 1048576)) {
		return
	}
	result, err := s.applyBillingWebhook(r.Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, errInvalidBillingWebhookRequest):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, sql.ErrNoRows):
			http.Error(w, "billing account not found", http.StatusNotFound)
		default:
			log.Printf("apply billing webhook: %v", err)
			http.Error(w, "failed to apply billing webhook", http.StatusInternalServerError)
		}
		return
	}
	if result.Duplicate {
		writeJSON(w, http.StatusOK, map[string]any{"status": "duplicate", "billing_account": result.Account})
		return
	}
	s.recordAuditLog(r, "webhook", "billing_account", strconv.FormatInt(result.Account.ID, 10), map[string]any{
		"event_id":             strings.TrimSpace(req.EventID),
		"tenant_id":            result.Account.TenantID,
		"provider":             result.Account.Provider,
		"provider_customer_id": result.Account.ProviderCustomerID,
		"status":               result.Account.Status,
		"plan":                 result.Account.Plan,
	})
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted", "billing_account": result.Account})
}

func (s *server) billingWebhookEventsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r, "control:read") {
		return
	}

	req := billingWebhookEventListRequest{Limit: 100}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		req.Limit = parsed
	}
	req.Provider = strings.TrimSpace(r.URL.Query().Get("provider"))
	req.EventID = strings.TrimSpace(r.URL.Query().Get("event_id"))
	if raw := strings.TrimSpace(r.URL.Query().Get("billing_account_id")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed <= 0 {
			http.Error(w, "invalid billing_account_id", http.StatusBadRequest)
			return
		}
		req.BillingAccountID = parsed
	}

	events, err := s.listBillingWebhookEvents(r.Context(), req)
	if err != nil {
		log.Printf("list billing webhook events: %v", err)
		http.Error(w, "failed to list billing webhook events", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"billing_webhook_events": events,
	})
}

func (s *server) cacheAnalyticsSnapshotsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listCacheAnalyticsSnapshotsHandler(w, r)
	case http.MethodPost:
		s.createCacheAnalyticsSnapshotHandler(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) createCacheAnalyticsSnapshotHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r, "control:write") {
		return
	}
	if !s.allowRequest(r) {
		s.recordRateLimitBlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	var req cacheAnalyticsSnapshotRequest
	if !decodeJSONBody(w, r, &req, envInt64("HTTP_MAX_REQUEST_BODY_BYTES", 1048576)) {
		return
	}
	snapshot, err := s.createCacheAnalyticsSnapshot(r.Context(), req)
	if err != nil {
		if errors.Is(err, errInvalidCacheAnalyticsSnapshot) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("create cache analytics snapshot: %v", err)
		http.Error(w, "failed to create cache analytics snapshot", http.StatusInternalServerError)
		return
	}
	s.recordAuditLog(r, "create", "cache_analytics_snapshot", strconv.FormatInt(snapshot.ID, 10), map[string]any{
		"edge_node_id": snapshot.EdgeNodeID,
		"host":         snapshot.Host,
	})
	if err := s.exportCacheAnalyticsSnapshotOTLP(r.Context(), snapshot); err != nil {
		log.Printf("export cache analytics snapshot otlp: %v", err)
	}
	if err := s.exportCacheAnalyticsSnapshotWarehouse(snapshot); err != nil {
		log.Printf("export cache analytics snapshot warehouse: %v", err)
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":   "accepted",
		"snapshot": snapshot,
	})
}

func (s *server) listCacheAnalyticsSnapshotsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r, "control:read") {
		return
	}
	limit, ok := parsePositiveLimit(w, r, 100)
	if !ok {
		return
	}
	snapshots, err := s.listCacheAnalyticsSnapshots(r.Context(), limit)
	if err != nil {
		log.Printf("list cache analytics snapshots: %v", err)
		http.Error(w, "failed to list cache analytics snapshots", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"snapshots": snapshots,
	})
}

func (s *server) cacheAnalyticsPrometheusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r, "control:read") {
		return
	}
	limit, ok := parsePositiveLimit(w, r, 100)
	if !ok {
		return
	}
	snapshots, err := s.listCacheAnalyticsSnapshots(r.Context(), limit)
	if err != nil {
		log.Printf("export cache analytics prometheus: %v", err)
		http.Error(w, "failed to export cache analytics", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writeCacheAnalyticsPrometheus(w, snapshots)
}

func (s *server) registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r, "control:write") {
		return
	}
	if !s.allowRequest(r) {
		s.recordRateLimitBlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	var req registerRequest
	if !decodeJSONBody(w, r, &req, envInt64("HTTP_MAX_REQUEST_BODY_BYTES", 1048576)) {
		return
	}
	if req.NodeID == "" || req.Address == "" {
		http.Error(w, "node_id and address are required", http.StatusBadRequest)
		return
	}

	node, err := s.upsertEdgeNode(r.Context(), req)
	if err != nil {
		log.Printf("register edge node: %v", err)
		http.Error(w, "failed to register edge node", http.StatusInternalServerError)
		return
	}
	s.recordAuditLog(r, "register", "edge_node", node.NodeID, map[string]any{
		"address": node.Address,
	})

	writeJSON(w, http.StatusAccepted, map[string]any{
		"status": "accepted",
		"node":   node,
	})
}

func (s *server) listEdgeNodesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nodes, err := s.listEdgeNodes(r.Context())
	if err != nil {
		log.Printf("list edge nodes: %v", err)
		http.Error(w, "failed to list edge nodes", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": nodes,
	})
}

func (s *server) edgeHealthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r, "control:read") {
		return
	}
	health, err := s.listEdgeHealth(r.Context(), envDuration("EDGE_HEALTH_STALE_AFTER", 2*time.Minute))
	if err != nil {
		log.Printf("list edge health: %v", err)
		http.Error(w, "failed to list edge health", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"edges": health,
	})
}

func (s *server) cacheInvalidationHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r, "control:write") {
		return
	}
	if !s.allowRequest(r) {
		s.recordRateLimitBlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	var req cacheInvalidationRequest
	if !decodeJSONBody(w, r, &req, envInt64("HTTP_MAX_REQUEST_BODY_BYTES", 1048576)) {
		return
	}

	invalidation, err := s.createCacheInvalidation(r.Context(), req)
	if err != nil {
		if errors.Is(err, errInvalidInvalidationRequest) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("create cache invalidation: %v", err)
		http.Error(w, "failed to create cache invalidation", http.StatusInternalServerError)
		return
	}

	if err := s.publishCacheInvalidation(invalidation); err != nil {
		s.recordInvalidationFailure()
		log.Printf("publish cache invalidation: %v", err)
		http.Error(w, "failed to publish cache invalidation", http.StatusInternalServerError)
		return
	}
	s.recordInvalidation(invalidation.Mode)
	s.recordAuditLog(r, "create", "cache_invalidation", strconv.FormatInt(invalidation.ID, 10), map[string]any{
		"host": invalidation.Host,
		"mode": invalidation.Mode,
	})

	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":       "accepted",
		"invalidation": invalidation,
	})
}

func (s *server) cachePrewarmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r, "control:write") {
		return
	}
	if !s.allowRequest(r) {
		s.recordRateLimitBlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	var req cachePrewarmRequest
	if !decodeJSONBody(w, r, &req, envInt64("HTTP_MAX_REQUEST_BODY_BYTES", 1048576)) {
		return
	}
	job, err := s.createCachePrewarmJob(r.Context(), req)
	if err != nil {
		if errors.Is(err, errInvalidPrewarmRequest) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("create cache prewarm: %v", err)
		http.Error(w, "failed to create cache prewarm", http.StatusInternalServerError)
		return
	}
	if err := s.publishCachePrewarm(job); err != nil {
		log.Printf("publish cache prewarm: %v", err)
		http.Error(w, "failed to publish cache prewarm", http.StatusInternalServerError)
		return
	}
	s.recordAuditLog(r, "create", "cache_prewarm", strconv.FormatInt(job.ID, 10), map[string]any{
		"host":  job.Host,
		"paths": len(job.Paths),
	})
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":  "accepted",
		"prewarm": job,
	})
}

func (s *server) cacheInvalidationDeliveriesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.recordCacheInvalidationDeliveryHandler(w, r)
	case http.MethodGet:
		s.listCacheInvalidationDeliveriesHandler(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) recordCacheInvalidationDeliveryHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r, "control:write") {
		return
	}
	if !s.allowRequest(r) {
		s.recordRateLimitBlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	var req cacheInvalidationDeliveryRequest
	if !decodeJSONBody(w, r, &req, envInt64("HTTP_MAX_REQUEST_BODY_BYTES", 1048576)) {
		return
	}

	delivery, err := s.recordCacheInvalidationDelivery(r.Context(), req)
	if err != nil {
		if errors.Is(err, errInvalidInvalidationDeliveryRequest) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("record cache invalidation delivery: %v", err)
		http.Error(w, "failed to record cache invalidation delivery", http.StatusInternalServerError)
		return
	}
	s.recordAuditLog(r, "record", "cache_invalidation_delivery", strconv.FormatInt(delivery.InvalidationID, 10)+":"+delivery.NodeID, map[string]any{
		"status": delivery.Status,
	})

	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":   "accepted",
		"delivery": delivery,
	})
}

func (s *server) listCacheInvalidationDeliveriesHandler(w http.ResponseWriter, r *http.Request) {
	rawID := strings.TrimSpace(r.URL.Query().Get("invalidation_id"))
	if rawID == "" {
		http.Error(w, "invalidation_id is required", http.StatusBadRequest)
		return
	}
	invalidationID, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || invalidationID <= 0 {
		http.Error(w, "invalidation_id is required", http.StatusBadRequest)
		return
	}

	deliveries, err := s.listCacheInvalidationDeliveries(r.Context(), invalidationID)
	if err != nil {
		log.Printf("list cache invalidation deliveries: %v", err)
		http.Error(w, "failed to list cache invalidation deliveries", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"deliveries": deliveries,
	})
}

func (s *server) upsertEdgeNode(ctx context.Context, req registerRequest) (edgeNode, error) {
	capabilities, err := json.Marshal(req.Capabilities)
	if err != nil {
		return edgeNode{}, err
	}

	const query = `
		INSERT INTO edge_nodes (node_id, address, capabilities, status, last_seen_at, updated_at)
		VALUES ($1, $2, $3::jsonb, 'active', now(), now())
		ON CONFLICT (node_id) DO UPDATE SET
			address = EXCLUDED.address,
			capabilities = EXCLUDED.capabilities,
			status = 'active',
			last_seen_at = now(),
			updated_at = now()
		RETURNING node_id, address, capabilities, status, last_seen_at, created_at, updated_at`

	return scanEdgeNode(s.db.QueryRowContext(ctx, query, req.NodeID, req.Address, string(capabilities)))
}

func (s *server) listEdgeNodes(ctx context.Context) ([]edgeNode, error) {
	const query = `
		SELECT node_id, address, capabilities, status, last_seen_at, created_at, updated_at
		FROM edge_nodes
		ORDER BY node_id`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []edgeNode
	for rows.Next() {
		node, err := scanEdgeNode(rows)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if nodes == nil {
		nodes = []edgeNode{}
	}
	return nodes, nil
}

func (s *server) listEdgeHealth(ctx context.Context, staleAfter time.Duration) ([]edgeHealth, error) {
	if staleAfter <= 0 {
		staleAfter = 2 * time.Minute
	}
	const query = `
		SELECT n.node_id, n.address, n.capabilities, n.status, n.last_seen_at, n.created_at, n.updated_at,
			s.observed_at, COALESCE(s.cache_fill_latency, '{}'::jsonb)
		FROM edge_nodes n
		LEFT JOIN LATERAL (
			SELECT observed_at, cache_fill_latency
			FROM cache_analytics_snapshots
			WHERE edge_node_id = n.node_id
			ORDER BY observed_at DESC, id DESC
			LIMIT 1
		) s ON true
		ORDER BY n.node_id`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	now := time.Now().UTC()
	var out []edgeHealth
	for rows.Next() {
		var node edgeNode
		var rawCapabilities []byte
		var observedAt sql.NullTime
		var rawFill []byte
		if err := rows.Scan(
			&node.NodeID,
			&node.Address,
			&rawCapabilities,
			&node.Status,
			&node.LastSeenAt,
			&node.CreatedAt,
			&node.UpdatedAt,
			&observedAt,
			&rawFill,
		); err != nil {
			return nil, err
		}
		if len(rawCapabilities) > 0 {
			if err := json.Unmarshal(rawCapabilities, &node.Capabilities); err != nil {
				return nil, err
			}
		}
		if node.Capabilities == nil {
			node.Capabilities = []string{}
		}
		var fill cacheFillLatencyMetric
		if len(rawFill) > 0 {
			if err := json.Unmarshal(rawFill, &fill); err != nil {
				return nil, err
			}
		}
		secondsSinceSeen := int64(now.Sub(node.LastSeenAt.UTC()).Seconds())
		if secondsSinceSeen < 0 {
			secondsSinceSeen = 0
		}
		health := edgeHealth{
			Node:                 node,
			Healthy:              node.Status == "active" && time.Duration(secondsSinceSeen)*time.Second <= staleAfter,
			SecondsSinceLastSeen: secondsSinceSeen,
			CacheFillLatency:     fill,
		}
		if observedAt.Valid {
			observed := observedAt.Time
			health.LastCacheObservedAt = &observed
		}
		out = append(out, health)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []edgeHealth{}
	}
	return out, nil
}

var errInvalidOriginRequest = errors.New("name and http(s) base_url are required")

func (s *server) upsertOrigin(ctx context.Context, req originRequest) (cdnOrigin, error) {
	req.Name = strings.TrimSpace(req.Name)
	req.BaseURL = strings.TrimSpace(req.BaseURL)
	if req.Name == "" || !validOriginBaseURL(req.BaseURL) {
		return cdnOrigin{}, errInvalidOriginRequest
	}
	if req.Headers == nil {
		req.Headers = map[string]string{}
	}
	headers, err := json.Marshal(req.Headers)
	if err != nil {
		return cdnOrigin{}, err
	}

	const query = `
		INSERT INTO cdn_origins (name, base_url, headers, status, updated_at)
		VALUES ($1, $2, $3::jsonb, 'active', now())
		ON CONFLICT (name) DO UPDATE SET
			base_url = EXCLUDED.base_url,
			headers = EXCLUDED.headers,
			status = 'active',
			updated_at = now()
		RETURNING id, name, base_url, headers, status, created_at, updated_at`

	return scanOrigin(s.db.QueryRowContext(ctx, query, req.Name, req.BaseURL, string(headers)))
}

func (s *server) listOrigins(ctx context.Context) ([]cdnOrigin, error) {
	const query = `
		SELECT id, name, base_url, headers, status, created_at, updated_at
		FROM cdn_origins
		ORDER BY name`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var origins []cdnOrigin
	for rows.Next() {
		origin, err := scanOrigin(rows)
		if err != nil {
			return nil, err
		}
		origins = append(origins, origin)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if origins == nil {
		origins = []cdnOrigin{}
	}
	return origins, nil
}

func validOriginBaseURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return parsed.Host != "" && (parsed.Scheme == "http" || parsed.Scheme == "https")
}

var errInvalidRouteRequest = errors.New("host, path_prefix, and origin_id are required")

func (s *server) upsertRoute(ctx context.Context, req routeRequest) (cdnRoute, error) {
	req.Host = normalizeRouteHost(req.Host)
	req.PathPrefix = strings.TrimSpace(req.PathPrefix)
	if req.PathPrefix == "" {
		req.PathPrefix = "/"
	}
	if !validRouteHost(req.Host) || !validRoutePathPrefix(req.PathPrefix) || req.OriginID <= 0 {
		return cdnRoute{}, errInvalidRouteRequest
	}
	policy, err := normalizeCachePolicy(req.CacheTTLSeconds, req.CachePolicy)
	if err != nil {
		return cdnRoute{}, errInvalidRouteRequest
	}
	deliveryRules, err := normalizeDeliveryRules(req.DeliveryRules)
	if err != nil {
		return cdnRoute{}, errInvalidRouteRequest
	}
	rawDeliveryRules, err := json.Marshal(deliveryRules)
	if err != nil {
		return cdnRoute{}, err
	}
	wafRules, err := normalizeWAFRules(req.WAFRules)
	if err != nil {
		return cdnRoute{}, errInvalidRouteRequest
	}
	rawWAFRules, err := json.Marshal(wafRules)
	if err != nil {
		return cdnRoute{}, err
	}
	rateLimitRules, err := normalizeRateLimitRules(req.RateLimitRules, req.Host, req.PathPrefix)
	if err != nil {
		return cdnRoute{}, errInvalidRouteRequest
	}
	rawRateLimitRules, err := json.Marshal(rateLimitRules)
	if err != nil {
		return cdnRoute{}, err
	}

	var cacheTTL sql.NullInt64
	if policy.TTLSeconds != nil {
		cacheTTL = sql.NullInt64{Int64: int64(*policy.TTLSeconds), Valid: true}
	}
	var staleWhileRevalidate sql.NullInt64
	if policy.StaleWhileRevalidateSeconds != nil {
		staleWhileRevalidate = sql.NullInt64{Int64: int64(*policy.StaleWhileRevalidateSeconds), Valid: true}
	}

	const query = `
		WITH upserted AS (
			INSERT INTO cdn_routes (host, path_prefix, origin_id, cache_mode, cache_ttl_seconds, stale_while_revalidate_seconds, delivery_rules, waf_rules, rate_limit_rules, status, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', now())
			ON CONFLICT (host, path_prefix) DO UPDATE SET
				origin_id = EXCLUDED.origin_id,
				cache_mode = EXCLUDED.cache_mode,
				cache_ttl_seconds = EXCLUDED.cache_ttl_seconds,
				stale_while_revalidate_seconds = EXCLUDED.stale_while_revalidate_seconds,
				delivery_rules = EXCLUDED.delivery_rules,
				waf_rules = EXCLUDED.waf_rules,
				rate_limit_rules = EXCLUDED.rate_limit_rules,
				status = 'active',
				updated_at = now()
			RETURNING id, host, path_prefix, origin_id, cache_mode, cache_ttl_seconds, stale_while_revalidate_seconds, delivery_rules, waf_rules, rate_limit_rules, status, created_at, updated_at
		)
		SELECT r.id, r.host, r.path_prefix, r.origin_id, o.name, o.base_url,
			r.cache_mode, r.cache_ttl_seconds, r.stale_while_revalidate_seconds, r.delivery_rules, r.waf_rules, r.rate_limit_rules, r.status, r.created_at, r.updated_at
		FROM upserted r
		JOIN cdn_origins o ON o.id = r.origin_id`

	return scanRoute(s.db.QueryRowContext(ctx, query, req.Host, req.PathPrefix, req.OriginID, policy.Mode, cacheTTL, staleWhileRevalidate, rawDeliveryRules, rawWAFRules, rawRateLimitRules))
}

func (s *server) listRoutes(ctx context.Context) ([]cdnRoute, error) {
	const query = `
		SELECT r.id, r.host, r.path_prefix, r.origin_id, o.name, o.base_url,
			r.cache_mode, r.cache_ttl_seconds, r.stale_while_revalidate_seconds, r.delivery_rules, r.waf_rules, r.rate_limit_rules, r.status, r.created_at, r.updated_at
		FROM cdn_routes r
		JOIN cdn_origins o ON o.id = r.origin_id
		ORDER BY r.host, length(r.path_prefix) DESC, r.path_prefix`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var routes []cdnRoute
	for rows.Next() {
		route, err := scanRoute(rows)
		if err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if routes == nil {
		routes = []cdnRoute{}
	}
	return routes, nil
}

var errInvalidDomainRequest = errors.New("host and valid tls_mode are required")

func (s *server) upsertDomain(ctx context.Context, req domainRequest) (cdnDomain, error) {
	req.Host = normalizeRouteHost(req.Host)
	req.TLSMode = normalizeTLSMode(req.TLSMode)
	if !validRouteHost(req.Host) || !validTLSMode(req.TLSMode) {
		return cdnDomain{}, errInvalidDomainRequest
	}

	var routeID sql.NullInt64
	if req.RouteID != nil {
		if *req.RouteID <= 0 {
			return cdnDomain{}, errInvalidDomainRequest
		}
		routeID = sql.NullInt64{Int64: *req.RouteID, Valid: true}
	}
	txtName := domainVerificationTXTName(req.Host)
	txtValue := domainVerificationTXTValue(req.Host)

	const query = `
		INSERT INTO cdn_domains (host, route_id, tls_mode, status, dns_txt_name, dns_txt_value, updated_at)
		VALUES ($1, $2, $3, 'pending_dns', $4, $5, now())
		ON CONFLICT (host) DO UPDATE SET
			route_id = EXCLUDED.route_id,
			tls_mode = EXCLUDED.tls_mode,
			status = CASE
				WHEN cdn_domains.status = 'active' THEN 'active'
				ELSE 'pending_dns'
			END,
			dns_txt_name = EXCLUDED.dns_txt_name,
			dns_txt_value = COALESCE(NULLIF(cdn_domains.dns_txt_value, ''), EXCLUDED.dns_txt_value),
			updated_at = now()
		RETURNING id, host, route_id, tls_mode, status, dns_txt_name, dns_txt_value, verified_at, created_at, updated_at`

	return scanDomain(s.db.QueryRowContext(ctx, query, req.Host, routeID, req.TLSMode, txtName, txtValue))
}

func (s *server) listDomains(ctx context.Context) ([]cdnDomain, error) {
	const query = `
		SELECT id, host, route_id, tls_mode, status, dns_txt_name, dns_txt_value, verified_at, created_at, updated_at
		FROM cdn_domains
		ORDER BY host`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []cdnDomain
	for rows.Next() {
		domain, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if domains == nil {
		domains = []cdnDomain{}
	}
	return domains, nil
}

func (s *server) verifyDomain(ctx context.Context, req domainVerificationRequest) (cdnDomain, bool, error) {
	host := normalizeRouteHost(req.Host)
	if !validRouteHost(host) {
		return cdnDomain{}, false, errInvalidDomainRequest
	}
	domain, err := s.getDomainByHost(ctx, host)
	if err != nil {
		return cdnDomain{}, false, err
	}

	if s.domainVerificationBypass {
		domain, err = s.markDomainVerified(ctx, host)
		return domain, true, err
	}

	lookupTXT := s.lookupTXT
	if lookupTXT == nil {
		lookupTXT = net.DefaultResolver.LookupTXT
	}
	records, lookupErr := lookupTXT(ctx, domain.DNSTXTName)
	verified := lookupErr == nil && txtRecordsContain(records, domain.DNSTXTValue)
	if !verified {
		domain, err = s.updateDomainVerificationStatus(ctx, host, "failed")
		return domain, false, err
	}
	domain, err = s.markDomainVerified(ctx, host)
	return domain, true, err
}

func (s *server) getDomainByHost(ctx context.Context, host string) (cdnDomain, error) {
	const query = `
		SELECT id, host, route_id, tls_mode, status, dns_txt_name, dns_txt_value, verified_at, created_at, updated_at
		FROM cdn_domains
		WHERE host = $1`
	return scanDomain(s.db.QueryRowContext(ctx, query, host))
}

func (s *server) markDomainVerified(ctx context.Context, host string) (cdnDomain, error) {
	const query = `
		UPDATE cdn_domains
		SET status = 'active', verified_at = now(), updated_at = now()
		WHERE host = $1
		RETURNING id, host, route_id, tls_mode, status, dns_txt_name, dns_txt_value, verified_at, created_at, updated_at`
	return scanDomain(s.db.QueryRowContext(ctx, query, host))
}

func (s *server) updateDomainVerificationStatus(ctx context.Context, host string, status string) (cdnDomain, error) {
	const query = `
		UPDATE cdn_domains
		SET status = $2, updated_at = now()
		WHERE host = $1
		RETURNING id, host, route_id, tls_mode, status, dns_txt_name, dns_txt_value, verified_at, created_at, updated_at`
	return scanDomain(s.db.QueryRowContext(ctx, query, host, status))
}

func normalizeTLSMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return "managed"
	}
	return mode
}

func validTLSMode(mode string) bool {
	switch mode {
	case "off", "manual", "managed":
		return true
	default:
		return false
	}
}

func domainVerificationTXTName(host string) string {
	return "_astra-cdn." + normalizeRouteHost(host)
}

func domainVerificationTXTValue(host string) string {
	sum := sha256.Sum256([]byte("astra-cdn-domain:" + normalizeRouteHost(host)))
	return "astra-cdn-verify=" + hex.EncodeToString(sum[:])[:32]
}

func txtRecordsContain(records []string, expected string) bool {
	for _, record := range records {
		if strings.TrimSpace(record) == expected {
			return true
		}
	}
	return false
}

var errInvalidAPIKeyRequest = errors.New("name or valid id is required")

func (s *server) createAPIKey(ctx context.Context, req apiKeyCreateRequest) (apiKeyCreateResponse, error) {
	req.Name = strings.TrimSpace(req.Name)
	req.Scopes = normalizeScopes(req.Scopes)
	if req.Name == "" {
		return apiKeyCreateResponse{}, errInvalidAPIKeyRequest
	}
	key, err := generateAPIKey()
	if err != nil {
		return apiKeyCreateResponse{}, err
	}
	keyHash := apiKeyHash(key)
	scopesJSON, err := json.Marshal(req.Scopes)
	if err != nil {
		return apiKeyCreateResponse{}, err
	}

	const query = `
		INSERT INTO api_keys (key_hash, name, scopes)
		VALUES ($1, $2, ARRAY(SELECT jsonb_array_elements_text($3::jsonb)))
		RETURNING id, name, array_to_json(scopes)::jsonb, revoked_at, created_at`
	record, err := scanAPIKey(s.db.QueryRowContext(ctx, query, keyHash, req.Name, string(scopesJSON)))
	if err != nil {
		return apiKeyCreateResponse{}, err
	}
	return apiKeyCreateResponse{
		Status: "created",
		Key:    key,
		APIKey: record,
	}, nil
}

func (s *server) listAPIKeys(ctx context.Context) ([]apiKeyRecord, error) {
	const query = `
		SELECT id, name, array_to_json(scopes)::jsonb, revoked_at, created_at
		FROM api_keys
		ORDER BY created_at DESC, id DESC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []apiKeyRecord
	for rows.Next() {
		key, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if keys == nil {
		keys = []apiKeyRecord{}
	}
	return keys, nil
}

func (s *server) revokeAPIKey(ctx context.Context, req apiKeyRevokeRequest) (apiKeyRecord, error) {
	if req.ID <= 0 {
		return apiKeyRecord{}, errInvalidAPIKeyRequest
	}
	const query = `
		UPDATE api_keys
		SET revoked_at = COALESCE(revoked_at, now())
		WHERE id = $1
		RETURNING id, name, array_to_json(scopes)::jsonb, revoked_at, created_at`
	return scanAPIKey(s.db.QueryRowContext(ctx, query, req.ID))
}

var errInvalidTenantRequest = errors.New("valid tenant name and slug are required")
var errInvalidTenantUserRequest = errors.New("valid tenant user is required")
var errInvalidBillingAccountRequest = errors.New("valid billing account is required")
var errInvalidBillingWebhookRequest = errors.New("valid billing webhook is required")

func (s *server) upsertTenant(ctx context.Context, req tenantRequest) (tenantRecord, error) {
	req.Name = strings.TrimSpace(req.Name)
	req.Slug = normalizeSlug(req.Slug)
	req.Status = normalizeStatus(req.Status, "active")
	if req.Name == "" || req.Slug == "" || !validLifecycleStatus(req.Status) {
		return tenantRecord{}, errInvalidTenantRequest
	}
	const query = `
		INSERT INTO tenants (name, slug, status)
		VALUES ($1, $2, $3)
		ON CONFLICT (slug) DO UPDATE SET
			name = EXCLUDED.name,
			status = EXCLUDED.status,
			updated_at = now()
		RETURNING id, name, slug, status, created_at, updated_at`
	return scanTenant(s.db.QueryRowContext(ctx, query, req.Name, req.Slug, req.Status))
}

func (s *server) listTenants(ctx context.Context) ([]tenantRecord, error) {
	const query = `
		SELECT id, name, slug, status, created_at, updated_at
		FROM tenants
		ORDER BY created_at DESC, id DESC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tenants []tenantRecord
	for rows.Next() {
		tenant, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, tenant)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if tenants == nil {
		tenants = []tenantRecord{}
	}
	return tenants, nil
}

func (s *server) upsertTenantUser(ctx context.Context, req tenantUserRequest) (tenantUserRecord, error) {
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Role = normalizeRole(req.Role)
	req.Status = normalizeStatus(req.Status, "active")
	if req.TenantID <= 0 || req.Email == "" || !strings.Contains(req.Email, "@") || req.Role == "" || !validLifecycleStatus(req.Status) {
		return tenantUserRecord{}, errInvalidTenantUserRequest
	}
	const query = `
		INSERT INTO tenant_users (tenant_id, email, role, status)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, email) DO UPDATE SET
			role = EXCLUDED.role,
			status = EXCLUDED.status,
			updated_at = now()
		RETURNING id, tenant_id, email, role, status, created_at, updated_at`
	return scanTenantUser(s.db.QueryRowContext(ctx, query, req.TenantID, req.Email, req.Role, req.Status))
}

func (s *server) listTenantUsers(ctx context.Context, tenantID int64) ([]tenantUserRecord, error) {
	query := `
		SELECT id, tenant_id, email, role, status, created_at, updated_at
		FROM tenant_users`
	args := []any{}
	if tenantID > 0 {
		query += ` WHERE tenant_id = $1`
		args = append(args, tenantID)
	}
	query += ` ORDER BY created_at DESC, id DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []tenantUserRecord
	for rows.Next() {
		user, err := scanTenantUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if users == nil {
		users = []tenantUserRecord{}
	}
	return users, nil
}

func (s *server) upsertBillingAccount(ctx context.Context, req billingAccountRequest) (billingAccountRecord, error) {
	req.Provider = strings.ToLower(strings.TrimSpace(req.Provider))
	req.ProviderCustomerID = strings.TrimSpace(req.ProviderCustomerID)
	req.Plan = strings.ToLower(strings.TrimSpace(req.Plan))
	req.Status = normalizeStatus(req.Status, "trialing")
	if req.TenantID <= 0 || req.Provider == "" || req.Plan == "" || !validBillingStatus(req.Status) {
		return billingAccountRecord{}, errInvalidBillingAccountRequest
	}
	const query = `
		INSERT INTO billing_accounts (tenant_id, provider, provider_customer_id, plan, status)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id) DO UPDATE SET
			provider = EXCLUDED.provider,
			provider_customer_id = EXCLUDED.provider_customer_id,
			plan = EXCLUDED.plan,
			status = EXCLUDED.status,
			updated_at = now()
		RETURNING id, tenant_id, provider, provider_customer_id, plan, status, created_at, updated_at`
	return scanBillingAccount(s.db.QueryRowContext(ctx, query, req.TenantID, req.Provider, req.ProviderCustomerID, req.Plan, req.Status))
}

func (s *server) listBillingAccounts(ctx context.Context, tenantID int64) ([]billingAccountRecord, error) {
	query := `
		SELECT id, tenant_id, provider, provider_customer_id, plan, status, created_at, updated_at
		FROM billing_accounts`
	args := []any{}
	if tenantID > 0 {
		query += ` WHERE tenant_id = $1`
		args = append(args, tenantID)
	}
	query += ` ORDER BY created_at DESC, id DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var accounts []billingAccountRecord
	for rows.Next() {
		account, err := scanBillingAccount(rows)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if accounts == nil {
		accounts = []billingAccountRecord{}
	}
	return accounts, nil
}

func (s *server) applyBillingWebhook(ctx context.Context, req billingWebhookRequest) (billingWebhookResult, error) {
	req.EventID = strings.TrimSpace(req.EventID)
	req.Provider = strings.ToLower(strings.TrimSpace(req.Provider))
	req.ProviderCustomerID = strings.TrimSpace(req.ProviderCustomerID)
	req.Plan = strings.ToLower(strings.TrimSpace(req.Plan))
	req.Status = normalizeStatus(req.Status, "")
	if req.EventID == "" || req.Provider == "" || !validBillingStatus(req.Status) {
		return billingWebhookResult{}, errInvalidBillingWebhookRequest
	}
	if req.TenantID <= 0 && req.ProviderCustomerID == "" {
		return billingWebhookResult{}, errInvalidBillingWebhookRequest
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return billingWebhookResult{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return billingWebhookResult{}, err
	}
	committed := false
	defer func() {
		if !committed {
			if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
				log.Printf("billing webhook rollback failed provider=%s event_id=%s err=%v", req.Provider, req.EventID, err)
			}
		}
	}()

	var eventRowID int64
	insertEventQuery := `
		INSERT INTO billing_webhook_events (provider, event_id, payload)
		VALUES ($1, $2, $3::jsonb)
		ON CONFLICT (provider, event_id) DO NOTHING
		RETURNING id`
	if err := tx.QueryRowContext(ctx, insertEventQuery, req.Provider, req.EventID, string(payload)).Scan(&eventRowID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			account, err := billingWebhookAccountByEvent(ctx, tx, req.Provider, req.EventID)
			if err != nil {
				return billingWebhookResult{}, err
			}
			if err := tx.Commit(); err != nil {
				return billingWebhookResult{}, err
			}
			committed = true
			return billingWebhookResult{Account: account, Duplicate: true}, nil
		}
		return billingWebhookResult{}, err
	}
	const returning = `
		RETURNING id, tenant_id, provider, provider_customer_id, plan, status, created_at, updated_at`
	var account billingAccountRecord
	if req.TenantID > 0 {
		const query = `
			UPDATE billing_accounts
			SET status = $1,
				plan = CASE WHEN $2 = '' THEN plan ELSE $2 END,
				updated_at = now()
			WHERE tenant_id = $3 AND provider = $4` + returning
		account, err = scanBillingAccount(tx.QueryRowContext(ctx, query, req.Status, req.Plan, req.TenantID, req.Provider))
	} else {
		const query = `
			UPDATE billing_accounts
			SET status = $1,
				plan = CASE WHEN $2 = '' THEN plan ELSE $2 END,
				updated_at = now()
			WHERE provider = $3 AND provider_customer_id = $4` + returning
		account, err = scanBillingAccount(tx.QueryRowContext(ctx, query, req.Status, req.Plan, req.Provider, req.ProviderCustomerID))
	}
	if err != nil {
		return billingWebhookResult{}, err
	}
	updateEventQuery := `
		UPDATE billing_webhook_events
		SET billing_account_id = $1,
			status = 'applied',
			payload = $2::jsonb,
			processed_at = now()
		WHERE id = $3`
	if _, err := tx.ExecContext(ctx, updateEventQuery, account.ID, string(payload), eventRowID); err != nil {
		return billingWebhookResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return billingWebhookResult{}, err
	}
	committed = true
	return billingWebhookResult{Account: account}, nil
}

func billingWebhookAccountByEvent(ctx context.Context, tx *sql.Tx, provider string, eventID string) (billingAccountRecord, error) {
	const query = `
		SELECT ba.id, ba.tenant_id, ba.provider, ba.provider_customer_id, ba.plan, ba.status, ba.created_at, ba.updated_at
		FROM billing_webhook_events bwe
		JOIN billing_accounts ba ON ba.id = bwe.billing_account_id
		WHERE bwe.provider = $1 AND bwe.event_id = $2`
	return scanBillingAccount(tx.QueryRowContext(ctx, query, provider, eventID))
}

func (s *server) listBillingWebhookEvents(ctx context.Context, req billingWebhookEventListRequest) ([]billingWebhookEventRecord, error) {
	if req.Limit <= 0 {
		req.Limit = 100
	}
	if req.Limit > 1000 {
		req.Limit = 1000
	}
	req.Provider = strings.ToLower(strings.TrimSpace(req.Provider))
	req.EventID = strings.TrimSpace(req.EventID)

	query := `
		SELECT id, provider, event_id, billing_account_id, status, payload, processed_at, created_at
		FROM billing_webhook_events`
	var args []any
	var filters []string
	if req.Provider != "" {
		args = append(args, req.Provider)
		filters = append(filters, fmt.Sprintf("provider = $%d", len(args)))
	}
	if req.EventID != "" {
		args = append(args, req.EventID)
		filters = append(filters, fmt.Sprintf("event_id = $%d", len(args)))
	}
	if req.BillingAccountID > 0 {
		args = append(args, req.BillingAccountID)
		filters = append(filters, fmt.Sprintf("billing_account_id = $%d", len(args)))
	}
	if len(filters) > 0 {
		query += "\n\t\tWHERE " + strings.Join(filters, " AND ")
	}
	args = append(args, req.Limit)
	query += fmt.Sprintf("\n\t\tORDER BY processed_at DESC, id DESC\n\t\tLIMIT $%d", len(args))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []billingWebhookEventRecord
	for rows.Next() {
		event, err := scanBillingWebhookEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if events == nil {
		events = []billingWebhookEventRecord{}
	}
	return events, nil
}

var errInvalidCacheAnalyticsSnapshot = errors.New("valid cache analytics snapshot is required")

func (s *server) createCacheAnalyticsSnapshot(ctx context.Context, req cacheAnalyticsSnapshotRequest) (cacheAnalyticsSnapshot, error) {
	req.EdgeNodeID = strings.TrimSpace(req.EdgeNodeID)
	req.Host = normalizeRouteHost(req.Host)
	if req.Host != "" && !validRouteHost(req.Host) {
		return cacheAnalyticsSnapshot{}, errInvalidCacheAnalyticsSnapshot
	}
	if !validCacheAnalyticsTotals(req.Cache.Requests, req.Cache.Hits, req.Cache.Misses, req.Cache.HitRatio) {
		return cacheAnalyticsSnapshot{}, errInvalidCacheAnalyticsSnapshot
	}
	for key, metric := range req.Cache.ByHost {
		if normalizeRouteHost(key) == "" || !validCacheAnalyticsDimension(metric) {
			return cacheAnalyticsSnapshot{}, errInvalidCacheAnalyticsSnapshot
		}
	}
	for key, metric := range req.Cache.ByRoute {
		if strings.TrimSpace(key) == "" || !validCacheAnalyticsDimension(metric) {
			return cacheAnalyticsSnapshot{}, errInvalidCacheAnalyticsSnapshot
		}
	}
	if req.Cache.ByLayer == nil {
		req.Cache.ByLayer = map[string]cacheAnalyticsLayerMetric{}
	}
	if req.Cache.ByHost == nil {
		req.Cache.ByHost = map[string]cacheAnalyticsDimensionMetric{}
	}
	if req.Cache.ByRoute == nil {
		req.Cache.ByRoute = map[string]cacheAnalyticsDimensionMetric{}
	}
	byLayer, err := json.Marshal(req.Cache.ByLayer)
	if err != nil {
		return cacheAnalyticsSnapshot{}, err
	}
	byHost, err := json.Marshal(req.Cache.ByHost)
	if err != nil {
		return cacheAnalyticsSnapshot{}, err
	}
	byRoute, err := json.Marshal(req.Cache.ByRoute)
	if err != nil {
		return cacheAnalyticsSnapshot{}, err
	}
	fill, err := json.Marshal(req.Cache.Fill)
	if err != nil {
		return cacheAnalyticsSnapshot{}, err
	}
	observedAt := time.Now().UTC()
	if req.ObservedAt != nil {
		observedAt = req.ObservedAt.UTC()
	}

	const query = `
		INSERT INTO cache_analytics_snapshots (edge_node_id, host, requests, hits, misses, hit_ratio, by_layer, by_host, by_route, cache_fill_latency, observed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb, $11)
		RETURNING id, edge_node_id, host, requests, hits, misses, hit_ratio, by_layer, by_host, by_route, cache_fill_latency, observed_at, created_at`
	return scanCacheAnalyticsSnapshot(s.db.QueryRowContext(
		ctx,
		query,
		req.EdgeNodeID,
		req.Host,
		int64(req.Cache.Requests),
		int64(req.Cache.Hits),
		int64(req.Cache.Misses),
		req.Cache.HitRatio,
		string(byLayer),
		string(byHost),
		string(byRoute),
		string(fill),
		observedAt,
	))
}

func parsePositiveLimit(w http.ResponseWriter, r *http.Request, defaultLimit int) (int, bool) {
	limit := defaultLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return 0, false
		}
		limit = parsed
	}
	return limit, true
}

func (s *server) listCacheAnalyticsSnapshots(ctx context.Context, limit int) ([]cacheAnalyticsSnapshot, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	const query = `
		SELECT id, edge_node_id, host, requests, hits, misses, hit_ratio, by_layer, by_host, by_route, cache_fill_latency, observed_at, created_at
		FROM cache_analytics_snapshots
		ORDER BY observed_at DESC, id DESC
		LIMIT $1`
	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var snapshots []cacheAnalyticsSnapshot
	for rows.Next() {
		snapshot, err := scanCacheAnalyticsSnapshot(rows)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if snapshots == nil {
		snapshots = []cacheAnalyticsSnapshot{}
	}
	return snapshots, nil
}

func writeCacheAnalyticsPrometheus(w http.ResponseWriter, snapshots []cacheAnalyticsSnapshot) {
	fmt.Fprintln(w, "# HELP astracdn_control_cache_snapshot_observed_timestamp_seconds Persisted cache analytics snapshot observation time")
	fmt.Fprintln(w, "# TYPE astracdn_control_cache_snapshot_observed_timestamp_seconds gauge")
	fmt.Fprintln(w, "# HELP astracdn_control_cache_snapshot_requests Persisted cache analytics snapshot request count")
	fmt.Fprintln(w, "# TYPE astracdn_control_cache_snapshot_requests gauge")
	fmt.Fprintln(w, "# HELP astracdn_control_cache_snapshot_hits Persisted cache analytics snapshot hit count")
	fmt.Fprintln(w, "# TYPE astracdn_control_cache_snapshot_hits gauge")
	fmt.Fprintln(w, "# HELP astracdn_control_cache_snapshot_misses Persisted cache analytics snapshot miss count")
	fmt.Fprintln(w, "# TYPE astracdn_control_cache_snapshot_misses gauge")
	fmt.Fprintln(w, "# HELP astracdn_control_cache_snapshot_hit_ratio Persisted cache analytics snapshot hit ratio")
	fmt.Fprintln(w, "# TYPE astracdn_control_cache_snapshot_hit_ratio gauge")
	fmt.Fprintln(w, "# HELP astracdn_control_cache_snapshot_layer_requests Persisted cache analytics snapshot request count by cache layer")
	fmt.Fprintln(w, "# TYPE astracdn_control_cache_snapshot_layer_requests gauge")
	fmt.Fprintln(w, "# HELP astracdn_control_cache_snapshot_dimension_requests Persisted cache analytics snapshot request count by host or route dimension")
	fmt.Fprintln(w, "# TYPE astracdn_control_cache_snapshot_dimension_requests gauge")
	fmt.Fprintln(w, "# HELP astracdn_control_cache_snapshot_dimension_hit_ratio Persisted cache analytics snapshot hit ratio by host or route dimension")
	fmt.Fprintln(w, "# TYPE astracdn_control_cache_snapshot_dimension_hit_ratio gauge")
	fmt.Fprintln(w, "# HELP astracdn_control_cache_snapshot_cache_fill_latency_seconds Persisted cache-fill latency summary")
	fmt.Fprintln(w, "# TYPE astracdn_control_cache_snapshot_cache_fill_latency_seconds gauge")

	for _, snapshot := range snapshots {
		labels := cacheSnapshotPromLabels(snapshot)
		fmt.Fprintf(w, "astracdn_control_cache_snapshot_observed_timestamp_seconds{%s} %d\n", labels, snapshot.ObservedAt.Unix())
		fmt.Fprintf(w, "astracdn_control_cache_snapshot_requests{%s} %d\n", labels, snapshot.Cache.Requests)
		fmt.Fprintf(w, "astracdn_control_cache_snapshot_hits{%s} %d\n", labels, snapshot.Cache.Hits)
		fmt.Fprintf(w, "astracdn_control_cache_snapshot_misses{%s} %d\n", labels, snapshot.Cache.Misses)
		fmt.Fprintf(w, "astracdn_control_cache_snapshot_hit_ratio{%s} %.6f\n", labels, snapshot.Cache.HitRatio)

		for _, layer := range sortedKeys(snapshot.Cache.ByLayer) {
			metric := snapshot.Cache.ByLayer[layer]
			layerLabels := labels + fmt.Sprintf(`,layer="%s",result="%s"`, promLabelValue(layer), promLabelValue(metric.Result))
			fmt.Fprintf(w, "astracdn_control_cache_snapshot_layer_requests{%s} %d\n", layerLabels, metric.Requests)
		}

		writeCacheAnalyticsDimensionPrometheus(w, labels, "host", snapshot.Cache.ByHost)
		writeCacheAnalyticsDimensionPrometheus(w, labels, "route", snapshot.Cache.ByRoute)

		fmt.Fprintf(w, "astracdn_control_cache_snapshot_cache_fill_latency_seconds{%s,stat=\"count\"} %d\n", labels, snapshot.Cache.Fill.Count)
		fmt.Fprintf(w, "astracdn_control_cache_snapshot_cache_fill_latency_seconds{%s,stat=\"sum\"} %.6f\n", labels, snapshot.Cache.Fill.SumSeconds)
		fmt.Fprintf(w, "astracdn_control_cache_snapshot_cache_fill_latency_seconds{%s,stat=\"avg\"} %.6f\n", labels, snapshot.Cache.Fill.AvgSeconds)
		fmt.Fprintf(w, "astracdn_control_cache_snapshot_cache_fill_latency_seconds{%s,stat=\"max\"} %.6f\n", labels, snapshot.Cache.Fill.MaxSeconds)
	}
}

func writeCacheAnalyticsDimensionPrometheus(w http.ResponseWriter, baseLabels string, dimensionType string, dimensions map[string]cacheAnalyticsDimensionMetric) {
	for _, dimension := range sortedKeys(dimensions) {
		metric := dimensions[dimension]
		labels := baseLabels + fmt.Sprintf(`,dimension_type="%s",dimension="%s"`, promLabelValue(dimensionType), promLabelValue(dimension))
		fmt.Fprintf(w, "astracdn_control_cache_snapshot_dimension_requests{%s,result=\"all\"} %d\n", labels, metric.Requests)
		fmt.Fprintf(w, "astracdn_control_cache_snapshot_dimension_requests{%s,result=\"hit\"} %d\n", labels, metric.Hits)
		fmt.Fprintf(w, "astracdn_control_cache_snapshot_dimension_requests{%s,result=\"miss\"} %d\n", labels, metric.Misses)
		fmt.Fprintf(w, "astracdn_control_cache_snapshot_dimension_hit_ratio{%s} %.6f\n", labels, metric.HitRatio)
	}
}

func cacheSnapshotPromLabels(snapshot cacheAnalyticsSnapshot) string {
	return fmt.Sprintf(`snapshot_id="%d",edge_node_id="%s",host="%s"`,
		snapshot.ID,
		promLabelValue(snapshot.EdgeNodeID),
		promLabelValue(snapshot.Host),
	)
}

func promLabelValue(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return replacer.Replace(value)
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func newCacheAnalyticsOTLPExporterFromEnv() *cacheAnalyticsOTLPExporter {
	endpoint := strings.TrimSpace(env("CONTROL_OTLP_METRICS_ENDPOINT", ""))
	if endpoint == "" {
		return nil
	}
	timeout := envDuration("CONTROL_OTLP_EXPORT_TIMEOUT", 5*time.Second)
	return &cacheAnalyticsOTLPExporter{
		endpoint: endpoint,
		headers:  parseHeaderPairs(env("CONTROL_OTLP_HEADERS", "")),
		timeout:  timeout,
		client:   &http.Client{Timeout: timeout},
	}
}

func (s *server) exportCacheAnalyticsSnapshotOTLP(ctx context.Context, snapshot cacheAnalyticsSnapshot) error {
	if s == nil || s.otlpExporter == nil {
		return nil
	}
	return s.otlpExporter.exportSnapshot(ctx, snapshot)
}

func (e *cacheAnalyticsOTLPExporter) exportSnapshot(ctx context.Context, snapshot cacheAnalyticsSnapshot) error {
	if e == nil || strings.TrimSpace(e.endpoint) == "" {
		return nil
	}
	payload, err := json.Marshal(cacheAnalyticsSnapshotOTLPPayload(snapshot))
	if err != nil {
		return err
	}
	timeout := e.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range e.headers {
		req.Header.Set(key, value)
	}
	client := e.client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("otlp collector returned status %d", resp.StatusCode)
	}
	return nil
}

func cacheAnalyticsSnapshotOTLPPayload(snapshot cacheAnalyticsSnapshot) map[string]any {
	now := snapshot.ObservedAt
	attributes := []map[string]any{
		otlpStringAttribute("snapshot.id", strconv.FormatInt(snapshot.ID, 10)),
		otlpStringAttribute("edge.node_id", snapshot.EdgeNodeID),
		otlpStringAttribute("cdn.host", snapshot.Host),
	}
	dataPointAttrs := func(extra ...map[string]any) []map[string]any {
		out := make([]map[string]any, 0, len(attributes)+len(extra))
		out = append(out, attributes...)
		out = append(out, extra...)
		return out
	}

	metrics := []map[string]any{
		otlpIntGauge("astracdn.control.cache_snapshot.requests", "Persisted cache analytics snapshot request count", "1", snapshot.Cache.Requests, now, dataPointAttrs()),
		otlpIntGauge("astracdn.control.cache_snapshot.hits", "Persisted cache analytics snapshot hit count", "1", snapshot.Cache.Hits, now, dataPointAttrs()),
		otlpIntGauge("astracdn.control.cache_snapshot.misses", "Persisted cache analytics snapshot miss count", "1", snapshot.Cache.Misses, now, dataPointAttrs()),
		otlpDoubleGauge("astracdn.control.cache_snapshot.hit_ratio", "Persisted cache analytics snapshot hit ratio", "1", snapshot.Cache.HitRatio, now, dataPointAttrs()),
		otlpIntGauge("astracdn.control.cache_snapshot.cache_fill_latency.count", "Persisted cache-fill sample count", "1", snapshot.Cache.Fill.Count, now, dataPointAttrs()),
		otlpDoubleGauge("astracdn.control.cache_snapshot.cache_fill_latency.sum", "Persisted cache-fill latency sum", "s", snapshot.Cache.Fill.SumSeconds, now, dataPointAttrs()),
		otlpDoubleGauge("astracdn.control.cache_snapshot.cache_fill_latency.avg", "Persisted cache-fill latency average", "s", snapshot.Cache.Fill.AvgSeconds, now, dataPointAttrs()),
		otlpDoubleGauge("astracdn.control.cache_snapshot.cache_fill_latency.max", "Persisted cache-fill latency max", "s", snapshot.Cache.Fill.MaxSeconds, now, dataPointAttrs()),
	}
	for _, layer := range sortedKeys(snapshot.Cache.ByLayer) {
		metric := snapshot.Cache.ByLayer[layer]
		metrics = append(metrics, otlpIntGauge(
			"astracdn.control.cache_snapshot.layer.requests",
			"Persisted cache analytics snapshot request count by cache layer",
			"1",
			metric.Requests,
			now,
			dataPointAttrs(otlpStringAttribute("cache.layer", layer), otlpStringAttribute("cache.result", metric.Result)),
		))
	}
	for _, dimension := range sortedKeys(snapshot.Cache.ByHost) {
		metric := snapshot.Cache.ByHost[dimension]
		metrics = append(metrics, otlpDimensionGauges(now, dataPointAttrs, "host", dimension, metric)...)
	}
	for _, dimension := range sortedKeys(snapshot.Cache.ByRoute) {
		metric := snapshot.Cache.ByRoute[dimension]
		metrics = append(metrics, otlpDimensionGauges(now, dataPointAttrs, "route", dimension, metric)...)
	}

	return map[string]any{
		"resourceMetrics": []map[string]any{
			{
				"resource": map[string]any{
					"attributes": []map[string]any{
						otlpStringAttribute("service.name", "astra-cdn-control"),
					},
				},
				"scopeMetrics": []map[string]any{
					{
						"scope": map[string]any{
							"name":    "astra-cdn/control",
							"version": "0.1.0",
						},
						"metrics": metrics,
					},
				},
			},
		},
	}
}

func otlpDimensionGauges(observedAt time.Time, attrs func(...map[string]any) []map[string]any, dimensionType string, dimension string, metric cacheAnalyticsDimensionMetric) []map[string]any {
	return []map[string]any{
		otlpIntGauge("astracdn.control.cache_snapshot.dimension.requests", "Persisted cache analytics snapshot dimension request count", "1", metric.Requests, observedAt, attrs(otlpStringAttribute("cdn.dimension_type", dimensionType), otlpStringAttribute("cdn.dimension", dimension), otlpStringAttribute("cache.result", "all"))),
		otlpIntGauge("astracdn.control.cache_snapshot.dimension.requests", "Persisted cache analytics snapshot dimension hit count", "1", metric.Hits, observedAt, attrs(otlpStringAttribute("cdn.dimension_type", dimensionType), otlpStringAttribute("cdn.dimension", dimension), otlpStringAttribute("cache.result", "hit"))),
		otlpIntGauge("astracdn.control.cache_snapshot.dimension.requests", "Persisted cache analytics snapshot dimension miss count", "1", metric.Misses, observedAt, attrs(otlpStringAttribute("cdn.dimension_type", dimensionType), otlpStringAttribute("cdn.dimension", dimension), otlpStringAttribute("cache.result", "miss"))),
		otlpDoubleGauge("astracdn.control.cache_snapshot.dimension.hit_ratio", "Persisted cache analytics snapshot dimension hit ratio", "1", metric.HitRatio, observedAt, attrs(otlpStringAttribute("cdn.dimension_type", dimensionType), otlpStringAttribute("cdn.dimension", dimension))),
	}
}

func otlpIntGauge(name string, description string, unit string, value uint64, observedAt time.Time, attributes []map[string]any) map[string]any {
	return otlpGauge(name, description, unit, map[string]any{
		"asInt": strconv.FormatUint(value, 10),
	}, observedAt, attributes)
}

func otlpDoubleGauge(name string, description string, unit string, value float64, observedAt time.Time, attributes []map[string]any) map[string]any {
	return otlpGauge(name, description, unit, map[string]any{
		"asDouble": value,
	}, observedAt, attributes)
}

func otlpGauge(name string, description string, unit string, value map[string]any, observedAt time.Time, attributes []map[string]any) map[string]any {
	point := map[string]any{
		"timeUnixNano": strconv.FormatInt(observedAt.UnixNano(), 10),
		"attributes":   attributes,
	}
	for key, val := range value {
		point[key] = val
	}
	return map[string]any{
		"name":        name,
		"description": description,
		"unit":        unit,
		"gauge": map[string]any{
			"dataPoints": []map[string]any{point},
		},
	}
}

func otlpStringAttribute(key string, value string) map[string]any {
	return map[string]any{
		"key": key,
		"value": map[string]any{
			"stringValue": value,
		},
	}
}

func parseHeaderPairs(raw string) map[string]string {
	headers := map[string]string{}
	for _, part := range splitCSV(raw) {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			key, value, ok = strings.Cut(part, ":")
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if ok && key != "" && value != "" {
			headers[key] = value
		}
	}
	return headers
}

func newCacheAnalyticsWarehouseSinkFromEnv() *cacheAnalyticsWarehouseSink {
	path := strings.TrimSpace(env("CONTROL_WAREHOUSE_JSONL_PATH", ""))
	if path == "" {
		return nil
	}
	return &cacheAnalyticsWarehouseSink{
		path: path,
		now:  time.Now,
	}
}

func (s *server) exportCacheAnalyticsSnapshotWarehouse(snapshot cacheAnalyticsSnapshot) error {
	if s == nil || s.warehouseSink == nil {
		return nil
	}
	return s.warehouseSink.exportSnapshot(snapshot)
}

func (s *cacheAnalyticsWarehouseSink) exportSnapshot(snapshot cacheAnalyticsSnapshot) error {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return nil
	}
	record := cacheAnalyticsSnapshotWarehouseRecord(snapshot, s.exportedAt())
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if dir := filepath.Dir(s.path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(append(payload, '\n')); err != nil {
		return err
	}
	return nil
}

func (s *cacheAnalyticsWarehouseSink) exportedAt() time.Time {
	if s != nil && s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

func cacheAnalyticsSnapshotWarehouseRecord(snapshot cacheAnalyticsSnapshot, exportedAt time.Time) map[string]any {
	return map[string]any{
		"schema_version": "1",
		"record_type":    "cache_analytics_snapshot",
		"exported_at":    exportedAt,
		"snapshot": map[string]any{
			"id":           snapshot.ID,
			"edge_node_id": snapshot.EdgeNodeID,
			"host":         snapshot.Host,
			"observed_at":  snapshot.ObservedAt,
			"created_at":   snapshot.CreatedAt,
		},
		"cache": map[string]any{
			"requests":           snapshot.Cache.Requests,
			"hits":               snapshot.Cache.Hits,
			"misses":             snapshot.Cache.Misses,
			"hit_ratio":          snapshot.Cache.HitRatio,
			"by_layer":           snapshot.Cache.ByLayer,
			"by_host":            snapshot.Cache.ByHost,
			"by_route":           snapshot.Cache.ByRoute,
			"cache_fill_latency": snapshot.Cache.Fill,
		},
	}
}

func absFloat(value float64) float64 {
	if value < 0 {
		return -value
	}
	return value
}

func validCacheAnalyticsTotals(requests uint64, hits uint64, misses uint64, hitRatio float64) bool {
	if requests != hits+misses || hitRatio < 0 || hitRatio > 1 {
		return false
	}
	if requests == 0 {
		return hitRatio == 0
	}
	expected := float64(hits) / float64(requests)
	return absFloat(hitRatio-expected) <= 0.000001
}

func validCacheAnalyticsDimension(metric cacheAnalyticsDimensionMetric) bool {
	if !validCacheAnalyticsTotals(metric.Requests, metric.Hits, metric.Misses, metric.HitRatio) {
		return false
	}
	return metric.ByLayer != nil
}

func generateAPIKey() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "ak_" + hex.EncodeToString(raw[:]), nil
}

func apiKeyHash(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return hex.EncodeToString(sum[:])
}

func normalizeScopes(scopes []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
	}
	sort.Strings(normalized)
	return normalized
}

func normalizeSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if r == '-' || r == '_' || r == ' ' || r == '.' {
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func normalizeRole(role string) string {
	role = strings.ToLower(strings.TrimSpace(role))
	switch role {
	case "owner", "admin", "operator", "viewer", "billing":
		return role
	default:
		return ""
	}
}

func normalizeStatus(status string, fallback string) string {
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		return fallback
	}
	return status
}

func validLifecycleStatus(status string) bool {
	switch status {
	case "active", "suspended", "disabled":
		return true
	default:
		return false
	}
}

func validBillingStatus(status string) bool {
	switch status {
	case "trialing", "active", "past_due", "canceled", "disabled":
		return true
	default:
		return false
	}
}

func optionalPositiveInt64(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, errors.New("invalid positive integer")
	}
	return value, nil
}

func normalizeCachePolicy(legacyTTL *int, req *cachePolicyRequest) (cachePolicy, error) {
	policy := cachePolicy{Mode: "origin"}
	if legacyTTL != nil {
		policy.TTLSeconds = legacyTTL
	}
	if req != nil {
		if strings.TrimSpace(req.Mode) != "" {
			policy.Mode = strings.ToLower(strings.TrimSpace(req.Mode))
		}
		if req.TTLSeconds != nil {
			policy.TTLSeconds = req.TTLSeconds
		}
		if req.StaleWhileRevalidateSeconds != nil {
			policy.StaleWhileRevalidateSeconds = req.StaleWhileRevalidateSeconds
		}
	}

	switch policy.Mode {
	case "origin", "override", "bypass":
	default:
		return cachePolicy{}, errInvalidRouteRequest
	}
	if policy.TTLSeconds != nil && *policy.TTLSeconds < 0 {
		return cachePolicy{}, errInvalidRouteRequest
	}
	if policy.StaleWhileRevalidateSeconds != nil && *policy.StaleWhileRevalidateSeconds < 0 {
		return cachePolicy{}, errInvalidRouteRequest
	}
	if policy.Mode == "override" && (policy.TTLSeconds == nil || *policy.TTLSeconds == 0) {
		return cachePolicy{}, errInvalidRouteRequest
	}
	if policy.Mode == "bypass" {
		policy.TTLSeconds = nil
		policy.StaleWhileRevalidateSeconds = nil
	}
	return policy, nil
}

func normalizeDeliveryRules(req deliveryRulesConfig) (deliveryRulesConfig, error) {
	normalized := deliveryRulesConfig{}
	for _, rule := range req.SetHeaders {
		pathPrefix, err := normalizeDeliveryRulePathPrefix(rule.PathPrefix)
		if err != nil {
			return deliveryRulesConfig{}, err
		}
		name := http.CanonicalHeaderKey(strings.TrimSpace(rule.Name))
		value := strings.TrimSpace(rule.Value)
		if name == "" || value == "" || !validHeaderName(name) {
			return deliveryRulesConfig{}, errInvalidRouteRequest
		}
		normalized.SetHeaders = append(normalized.SetHeaders, deliveryHeaderSetRule{
			PathPrefix: pathPrefix,
			Name:       name,
			Value:      value,
		})
	}
	for _, rule := range req.RemoveHeaders {
		pathPrefix, err := normalizeDeliveryRulePathPrefix(rule.PathPrefix)
		if err != nil {
			return deliveryRulesConfig{}, err
		}
		name := http.CanonicalHeaderKey(strings.TrimSpace(rule.Name))
		if name == "" || !validHeaderName(name) {
			return deliveryRulesConfig{}, errInvalidRouteRequest
		}
		normalized.RemoveHeaders = append(normalized.RemoveHeaders, deliveryHeaderRemoveRule{
			PathPrefix: pathPrefix,
			Name:       name,
		})
	}
	for _, rule := range req.Redirects {
		pathPrefix, err := normalizeDeliveryRulePathPrefix(rule.PathPrefix)
		if err != nil {
			return deliveryRulesConfig{}, err
		}
		target := strings.TrimSpace(rule.Target)
		if target == "" || !validRedirectStatus(rule.Status) {
			return deliveryRulesConfig{}, errInvalidRouteRequest
		}
		normalized.Redirects = append(normalized.Redirects, deliveryRedirectRule{
			PathPrefix: pathPrefix,
			Target:     target,
			Status:     rule.Status,
		})
	}
	return normalized, nil
}

func normalizeDeliveryRulePathPrefix(prefix string) (string, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "*" {
		return "*", nil
	}
	if !validRoutePathPrefix(prefix) {
		return "", errInvalidRouteRequest
	}
	return prefix, nil
}

func normalizeWAFRules(req wafRulesConfig) (wafRulesConfig, error) {
	normalized := wafRulesConfig{}
	if req.Enabled != nil {
		enabled := *req.Enabled
		normalized.Enabled = &enabled
	}
	for _, method := range req.Methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" || strings.ContainsAny(method, " \t\r\n") {
			return wafRulesConfig{}, errInvalidRouteRequest
		}
		normalized.Methods = append(normalized.Methods, method)
	}
	for _, prefix := range req.PathPrefixes {
		pathPrefix, err := normalizeDeliveryRulePathPrefix(prefix)
		if err != nil {
			return wafRulesConfig{}, err
		}
		if pathPrefix == "*" {
			return wafRulesConfig{}, errInvalidRouteRequest
		}
		normalized.PathPrefixes = append(normalized.PathPrefixes, pathPrefix)
	}
	for _, rule := range req.Headers {
		name := http.CanonicalHeaderKey(strings.TrimSpace(rule.Name))
		value := strings.ToLower(strings.TrimSpace(rule.ValueContains))
		if name == "" || value == "" || !validHeaderName(name) {
			return wafRulesConfig{}, errInvalidRouteRequest
		}
		normalized.Headers = append(normalized.Headers, wafHeaderRule{
			Name:          name,
			ValueContains: value,
		})
	}
	for _, raw := range req.IPs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if ip := net.ParseIP(raw); ip != nil {
			normalized.IPs = append(normalized.IPs, ip.String())
			continue
		}
		if _, cidr, err := net.ParseCIDR(raw); err == nil {
			normalized.IPs = append(normalized.IPs, cidr.String())
			continue
		}
		return wafRulesConfig{}, errInvalidRouteRequest
	}
	return normalized, nil
}

func normalizeRateLimitRules(req []rateLimitRule, routeHost string, routePathPrefix string) ([]rateLimitRule, error) {
	normalized := make([]rateLimitRule, 0, len(req))
	defaultHost := normalizeRouteHost(routeHost)
	defaultPath := strings.TrimSpace(routePathPrefix)
	if defaultPath == "" {
		defaultPath = "/"
	}
	for _, rule := range req {
		host := normalizeRouteHost(rule.Host)
		if host == "" {
			host = defaultHost
		}
		if host == "" {
			host = "*"
		}
		if host != "*" && !validRouteHost(host) {
			return nil, errInvalidRouteRequest
		}
		pathPrefix := strings.TrimSpace(rule.PathPrefix)
		if pathPrefix == "" {
			pathPrefix = defaultPath
		}
		if pathPrefix != "*" && !validRoutePathPrefix(pathPrefix) {
			return nil, errInvalidRouteRequest
		}
		if rule.RPS <= 0 || rule.Burst <= 0 {
			return nil, errInvalidRouteRequest
		}
		normalized = append(normalized, rateLimitRule{
			Host:       host,
			PathPrefix: pathPrefix,
			RPS:        rule.RPS,
			Burst:      rule.Burst,
		})
	}
	return normalized, nil
}

func validHeaderName(name string) bool {
	for _, r := range name {
		if r > 127 || !httpgutsHeaderTokenRune(r) {
			return false
		}
	}
	return true
}

func httpgutsHeaderTokenRune(r rune) bool {
	switch {
	case r >= '0' && r <= '9':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= 'a' && r <= 'z':
		return true
	}
	switch r {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

func validRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func normalizeRouteHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	return strings.TrimSuffix(host, ".")
}

func validRouteHost(host string) bool {
	if host == "" || strings.Contains(host, "://") || strings.ContainsAny(host, "/ \t\r\n") {
		return false
	}
	if strings.HasPrefix(host, ".") || strings.Contains(host, "..") {
		return false
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		if h == "" || p == "" {
			return false
		}
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
		return true
	}
	return true
}

func validRoutePathPrefix(prefix string) bool {
	return strings.HasPrefix(prefix, "/") && !strings.ContainsAny(prefix, "?#")
}

var errInvalidInvalidationRequest = errors.New("provide exactly one of keys, prefixes, or tags")
var errInvalidInvalidationDeliveryRequest = errors.New("invalidation_id, node_id, and valid status are required")
var errInvalidPrewarmRequest = errors.New("host and at least one valid /edge/ path are required")

func (s *server) createCacheInvalidation(ctx context.Context, req cacheInvalidationRequest) (cacheInvalidation, error) {
	req.Host = normalizeRouteHost(req.Host)
	if req.Host != "" && (req.Host == "*" || !validRouteHost(req.Host)) {
		return cacheInvalidation{}, errInvalidInvalidationRequest
	}

	keys := normalizeInvalidationValues(req.Keys)
	prefixes := normalizeInvalidationValues(req.Prefixes)
	tags := normalizeSurrogateTags(req.Tags)
	hasKeys := len(keys) > 0
	hasPrefixes := len(prefixes) > 0
	hasTags := len(tags) > 0
	if boolCount(hasKeys, hasPrefixes, hasTags) != 1 {
		return cacheInvalidation{}, errInvalidInvalidationRequest
	}

	mode := "keys"
	values := keys
	if hasPrefixes {
		mode = "prefixes"
		values = prefixes
	}
	if hasTags {
		mode = "tags"
		values = tags
	}

	rawValues, err := json.Marshal(values)
	if err != nil {
		return cacheInvalidation{}, err
	}

	const query = `
		INSERT INTO cache_invalidations (host, mode, values, requested_by)
		VALUES (NULLIF($1, ''), $2, $3::jsonb, NULLIF($4, ''))
		RETURNING id, COALESCE(host, ''), mode, values, COALESCE(requested_by, ''), status, created_at`

	var invalidation cacheInvalidation
	var rawStoredValues []byte
	if err := s.db.QueryRowContext(ctx, query, req.Host, mode, string(rawValues), req.RequestedBy).Scan(
		&invalidation.ID,
		&invalidation.Host,
		&invalidation.Mode,
		&rawStoredValues,
		&invalidation.RequestedBy,
		&invalidation.Status,
		&invalidation.CreatedAt,
	); err != nil {
		return cacheInvalidation{}, err
	}

	if err := json.Unmarshal(rawStoredValues, &invalidation.Values); err != nil {
		return cacheInvalidation{}, err
	}
	return invalidation, nil
}

func normalizeInvalidationValues(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normalizeSurrogateTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if !validSurrogateTag(tag) {
			continue
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
	}
	return out
}

func validSurrogateTag(tag string) bool {
	if tag == "" || len(tag) > 128 {
		return false
	}
	for _, r := range tag {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		switch r {
		case '.', '_', ':', '-':
			continue
		default:
			return false
		}
	}
	return true
}

func boolCount(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}

func (s *server) createCachePrewarmJob(ctx context.Context, req cachePrewarmRequest) (cachePrewarmJob, error) {
	req.Host = normalizeRouteHost(req.Host)
	if req.Host != "" && !validRouteHost(req.Host) {
		return cachePrewarmJob{}, errInvalidPrewarmRequest
	}
	paths := normalizePrewarmPaths(req.Paths)
	if len(paths) == 0 {
		return cachePrewarmJob{}, errInvalidPrewarmRequest
	}
	rawPaths, err := json.Marshal(paths)
	if err != nil {
		return cachePrewarmJob{}, err
	}
	const query = `
		INSERT INTO cache_prewarm_jobs (host, paths, requested_by)
		VALUES (NULLIF($1, ''), $2::jsonb, NULLIF($3, ''))
		RETURNING id, COALESCE(host, ''), paths, COALESCE(requested_by, ''), status, created_at`
	var job cachePrewarmJob
	var storedPaths []byte
	if err := s.db.QueryRowContext(ctx, query, req.Host, string(rawPaths), strings.TrimSpace(req.RequestedBy)).Scan(
		&job.ID,
		&job.Host,
		&storedPaths,
		&job.RequestedBy,
		&job.Status,
		&job.CreatedAt,
	); err != nil {
		return cachePrewarmJob{}, err
	}
	if err := json.Unmarshal(storedPaths, &job.Paths); err != nil {
		return cachePrewarmJob{}, err
	}
	return job, nil
}

func normalizePrewarmPaths(paths []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" || strings.ContainsAny(path, " \t\r\n") {
			continue
		}
		if !strings.HasPrefix(path, "/edge/") {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		normalized = append(normalized, path)
	}
	return normalized
}

func (s *server) recordCacheInvalidationDelivery(ctx context.Context, req cacheInvalidationDeliveryRequest) (cacheInvalidationDelivery, error) {
	req.NodeID = strings.TrimSpace(req.NodeID)
	req.Status = strings.ToLower(strings.TrimSpace(req.Status))
	req.Error = strings.TrimSpace(req.Error)
	if req.InvalidationID <= 0 || req.NodeID == "" || (req.Status != "applied" && req.Status != "failed") {
		return cacheInvalidationDelivery{}, errInvalidInvalidationDeliveryRequest
	}
	if req.Status == "applied" {
		req.Error = ""
	}

	const query = `
		WITH delivery AS (
			INSERT INTO cache_invalidation_deliveries (invalidation_id, node_id, status, error_message, delivered_at)
			VALUES ($1, $2, $3, NULLIF($4, ''), now())
			ON CONFLICT (invalidation_id, node_id) DO UPDATE SET
				status = EXCLUDED.status,
				error_message = EXCLUDED.error_message,
				delivered_at = now()
			RETURNING invalidation_id, node_id, status, error_message, delivered_at
		), invalidation_status AS (
			UPDATE cache_invalidations
			SET status = CASE WHEN $3 = 'failed' THEN 'failed' ELSE 'delivered' END
			WHERE id = $1
		)
		SELECT invalidation_id, node_id, status, COALESCE(error_message, ''), delivered_at
		FROM delivery`

	var delivery cacheInvalidationDelivery
	if err := s.db.QueryRowContext(ctx, query, req.InvalidationID, req.NodeID, req.Status, req.Error).Scan(
		&delivery.InvalidationID,
		&delivery.NodeID,
		&delivery.Status,
		&delivery.Error,
		&delivery.DeliveredAt,
	); err != nil {
		return cacheInvalidationDelivery{}, err
	}
	return delivery, nil
}

func (s *server) listCacheInvalidationDeliveries(ctx context.Context, invalidationID int64) ([]cacheInvalidationDelivery, error) {
	const query = `
		SELECT invalidation_id, node_id, status, COALESCE(error_message, ''), delivered_at
		FROM cache_invalidation_deliveries
		WHERE invalidation_id = $1
		ORDER BY node_id`

	rows, err := s.db.QueryContext(ctx, query, invalidationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deliveries []cacheInvalidationDelivery
	for rows.Next() {
		var delivery cacheInvalidationDelivery
		if err := rows.Scan(
			&delivery.InvalidationID,
			&delivery.NodeID,
			&delivery.Status,
			&delivery.Error,
			&delivery.DeliveredAt,
		); err != nil {
			return nil, err
		}
		deliveries = append(deliveries, delivery)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if deliveries == nil {
		deliveries = []cacheInvalidationDelivery{}
	}
	return deliveries, nil
}

func (s *server) recordAuditLog(r *http.Request, action string, resourceType string, resourceID string, metadata map[string]any) {
	if s == nil || !s.auditEnabled || s.db == nil {
		return
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	rawMetadata, err := json.Marshal(metadata)
	if err != nil {
		log.Printf("audit log metadata encode failed action=%s resource=%s err=%v", action, resourceType, err)
		rawMetadata = []byte(`{}`)
	}

	const query = `
		INSERT INTO control_audit_logs (actor, action, resource_type, resource_id, request_id, remote_addr, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)`
	if _, err := s.db.ExecContext(
		r.Context(),
		query,
		auditActor(r),
		strings.TrimSpace(action),
		strings.TrimSpace(resourceType),
		strings.TrimSpace(resourceID),
		requestIDFromContext(r.Context()),
		clientIP(r),
		string(rawMetadata),
	); err != nil {
		log.Printf("audit log write failed action=%s resource=%s id=%s err=%v", action, resourceType, resourceID, err)
	}
}

func (s *server) listAuditLogs(ctx context.Context, req auditLogListRequest) ([]auditLogEntry, error) {
	if req.Limit <= 0 {
		req.Limit = 100
	}
	if req.Limit > 1000 {
		req.Limit = 1000
	}
	req.Action = strings.TrimSpace(req.Action)
	req.ResourceType = strings.TrimSpace(req.ResourceType)

	query := `
		SELECT id, actor, action, resource_type, resource_id, request_id, remote_addr, metadata, created_at
		FROM control_audit_logs`
	var args []any
	var filters []string
	if req.Action != "" {
		args = append(args, req.Action)
		filters = append(filters, fmt.Sprintf("action = $%d", len(args)))
	}
	if req.ResourceType != "" {
		args = append(args, req.ResourceType)
		filters = append(filters, fmt.Sprintf("resource_type = $%d", len(args)))
	}
	if len(filters) > 0 {
		query += "\n\t\tWHERE " + strings.Join(filters, " AND ")
	}
	args = append(args, req.Limit)
	query += fmt.Sprintf("\n\t\tORDER BY created_at DESC, id DESC\n\t\tLIMIT $%d", len(args))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []auditLogEntry
	for rows.Next() {
		entry, err := scanAuditLogEntry(rows)
		if err != nil {
			return nil, err
		}
		logs = append(logs, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if logs == nil {
		logs = []auditLogEntry{}
	}
	return logs, nil
}

func (s *server) recordRouteRuleVersion(ctx context.Context, route cdnRoute, changedBy string, requestID string) error {
	if s == nil || s.db == nil || route.ID <= 0 {
		return nil
	}
	rawDeliveryRules, err := json.Marshal(route.DeliveryRules)
	if err != nil {
		return err
	}
	rawWAFRules, err := json.Marshal(route.WAFRules)
	if err != nil {
		return err
	}
	rawRateLimitRules, err := json.Marshal(route.RateLimitRules)
	if err != nil {
		return err
	}

	const query = `
		INSERT INTO route_rule_versions (route_id, version, delivery_rules, waf_rules, rate_limit_rules, changed_by, request_id)
		VALUES (
			$1,
			COALESCE((SELECT max(version) + 1 FROM route_rule_versions WHERE route_id = $1), 1),
			$2::jsonb,
			$3::jsonb,
			$4::jsonb,
			NULLIF($5, ''),
			NULLIF($6, '')
		)`
	_, err = s.db.ExecContext(ctx, query, route.ID, rawDeliveryRules, rawWAFRules, rawRateLimitRules, changedBy, requestID)
	return err
}

func (s *server) listRouteRuleVersions(ctx context.Context, req routeRuleVersionListRequest) ([]routeRuleVersion, error) {
	if req.Limit <= 0 || req.Limit > 500 {
		req.Limit = 100
	}
	query := `
		SELECT id, route_id, version, delivery_rules, waf_rules, rate_limit_rules, changed_by, request_id, created_at
		FROM route_rule_versions`
	args := []any{}
	if req.RouteID > 0 {
		args = append(args, req.RouteID)
		query += ` WHERE route_id = $1`
	}
	args = append(args, req.Limit)
	query += fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d`, len(args))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []routeRuleVersion
	for rows.Next() {
		version, err := scanRouteRuleVersion(rows)
		if err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if versions == nil {
		versions = []routeRuleVersion{}
	}
	return versions, nil
}

func auditActor(r *http.Request) string {
	key := strings.TrimSpace(r.Header.Get("X-AstraCDN-API-Key"))
	if key == "" {
		key = strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	}
	if key == "" {
		return "anonymous"
	}
	hash := apiKeyHash(key)
	if len(hash) > 16 {
		hash = hash[:16]
	}
	return "api_key:" + hash
}

func (s *server) publishCacheInvalidation(invalidation cacheInvalidation) error {
	if s.events == nil {
		return nil
	}

	payload, err := json.Marshal(cacheInvalidationEvent{
		ID:     invalidation.ID,
		Host:   invalidation.Host,
		Mode:   invalidation.Mode,
		Values: invalidation.Values,
	})
	if err != nil {
		return err
	}
	if err := s.events.Publish("cache.invalidate", payload); err != nil {
		return err
	}
	return s.events.FlushTimeout(2 * time.Second)
}

func (s *server) publishCachePrewarm(job cachePrewarmJob) error {
	if s.events == nil {
		return nil
	}
	payload, err := json.Marshal(cachePrewarmEvent{
		ID:    job.ID,
		Host:  job.Host,
		Paths: job.Paths,
	})
	if err != nil {
		return err
	}
	if err := s.events.Publish("cache.prewarm", payload); err != nil {
		return err
	}
	return s.events.FlushTimeout(2 * time.Second)
}

func (s *server) publishConfigChanged(resource string, id int64) error {
	if s.events == nil {
		return nil
	}
	payload, err := json.Marshal(configChangedEvent{
		Resource:  resource,
		ID:        id,
		ChangedAt: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	if err := s.events.Publish("config.changed", payload); err != nil {
		return err
	}
	return s.events.FlushTimeout(2 * time.Second)
}

func newControlMetrics() *controlMetrics {
	return &controlMetrics{
		invalidations: make(map[string]uint64),
	}
}

func (s *server) recordRateLimitBlock() {
	if s.metrics == nil {
		return
	}
	s.metrics.mu.Lock()
	s.metrics.rateLimited++
	s.metrics.mu.Unlock()
}

func (s *server) rateLimitBlocksSnapshot() uint64 {
	if s.metrics == nil {
		return 0
	}
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()
	return s.metrics.rateLimited
}

func (s *server) recordInvalidation(mode string) {
	if s.metrics == nil {
		return
	}
	s.metrics.mu.Lock()
	s.metrics.invalidations[mode]++
	s.metrics.mu.Unlock()
}

func (s *server) recordInvalidationFailure() {
	if s.metrics == nil {
		return
	}
	s.metrics.mu.Lock()
	s.metrics.invalidationFailed++
	s.metrics.mu.Unlock()
}

func (s *server) invalidationMetricsSnapshot() (map[string]uint64, uint64) {
	if s.metrics == nil {
		return map[string]uint64{}, 0
	}
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()
	snapshot := make(map[string]uint64, len(s.metrics.invalidations))
	for mode, count := range s.metrics.invalidations {
		snapshot[mode] = count
	}
	return snapshot, s.metrics.invalidationFailed
}

func sortedMetricKeys(values map[string]uint64) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (s *server) requireAuth(w http.ResponseWriter, r *http.Request, requiredScopes ...string) bool {
	switch s.authorizeDecision(r, requiredScopes...) {
	case authAuthorized:
		return true
	case authForbidden:
		http.Error(w, "forbidden", http.StatusForbidden)
	default:
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
	return false
}

func (s *server) authorize(r *http.Request, requiredScopes ...string) bool {
	return s.authorizeDecision(r, requiredScopes...) == authAuthorized
}

func (s *server) authorizeDecision(r *http.Request, requiredScopes ...string) authDecision {
	if s.apiKey == "" && s.db == nil {
		return authAuthorized
	}
	key := requestAPIKey(r)
	if key == "" {
		return authMissing
	}
	if authorizeAPIKeyValue(key, s.apiKey) {
		return authAuthorized
	}
	if s.db == nil {
		return authMissing
	}
	record, ok, err := s.authorizePersistedAPIKey(r.Context(), key)
	if err != nil {
		log.Printf("api key lookup failed: %v", err)
		return authMissing
	}
	if !ok {
		return authMissing
	}
	if !apiKeyHasScopes(record.Scopes, requiredScopes...) {
		return authForbidden
	}
	return authAuthorized
}

func (s *server) allowRequest(r *http.Request) bool {
	if s.limiter == nil {
		return true
	}
	return s.limiter.allow(r)
}

func authorizeAPIKey(r *http.Request, expected string) bool {
	if expected == "" {
		return true
	}
	actual := requestAPIKey(r)
	if actual == "" {
		return false
	}
	return authorizeAPIKeyValue(actual, expected)
}

func authorizeAPIKeyValue(actual string, expected string) bool {
	if expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

func requestAPIKey(r *http.Request) string {
	actual := strings.TrimSpace(r.Header.Get("X-AstraCDN-API-Key"))
	if actual == "" {
		actual = strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	}
	return actual
}

func (s *server) authorizePersistedAPIKey(ctx context.Context, key string) (apiKeyRecord, bool, error) {
	const query = `
		SELECT id, name, array_to_json(scopes)::jsonb, revoked_at, created_at
		FROM api_keys
		WHERE key_hash = $1 AND revoked_at IS NULL
		LIMIT 1`
	record, err := scanAPIKey(s.db.QueryRowContext(ctx, query, apiKeyHash(key)))
	if errors.Is(err, sql.ErrNoRows) {
		return apiKeyRecord{}, false, nil
	}
	if err != nil {
		return apiKeyRecord{}, false, err
	}
	return record, true, nil
}

func apiKeyHasScopes(actual []string, required ...string) bool {
	if len(required) == 0 || len(actual) == 0 {
		return true
	}
	scopes := make(map[string]struct{}, len(actual))
	for _, scope := range normalizeScopes(actual) {
		scopes[scope] = struct{}{}
	}
	if _, ok := scopes["*"]; ok {
		return true
	}
	for _, requiredScope := range normalizeScopes(required) {
		if _, ok := scopes[requiredScope]; ok {
			continue
		}
		parts := strings.Split(requiredScope, ":")
		if len(parts) == 2 {
			if _, ok := scopes[parts[0]+":*"]; ok {
				continue
			}
		}
		return false
	}
	return true
}

func newRateLimiterFromEnv() *rateLimiter {
	return newRateLimiter(
		strings.ToLower(env("RATE_LIMIT_ENABLED", "true")) == "true",
		envFloat("RATE_LIMIT_RPS", 5),
		envFloat("RATE_LIMIT_BURST", 10),
	)
}

func newRateLimiter(enabled bool, rps, burst float64) *rateLimiter {
	if !enabled || rps <= 0 || burst <= 0 {
		return &rateLimiter{enabled: false}
	}
	return &rateLimiter{
		enabled: true,
		rps:     rps,
		burst:   burst,
		now:     time.Now,
		buckets: make(map[string]*rateLimitBucket),
	}
}

func (l *rateLimiter) allow(r *http.Request) bool {
	if l == nil || !l.enabled {
		return true
	}

	key := rateLimitKey(r)
	now := time.Now()
	if l.now != nil {
		now = l.now()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	bucket := l.buckets[key]
	if bucket == nil {
		bucket = &rateLimitBucket{tokens: l.burst, last: now}
		l.buckets[key] = bucket
	}

	elapsed := now.Sub(bucket.last).Seconds()
	if elapsed > 0 {
		bucket.tokens = min(l.burst, bucket.tokens+elapsed*l.rps)
		bucket.last = now
	}
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func rateLimitKey(r *http.Request) string {
	if key := r.Header.Get("X-AstraCDN-API-Key"); key != "" {
		return "api:" + key
	}
	if key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); key != "" {
		return "api:" + key
	}
	return "ip:" + clientIP(r)
}

func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if ip := strings.TrimSpace(strings.Split(forwarded, ",")[0]); ip != "" {
			return ip
		}
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func validateSecureConfig() error {
	if isLocalEnv() {
		return nil
	}
	if env("ASTRACDN_API_KEY", "") == "" || env("ASTRACDN_API_KEY", "") == "astracdn-local-dev-key" {
		return errors.New("ASTRACDN_API_KEY must be set to a non-default value outside local development")
	}
	if env("POSTGRES_PASSWORD", "") == "" || env("POSTGRES_PASSWORD", "") == "astracdn_local_password" {
		return errors.New("POSTGRES_PASSWORD must be set to a non-default value outside local development")
	}
	if strings.ToLower(env("RATE_LIMIT_ENABLED", "true")) != "true" {
		return errors.New("RATE_LIMIT_ENABLED must remain true outside local development")
	}
	if strings.ToLower(env("CONTROL_DOMAIN_VERIFICATION_BYPASS", "false")) == "true" {
		return errors.New("CONTROL_DOMAIN_VERIFICATION_BYPASS must remain false outside local development")
	}
	if strings.TrimSpace(env("CONTROL_BILLING_WEBHOOK_SECRET", "")) == "" {
		return errors.New("CONTROL_BILLING_WEBHOOK_SECRET must be set outside local development")
	}
	return nil
}

func isLocalEnv() bool {
	switch strings.ToLower(env("ASTRACDN_ENV", "local")) {
	case "local", "dev", "development", "test":
		return true
	default:
		return false
	}
}

type edgeNodeScanner interface {
	Scan(dest ...any) error
}

type originScanner interface {
	Scan(dest ...any) error
}

type routeScanner interface {
	Scan(dest ...any) error
}

type domainScanner interface {
	Scan(dest ...any) error
}

type apiKeyScanner interface {
	Scan(dest ...any) error
}

type tenantScanner interface {
	Scan(dest ...any) error
}

type tenantUserScanner interface {
	Scan(dest ...any) error
}

type billingAccountScanner interface {
	Scan(dest ...any) error
}

type billingWebhookEventScanner interface {
	Scan(dest ...any) error
}

type cacheAnalyticsSnapshotScanner interface {
	Scan(dest ...any) error
}

type auditLogScanner interface {
	Scan(dest ...any) error
}

type routeRuleVersionScanner interface {
	Scan(dest ...any) error
}

func scanEdgeNode(scanner edgeNodeScanner) (edgeNode, error) {
	var node edgeNode
	var rawCapabilities []byte
	if err := scanner.Scan(
		&node.NodeID,
		&node.Address,
		&rawCapabilities,
		&node.Status,
		&node.LastSeenAt,
		&node.CreatedAt,
		&node.UpdatedAt,
	); err != nil {
		return edgeNode{}, err
	}
	if len(rawCapabilities) > 0 {
		if err := json.Unmarshal(rawCapabilities, &node.Capabilities); err != nil {
			return edgeNode{}, err
		}
	}
	if node.Capabilities == nil {
		node.Capabilities = []string{}
	}
	return node, nil
}

func scanOrigin(scanner originScanner) (cdnOrigin, error) {
	var origin cdnOrigin
	var rawHeaders []byte
	if err := scanner.Scan(
		&origin.ID,
		&origin.Name,
		&origin.BaseURL,
		&rawHeaders,
		&origin.Status,
		&origin.CreatedAt,
		&origin.UpdatedAt,
	); err != nil {
		return cdnOrigin{}, err
	}
	if len(rawHeaders) > 0 {
		if err := json.Unmarshal(rawHeaders, &origin.Headers); err != nil {
			return cdnOrigin{}, err
		}
	}
	if origin.Headers == nil {
		origin.Headers = map[string]string{}
	}
	return origin, nil
}

func scanRoute(scanner routeScanner) (cdnRoute, error) {
	var route cdnRoute
	var cacheTTL sql.NullInt64
	var staleWhileRevalidate sql.NullInt64
	var rawDeliveryRules json.RawMessage
	var rawWAFRules json.RawMessage
	var rawRateLimitRules json.RawMessage
	if err := scanner.Scan(
		&route.ID,
		&route.Host,
		&route.PathPrefix,
		&route.OriginID,
		&route.OriginName,
		&route.OriginBaseURL,
		&route.CachePolicy.Mode,
		&cacheTTL,
		&staleWhileRevalidate,
		&rawDeliveryRules,
		&rawWAFRules,
		&rawRateLimitRules,
		&route.Status,
		&route.CreatedAt,
		&route.UpdatedAt,
	); err != nil {
		return cdnRoute{}, err
	}
	if cacheTTL.Valid {
		ttl := int(cacheTTL.Int64)
		route.CacheTTLSeconds = &ttl
		route.CachePolicy.TTLSeconds = &ttl
	}
	if staleWhileRevalidate.Valid {
		stale := int(staleWhileRevalidate.Int64)
		route.CachePolicy.StaleWhileRevalidateSeconds = &stale
	}
	if len(rawDeliveryRules) > 0 && string(rawDeliveryRules) != "null" {
		if err := json.Unmarshal(rawDeliveryRules, &route.DeliveryRules); err != nil {
			return cdnRoute{}, err
		}
	}
	if len(rawWAFRules) > 0 && string(rawWAFRules) != "null" {
		if err := json.Unmarshal(rawWAFRules, &route.WAFRules); err != nil {
			return cdnRoute{}, err
		}
	}
	if len(rawRateLimitRules) > 0 && string(rawRateLimitRules) != "null" {
		if err := json.Unmarshal(rawRateLimitRules, &route.RateLimitRules); err != nil {
			return cdnRoute{}, err
		}
	}
	if route.RateLimitRules == nil {
		route.RateLimitRules = []rateLimitRule{}
	}
	if route.CachePolicy.Mode == "" {
		route.CachePolicy.Mode = "origin"
	}
	return route, nil
}

func scanDomain(scanner domainScanner) (cdnDomain, error) {
	var domain cdnDomain
	var routeID sql.NullInt64
	var verifiedAt sql.NullTime
	if err := scanner.Scan(
		&domain.ID,
		&domain.Host,
		&routeID,
		&domain.TLSMode,
		&domain.Status,
		&domain.DNSTXTName,
		&domain.DNSTXTValue,
		&verifiedAt,
		&domain.CreatedAt,
		&domain.UpdatedAt,
	); err != nil {
		return cdnDomain{}, err
	}
	if routeID.Valid {
		id := routeID.Int64
		domain.RouteID = &id
	}
	if verifiedAt.Valid {
		verified := verifiedAt.Time
		domain.VerifiedAt = &verified
	}
	return domain, nil
}

func scanAPIKey(scanner apiKeyScanner) (apiKeyRecord, error) {
	var key apiKeyRecord
	var rawScopes []byte
	var revokedAt sql.NullTime
	if err := scanner.Scan(
		&key.ID,
		&key.Name,
		&rawScopes,
		&revokedAt,
		&key.CreatedAt,
	); err != nil {
		return apiKeyRecord{}, err
	}
	if len(rawScopes) > 0 {
		if err := json.Unmarshal(rawScopes, &key.Scopes); err != nil {
			return apiKeyRecord{}, err
		}
	}
	if key.Scopes == nil {
		key.Scopes = []string{}
	}
	if revokedAt.Valid {
		revoked := revokedAt.Time
		key.RevokedAt = &revoked
	}
	return key, nil
}

func scanTenant(scanner tenantScanner) (tenantRecord, error) {
	var tenant tenantRecord
	if err := scanner.Scan(
		&tenant.ID,
		&tenant.Name,
		&tenant.Slug,
		&tenant.Status,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	); err != nil {
		return tenantRecord{}, err
	}
	return tenant, nil
}

func scanTenantUser(scanner tenantUserScanner) (tenantUserRecord, error) {
	var user tenantUserRecord
	if err := scanner.Scan(
		&user.ID,
		&user.TenantID,
		&user.Email,
		&user.Role,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		return tenantUserRecord{}, err
	}
	return user, nil
}

func scanBillingAccount(scanner billingAccountScanner) (billingAccountRecord, error) {
	var account billingAccountRecord
	if err := scanner.Scan(
		&account.ID,
		&account.TenantID,
		&account.Provider,
		&account.ProviderCustomerID,
		&account.Plan,
		&account.Status,
		&account.CreatedAt,
		&account.UpdatedAt,
	); err != nil {
		return billingAccountRecord{}, err
	}
	return account, nil
}

func scanCacheAnalyticsSnapshot(scanner cacheAnalyticsSnapshotScanner) (cacheAnalyticsSnapshot, error) {
	var snapshot cacheAnalyticsSnapshot
	var requests int64
	var hits int64
	var misses int64
	var rawByLayer []byte
	var rawByHost []byte
	var rawByRoute []byte
	var rawFill []byte
	if err := scanner.Scan(
		&snapshot.ID,
		&snapshot.EdgeNodeID,
		&snapshot.Host,
		&requests,
		&hits,
		&misses,
		&snapshot.Cache.HitRatio,
		&rawByLayer,
		&rawByHost,
		&rawByRoute,
		&rawFill,
		&snapshot.ObservedAt,
		&snapshot.CreatedAt,
	); err != nil {
		return cacheAnalyticsSnapshot{}, err
	}
	snapshot.Cache.Requests = uint64(requests)
	snapshot.Cache.Hits = uint64(hits)
	snapshot.Cache.Misses = uint64(misses)
	if len(rawByLayer) > 0 {
		if err := json.Unmarshal(rawByLayer, &snapshot.Cache.ByLayer); err != nil {
			return cacheAnalyticsSnapshot{}, err
		}
	}
	if len(rawFill) > 0 {
		if err := json.Unmarshal(rawFill, &snapshot.Cache.Fill); err != nil {
			return cacheAnalyticsSnapshot{}, err
		}
	}
	if len(rawByHost) > 0 {
		if err := json.Unmarshal(rawByHost, &snapshot.Cache.ByHost); err != nil {
			return cacheAnalyticsSnapshot{}, err
		}
	}
	if len(rawByRoute) > 0 {
		if err := json.Unmarshal(rawByRoute, &snapshot.Cache.ByRoute); err != nil {
			return cacheAnalyticsSnapshot{}, err
		}
	}
	if snapshot.Cache.ByLayer == nil {
		snapshot.Cache.ByLayer = map[string]cacheAnalyticsLayerMetric{}
	}
	if snapshot.Cache.ByHost == nil {
		snapshot.Cache.ByHost = map[string]cacheAnalyticsDimensionMetric{}
	}
	if snapshot.Cache.ByRoute == nil {
		snapshot.Cache.ByRoute = map[string]cacheAnalyticsDimensionMetric{}
	}
	return snapshot, nil
}

func scanAuditLogEntry(scanner auditLogScanner) (auditLogEntry, error) {
	var entry auditLogEntry
	var rawMetadata []byte
	if err := scanner.Scan(
		&entry.ID,
		&entry.Actor,
		&entry.Action,
		&entry.ResourceType,
		&entry.ResourceID,
		&entry.RequestID,
		&entry.RemoteAddr,
		&rawMetadata,
		&entry.CreatedAt,
	); err != nil {
		return auditLogEntry{}, err
	}
	if len(rawMetadata) == 0 {
		rawMetadata = []byte(`{}`)
	}
	entry.Metadata = append(json.RawMessage(nil), rawMetadata...)
	return entry, nil
}

func scanBillingWebhookEvent(scanner billingWebhookEventScanner) (billingWebhookEventRecord, error) {
	var event billingWebhookEventRecord
	var billingAccountID sql.NullInt64
	var rawPayload []byte
	if err := scanner.Scan(
		&event.ID,
		&event.Provider,
		&event.EventID,
		&billingAccountID,
		&event.Status,
		&rawPayload,
		&event.ProcessedAt,
		&event.CreatedAt,
	); err != nil {
		return billingWebhookEventRecord{}, err
	}
	if billingAccountID.Valid {
		event.BillingAccountID = &billingAccountID.Int64
	}
	if len(rawPayload) == 0 {
		rawPayload = []byte(`{}`)
	}
	event.Payload = append(json.RawMessage(nil), rawPayload...)
	return event, nil
}

func scanRouteRuleVersion(scanner routeRuleVersionScanner) (routeRuleVersion, error) {
	var version routeRuleVersion
	var rawDeliveryRules json.RawMessage
	var rawWAFRules json.RawMessage
	var rawRateLimitRules json.RawMessage
	if err := scanner.Scan(
		&version.ID,
		&version.RouteID,
		&version.Version,
		&rawDeliveryRules,
		&rawWAFRules,
		&rawRateLimitRules,
		&version.ChangedBy,
		&version.RequestID,
		&version.CreatedAt,
	); err != nil {
		return routeRuleVersion{}, err
	}
	if len(rawDeliveryRules) > 0 && string(rawDeliveryRules) != "null" {
		if err := json.Unmarshal(rawDeliveryRules, &version.DeliveryRules); err != nil {
			return routeRuleVersion{}, err
		}
	}
	if len(rawWAFRules) > 0 && string(rawWAFRules) != "null" {
		if err := json.Unmarshal(rawWAFRules, &version.WAFRules); err != nil {
			return routeRuleVersion{}, err
		}
	}
	if len(rawRateLimitRules) > 0 && string(rawRateLimitRules) != "null" {
		if err := json.Unmarshal(rawRateLimitRules, &version.RateLimitRules); err != nil {
			return routeRuleVersion{}, err
		}
	}
	if version.RateLimitRules == nil {
		version.RateLimitRules = []rateLimitRule{}
	}
	return version, nil
}

func openDB() (*sql.DB, error) {
	db, err := sql.Open("pgx", postgresDSN())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pingWithRetry(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func openNATS() (*nats.Conn, error) {
	return nats.Connect(
		env("NATS_URL", nats.DefaultURL),
		nats.Name("astra-cdn-control"),
		nats.Timeout(2*time.Second),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(20),
		nats.ReconnectWait(500*time.Millisecond),
	)
}

func pingWithRetry(ctx context.Context, db *sql.DB) error {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	for {
		if err := db.PingContext(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), lastErr)
		case <-ticker.C:
		}
	}
}

func postgresDSN() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		env("POSTGRES_USER", "astracdn"),
		env("POSTGRES_PASSWORD", "astracdn_local_password"),
		env("POSTGRES_HOST", "localhost"),
		env("POSTGRES_PORT", "5432"),
		env("POSTGRES_DB", "astracdn"),
	)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, target any, limitBytes int64) bool {
	if limitBytes <= 0 {
		limitBytes = 1048576
	}
	if r.ContentLength > limitBytes {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return false
	}

	r.Body = http.MaxBytesReader(w, r.Body, limitBytes)
	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}

func decodeBillingWebhookBody(w http.ResponseWriter, r *http.Request, target *billingWebhookRequest, limitBytes int64) bool {
	raw, ok := readLimitedBody(w, r, limitBytes)
	if !ok {
		return false
	}
	secret := strings.TrimSpace(env("CONTROL_BILLING_WEBHOOK_SECRET", ""))
	if secret != "" && !validBillingWebhookSignature(r.Header.Get("X-AstraCDN-Billing-Signature"), raw, secret) {
		http.Error(w, "invalid billing webhook signature", http.StatusUnauthorized)
		return false
	}
	if err := json.Unmarshal(raw, target); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}

func readLimitedBody(w http.ResponseWriter, r *http.Request, limitBytes int64) ([]byte, bool) {
	if limitBytes <= 0 {
		limitBytes = 1048576
	}
	if r.ContentLength > limitBytes {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limitBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return nil, false
		}
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return nil, false
	}
	return raw, true
}

func validBillingWebhookSignature(rawHeader string, body []byte, secret string) bool {
	rawHeader = strings.TrimSpace(rawHeader)
	if rawHeader == "" || secret == "" {
		return false
	}
	signatureHex := strings.TrimSpace(strings.TrimPrefix(rawHeader, "sha256="))
	got, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	want := mac.Sum(nil)
	return hmac.Equal(got, want)
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

func envDuration(key string, fallback time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return value
}

func envBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return value
}

func envInt64(key string, fallback int64) int64 {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fallback
	}
	return value
}

func envFloat(key string, fallback float64) float64 {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return fallback
	}
	return value
}
