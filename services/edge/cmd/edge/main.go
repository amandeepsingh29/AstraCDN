package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
)

type edgeServer struct {
	originBase            *url.URL
	originShield          []*url.URL
	originFailover        []*url.URL
	controlBaseURL        string
	controlAPIKey         string
	nodeID                string
	validateDomain        bool
	analyticsPushInterval time.Duration
	healthPushInterval    time.Duration
	publicURL             string
	requestCoalescing     bool
	waf                   edgeWAFRules
	deliveryRules         edgeDeliveryRules
	ackAttempts           int
	ackBackoff            time.Duration
	originAttempts        int
	originBackoff         time.Duration
	client                *http.Client
	cache                 *memoryCache
	redis                 *redisCache
	routes                *routeConfigStore
	coalescer             *originCoalescer
	natsConn              *nats.Conn
	signer                signedURLValidator
	cookieSigner          signedCookieValidator
	limiter               *rateLimiter
	scopedLimiter         *edgeScopedRateLimiter
	metrics               *edgeMetrics
}

type signedURLValidator struct {
	enabled bool
	secret  string
	now     func() time.Time
}

type signedCookieValidator struct {
	enabled      bool
	secret       string
	cookieName   string
	pathPrefixes []string
	now          func() time.Time
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

type edgeScopedRateLimiter struct {
	enabled bool
	now     func() time.Time
	mu      sync.Mutex
	rules   []edgeRateLimitRule
	buckets map[string]*rateLimitBucket
}

type edgeRateLimitRule struct {
	host       string
	pathPrefix string
	rps        float64
	burst      float64
}

type contextKey string

const requestIDContextKey contextKey = "request_id"

const varyCacheKeySeparator = "::vary:"
const segmentCacheKeySeparator = "::segment:"
const shieldHopHeader = "X-AstraCDN-Shield-Hop"

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

type edgeMetrics struct {
	mu                 sync.RWMutex
	memory             uint64
	redis              uint64
	miss               uint64
	byHost             map[string]*edgeCacheTotals
	byRoute            map[string]*edgeCacheTotals
	rateLimited        uint64
	invalidations      map[string]uint64
	invalidationFailed uint64
	wafBlocked         uint64
	cacheFillCount     uint64
	cacheFillTotal     float64
	cacheFillMax       float64
}

type edgeCacheAnalyticsResponse struct {
	Cache edgeCacheAnalytics `json:"cache"`
}

type edgeCacheAnalytics struct {
	Requests uint64                                `json:"requests"`
	Hits     uint64                                `json:"hits"`
	Misses   uint64                                `json:"misses"`
	HitRatio float64                               `json:"hit_ratio"`
	ByLayer  map[string]edgeCacheCounter           `json:"by_layer"`
	ByHost   map[string]edgeCacheAnalyticsBreakout `json:"by_host"`
	ByRoute  map[string]edgeCacheAnalyticsBreakout `json:"by_route"`
	Fill     edgeCacheFillLatency                  `json:"cache_fill_latency"`
}

type edgeCacheCounter struct {
	Result   string `json:"result"`
	Requests uint64 `json:"requests"`
}

type edgeCacheTotals struct {
	memory uint64
	redis  uint64
	miss   uint64
}

type edgeCacheAnalyticsBreakout struct {
	Requests uint64                      `json:"requests"`
	Hits     uint64                      `json:"hits"`
	Misses   uint64                      `json:"misses"`
	HitRatio float64                     `json:"hit_ratio"`
	ByLayer  map[string]edgeCacheCounter `json:"by_layer"`
}

type edgeCacheFillLatency struct {
	Count      uint64  `json:"count"`
	SumSeconds float64 `json:"sum_seconds"`
	AvgSeconds float64 `json:"avg_seconds"`
	MaxSeconds float64 `json:"max_seconds"`
}

type edgeWAFRules struct {
	enabled      bool
	methods      map[string]struct{}
	pathPrefixes []string
	headers      []edgeWAFHeaderRule
	ips          []edgeWAFIPRule
}

type edgeWAFHeaderRule struct {
	name          string
	valueContains string
}

type edgeWAFIPRule struct {
	exact string
	cidr  *net.IPNet
}

type edgeWAFRulesConfig struct {
	Enabled      *bool                     `json:"enabled,omitempty"`
	Methods      []string                  `json:"methods,omitempty"`
	PathPrefixes []string                  `json:"path_prefixes,omitempty"`
	Headers      []edgeWAFHeaderRuleConfig `json:"headers,omitempty"`
	IPs          []string                  `json:"ips,omitempty"`
}

type edgeWAFHeaderRuleConfig struct {
	Name          string `json:"name"`
	ValueContains string `json:"value_contains"`
}

type edgeDeliveryRules struct {
	setHeaders    []edgeHeaderSetRule
	removeHeaders []edgeHeaderRemoveRule
	redirects     []edgeRedirectRule
}

type edgeHeaderSetRule struct {
	pathPrefix string
	name       string
	value      string
}

type edgeHeaderRemoveRule struct {
	pathPrefix string
	name       string
}

type edgeRedirectRule struct {
	pathPrefix string
	target     string
	status     int
}

type edgeDeliveryRulesConfig struct {
	SetHeaders    []edgeHeaderSetRuleConfig    `json:"set_headers,omitempty"`
	RemoveHeaders []edgeHeaderRemoveRuleConfig `json:"remove_headers,omitempty"`
	Redirects     []edgeRedirectRuleConfig     `json:"redirects,omitempty"`
}

type edgeHeaderSetRuleConfig struct {
	PathPrefix string `json:"path_prefix,omitempty"`
	Name       string `json:"name"`
	Value      string `json:"value"`
}

type edgeHeaderRemoveRuleConfig struct {
	PathPrefix string `json:"path_prefix,omitempty"`
	Name       string `json:"name"`
}

type edgeRedirectRuleConfig struct {
	PathPrefix string `json:"path_prefix,omitempty"`
	Target     string `json:"target"`
	Status     int    `json:"status"`
}

type edgeRateLimitRuleConfig struct {
	Host       string  `json:"host,omitempty"`
	PathPrefix string  `json:"path_prefix,omitempty"`
	RPS        float64 `json:"rps"`
	Burst      float64 `json:"burst"`
}

type cacheEntry struct {
	status       int
	header       http.Header
	body         []byte
	expiresAt    time.Time
	segmented    bool
	objectSize   int64
	segmentSize  int
	segmentCount int
}

type memoryCache struct {
	mu           sync.RWMutex
	entries      map[string]cacheEntry
	vary         map[string]map[string][]string
	surrogate    map[string]map[string]struct{}
	keySurrogate map[string]map[string]struct{}
}

type redisCache struct {
	client *redis.Client
}

type redisCacheEntry struct {
	Status       int         `json:"status"`
	Header       http.Header `json:"header"`
	Body         []byte      `json:"body"`
	ExpiresAt    time.Time   `json:"expires_at"`
	Segmented    bool        `json:"segmented,omitempty"`
	ObjectSize   int64       `json:"object_size,omitempty"`
	SegmentSize  int         `json:"segment_size,omitempty"`
	SegmentCount int         `json:"segment_count,omitempty"`
}

type cacheLookup struct {
	entry cacheEntry
	layer string
	key   string
	ok    bool
}

type originFetchResult struct {
	status     int
	header     http.Header
	body       []byte
	bodyReader io.ReadCloser
	originURL  string
	streamed   bool
}

type originFetchCall struct {
	done   chan struct{}
	result originFetchResult
	err    error
}

type originCoalescer struct {
	mu    sync.Mutex
	calls map[string]*originFetchCall
}

type byteRange struct {
	start int64
	end   int64
}

type edgeCachePolicy struct {
	Mode                        string `json:"mode"`
	TTLSeconds                  *int   `json:"ttl_seconds,omitempty"`
	StaleWhileRevalidateSeconds *int   `json:"stale_while_revalidate_seconds,omitempty"`
}

type edgeRouteConfig struct {
	Host           string                    `json:"host"`
	PathPrefix     string                    `json:"path_prefix"`
	OriginBaseURL  string                    `json:"origin_base_url"`
	CachePolicy    edgeCachePolicy           `json:"cache_policy"`
	DeliveryRules  edgeDeliveryRulesConfig   `json:"delivery_rules,omitempty"`
	WAFRules       edgeWAFRulesConfig        `json:"waf_rules,omitempty"`
	RateLimitRules []edgeRateLimitRuleConfig `json:"rate_limit_rules,omitempty"`
	originBase     *url.URL
	deliveryRules  edgeDeliveryRules
	wafRules       edgeWAFRules
	rateLimitRules []edgeRateLimitRule
}

type edgeRoutesResponse struct {
	Routes []edgeRouteConfig `json:"routes"`
}

type edgeDomainConfig struct {
	Host    string `json:"host"`
	TLSMode string `json:"tls_mode"`
	Status  string `json:"status"`
}

type edgeDomainsResponse struct {
	Domains []edgeDomainConfig `json:"domains"`
}

type requestRoute struct {
	originBases    []*url.URL
	policy         edgeCachePolicy
	waf            edgeWAFRules
	rules          edgeDeliveryRules
	rateLimitRules []edgeRateLimitRule
	host           string
	pathPrefix     string
	matched        bool
}

type routeConfigStore struct {
	baseURL         string
	apiKey          string
	client          *http.Client
	refreshInterval time.Duration

	mu          sync.RWMutex
	routes      []edgeRouteConfig
	domains     []edgeDomainConfig
	lastRefresh time.Time
	lastErr     error
}

type cacheInvalidationEvent struct {
	ID     int64    `json:"id"`
	Host   string   `json:"host,omitempty"`
	Mode   string   `json:"mode"`
	Values []string `json:"values"`
}

type cachePrewarmEvent struct {
	ID    int64    `json:"id"`
	Host  string   `json:"host,omitempty"`
	Paths []string `json:"paths"`
}

type cacheInvalidationDeliveryRequest struct {
	InvalidationID int64  `json:"invalidation_id"`
	NodeID         string `json:"node_id"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
}

type configChangedEvent struct {
	Resource  string    `json:"resource"`
	ID        int64     `json:"id"`
	ChangedAt time.Time `json:"changed_at"`
}

type cacheAnalyticsSnapshotRequest struct {
	EdgeNodeID string             `json:"edge_node_id,omitempty"`
	Cache      edgeCacheAnalytics `json:"cache"`
	ObservedAt time.Time          `json:"observed_at"`
}

type edgeRegistrationRequest struct {
	NodeID       string   `json:"node_id"`
	Address      string   `json:"address"`
	Capabilities []string `json:"capabilities"`
}

func main() {
	if err := validateSecureConfig(); err != nil {
		log.Fatalf("secure config: %v", err)
	}

	port := env("EDGE_PORT", "8080")
	originBase, err := url.Parse(env("ORIGIN_BASE_URL", "http://localhost:9000"))
	if err != nil {
		log.Fatalf("parse ORIGIN_BASE_URL: %v", err)
	}

	controlBaseURL := strings.TrimRight(strings.TrimSpace(env("CONTROL_BASE_URL", "")), "/")
	app := &edgeServer{
		originBase:            originBase,
		originShield:          parseOriginBaseURLs(env("EDGE_ORIGIN_SHIELD_URLS", "")),
		originFailover:        parseOriginBaseURLs(env("EDGE_ORIGIN_FAILOVER_URLS", "")),
		controlBaseURL:        controlBaseURL,
		controlAPIKey:         env("CONTROL_API_KEY", env("ASTRACDN_API_KEY", "")),
		nodeID:                env("EDGE_NODE_ID", ""),
		validateDomain:        strings.ToLower(env("EDGE_DOMAIN_VALIDATION_ENABLED", "false")) == "true",
		analyticsPushInterval: envDuration("EDGE_ANALYTICS_PUSH_INTERVAL", 0),
		healthPushInterval:    envDuration("EDGE_HEALTH_PUSH_INTERVAL", 60*time.Second),
		publicURL:             strings.TrimRight(env("EDGE_PUBLIC_URL", "http://edge:"+port), "/"),
		requestCoalescing:     envBool("EDGE_REQUEST_COALESCING_ENABLED", true),
		waf:                   newEdgeWAFRulesFromEnv(),
		deliveryRules:         newEdgeDeliveryRulesFromEnv(),
		ackAttempts:           envInt("EDGE_INVALIDATION_ACK_ATTEMPTS", 3),
		ackBackoff:            envDuration("EDGE_INVALIDATION_ACK_BACKOFF", 250*time.Millisecond),
		originAttempts:        max(1, envInt("EDGE_ORIGIN_ATTEMPTS", 1)),
		originBackoff:         envDuration("EDGE_ORIGIN_RETRY_BACKOFF", 100*time.Millisecond),
		client: &http.Client{
			Timeout: envDuration("EDGE_ORIGIN_TIMEOUT", 15*time.Second),
		},
		cache: newMemoryCache(),
		redis: newRedisCache(env("REDIS_ADDR", "localhost:6379")),
		routes: newRouteConfigStore(
			controlBaseURL,
			env("CONTROL_API_KEY", env("ASTRACDN_API_KEY", "")),
			envDuration("EDGE_CONFIG_REFRESH_INTERVAL", 15*time.Second),
		),
		coalescer: newOriginCoalescer(),
		signer: signedURLValidator{
			enabled: strings.ToLower(env("EDGE_SIGNING_ENABLED", "false")) == "true",
			secret:  env("EDGE_SIGNING_SECRET", ""),
			now:     time.Now,
		},
		cookieSigner: signedCookieValidator{
			enabled:      envBool("EDGE_SIGNED_COOKIE_ENABLED", false),
			secret:       env("EDGE_SIGNING_SECRET", ""),
			cookieName:   env("EDGE_SIGNED_COOKIE_NAME", "AstraCDN-Signature"),
			pathPrefixes: splitCSV(env("EDGE_SIGNED_COOKIE_PATH_PREFIXES", "")),
			now:          time.Now,
		},
		limiter:       newRateLimiterFromEnv(),
		scopedLimiter: newEdgeScopedRateLimiterFromEnv(),
		metrics:       newEdgeMetrics(),
	}
	defer app.redis.close()

	natsConn, err := openNATS()
	if err != nil {
		log.Fatalf("connect nats: %v", err)
	}
	app.natsConn = natsConn
	defer natsConn.Close()

	if err := app.subscribeCacheInvalidations(); err != nil {
		log.Fatalf("subscribe cache invalidations: %v", err)
	}
	if err := app.subscribeCachePrewarm(); err != nil {
		log.Fatalf("subscribe cache prewarm: %v", err)
	}
	if err := app.subscribeConfigChanges(); err != nil {
		log.Fatalf("subscribe config changes: %v", err)
	}
	app.startAnalyticsPublisher()
	app.startHealthPublisher()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler("edge"))
	mux.HandleFunc("/ready", app.readyHandler)
	mux.HandleFunc("/metrics", app.metricsHandler)
	mux.HandleFunc("/v1/cache/analytics", app.cacheAnalyticsHandler)
	mux.HandleFunc("/edge/", app.edgeHandler)

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           observabilityMiddleware("edge", corsMiddleware(mux)),
		ReadHeaderTimeout: envDuration("HTTP_READ_HEADER_TIMEOUT", 5*time.Second),
		ReadTimeout:       envDuration("HTTP_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:      envDuration("HTTP_WRITE_TIMEOUT", 30*time.Second),
		IdleTimeout:       envDuration("HTTP_IDLE_TIMEOUT", 60*time.Second),
	}

	log.Printf("edge service listening on :%s", port)
	if err := listenAndShutdown(server, envDuration("HTTP_SHUTDOWN_TIMEOUT", 10*time.Second)); err != nil {
		log.Fatal(err)
	}
}

func (s *edgeServer) startAnalyticsPublisher() {
	if s == nil || s.analyticsPushInterval <= 0 || s.controlBaseURL == "" || s.nodeID == "" {
		return
	}
	go func() {
		ticker := time.NewTicker(s.analyticsPushInterval)
		defer ticker.Stop()
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), minDuration(s.analyticsPushInterval, 5*time.Second))
			if err := s.pushCacheAnalyticsSnapshot(ctx); err != nil {
				log.Printf("cache analytics push failed: %v", err)
			}
			cancel()
		}
	}()
}

func (s *edgeServer) startHealthPublisher() {
	if s == nil || s.healthPushInterval <= 0 || s.controlBaseURL == "" || s.nodeID == "" {
		return
	}
	go func() {
		if err := s.pushEdgeHealth(context.Background()); err != nil {
			log.Printf("edge health push failed: %v", err)
		}
		ticker := time.NewTicker(s.healthPushInterval)
		defer ticker.Stop()
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), minDuration(s.healthPushInterval, 5*time.Second))
			if err := s.pushEdgeHealth(ctx); err != nil {
				log.Printf("edge health push failed: %v", err)
			}
			cancel()
		}
	}()
}

func (s *edgeServer) pushEdgeHealth(ctx context.Context) error {
	if s == nil || s.controlBaseURL == "" || s.nodeID == "" {
		return nil
	}
	address := strings.TrimSpace(s.publicURL)
	if address == "" {
		address = "http://edge:8080"
	}
	payload, err := json.Marshal(edgeRegistrationRequest{
		NodeID:       s.nodeID,
		Address:      address,
		Capabilities: []string{"cache", "proxy", "health"},
	})
	if err != nil {
		return err
	}
	client := s.client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.controlBaseURL+"/v1/edge/register", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.controlAPIKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.controlAPIKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("control edge registration returned status %d", resp.StatusCode)
	}
	return nil
}

func (s *edgeServer) pushCacheAnalyticsSnapshot(ctx context.Context) error {
	if s == nil || s.controlBaseURL == "" || s.nodeID == "" {
		return nil
	}
	payload, err := json.Marshal(cacheAnalyticsSnapshotRequest{
		EdgeNodeID: s.nodeID,
		Cache:      s.cacheAnalyticsSnapshot().Cache,
		ObservedAt: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	client := s.client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.controlBaseURL+"/v1/analytics/cache-snapshots", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.controlAPIKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.controlAPIKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("control analytics snapshot returned status %d", resp.StatusCode)
	}
	return nil
}

func (s *edgeServer) subscribeCacheInvalidations() error {
	if s.natsConn == nil {
		return nil
	}

	_, err := s.natsConn.Subscribe("cache.invalidate", func(msg *nats.Msg) {
		var event cacheInvalidationEvent
		if err := json.Unmarshal(msg.Data, &event); err != nil {
			log.Printf("cache invalidation decode failed: %v", err)
			return
		}
		if err := s.invalidateCache(context.Background(), event); err != nil {
			s.acknowledgeCacheInvalidation(context.Background(), event, "failed", err.Error())
			s.recordInvalidationFailure()
			log.Printf("cache invalidation failed id=%d mode=%s err=%v", event.ID, event.Mode, err)
			return
		}
		s.acknowledgeCacheInvalidation(context.Background(), event, "applied", "")
		s.recordInvalidation(event.Mode)
		log.Printf("cache invalidation applied id=%d mode=%s values=%d", event.ID, event.Mode, len(event.Values))
	})
	if err != nil {
		return err
	}
	return s.natsConn.FlushTimeout(2 * time.Second)
}

func (s *edgeServer) subscribeCachePrewarm() error {
	if s.natsConn == nil {
		return nil
	}
	_, err := s.natsConn.Subscribe("cache.prewarm", func(msg *nats.Msg) {
		var event cachePrewarmEvent
		if err := json.Unmarshal(msg.Data, &event); err != nil {
			log.Printf("cache prewarm decode failed: %v", err)
			return
		}
		warmed, failed := s.applyCachePrewarm(context.Background(), event)
		log.Printf("cache prewarm applied id=%d warmed=%d failed=%d", event.ID, warmed, failed)
	})
	if err != nil {
		return err
	}
	return s.natsConn.FlushTimeout(2 * time.Second)
}

func (s *edgeServer) acknowledgeCacheInvalidation(ctx context.Context, event cacheInvalidationEvent, status string, errorMessage string) {
	if s == nil || s.controlBaseURL == "" || s.nodeID == "" || event.ID <= 0 {
		return
	}

	payload, err := json.Marshal(cacheInvalidationDeliveryRequest{
		InvalidationID: event.ID,
		NodeID:         s.nodeID,
		Status:         status,
		Error:          errorMessage,
	})
	if err != nil {
		log.Printf("cache invalidation ack encode failed id=%d err=%v", event.ID, err)
		return
	}

	client := s.client
	if client == nil {
		client = http.DefaultClient
	}
	attempts := s.ackAttempts
	if attempts <= 0 {
		attempts = 1
	}
	backoff := s.ackBackoff
	if backoff <= 0 {
		backoff = 250 * time.Millisecond
	}

	for attempt := 1; attempt <= attempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.controlBaseURL+"/v1/cache/invalidation-deliveries", strings.NewReader(string(payload)))
		if err != nil {
			log.Printf("cache invalidation ack request failed id=%d err=%v", event.ID, err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if s.controlAPIKey != "" {
			req.Header.Set("Authorization", "Bearer "+s.controlAPIKey)
		}

		resp, err := client.Do(req)
		if err == nil && resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
				return
			}
			err = fmt.Errorf("status=%d", resp.StatusCode)
		}

		if attempt == attempts {
			log.Printf("cache invalidation ack failed id=%d attempts=%d err=%v", event.ID, attempts, err)
			return
		}

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			log.Printf("cache invalidation ack canceled id=%d attempt=%d err=%v", event.ID, attempt, ctx.Err())
			return
		case <-timer.C:
		}
		backoff *= 2
	}
}

func (s *edgeServer) invalidateCache(ctx context.Context, event cacheInvalidationEvent) error {
	values := event.Values
	if event.Host != "" {
		values = hostScopedInvalidationValues(event.Host, event.Values)
	}

	switch event.Mode {
	case "keys":
		s.cache.deleteKeys(values)
		return s.redis.deleteKeys(ctx, values)
	case "prefixes":
		s.cache.deletePrefixes(values)
		return s.redis.deletePrefixes(ctx, values)
	case "tags":
		s.cache.deleteTags(event.Values, event.Host)
		return s.redis.deleteTags(ctx, event.Values, event.Host)
	default:
		return fmt.Errorf("unknown invalidation mode %q", event.Mode)
	}
}

func (s *edgeServer) applyCachePrewarm(ctx context.Context, event cachePrewarmEvent) (int, int) {
	warmed := 0
	failed := 0
	for _, path := range event.Paths {
		if err := s.prewarmPath(ctx, event.Host, path); err != nil {
			failed++
			log.Printf("cache prewarm path failed id=%d host=%s path=%s err=%v", event.ID, event.Host, path, err)
			continue
		}
		warmed++
	}
	return warmed, failed
}

func (s *edgeServer) prewarmPath(ctx context.Context, host string, path string) error {
	path = strings.TrimSpace(path)
	if !strings.HasPrefix(path, "/edge/") {
		return fmt.Errorf("invalid prewarm path %q", path)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	req.Host = normalizeRouteHost(host)
	route := s.routeForRequest(req)
	if route.policy.Mode == "bypass" {
		return nil
	}
	cacheKey := cacheKeyForRequest(req)
	if lookup := s.getFreshCacheEntry(ctx, req, cacheKey); lookup.ok {
		return nil
	}
	originResult, err := s.fetchOriginForRequest(req, route, cacheKey)
	if err != nil {
		return err
	}
	if originResult.streamed {
		if originResult.bodyReader != nil {
			_ = originResult.bodyReader.Close()
		}
		return nil
	}
	header := cloneCacheableHeaders(originResult.header)
	body, header := transformImageForDelivery(req, header, originResult.body)
	ttl := ttlForStorage(route.policy, req, header)
	if originResult.status != http.StatusOK || ttl <= 0 || !responseVaryCacheable(header) {
		return nil
	}
	entry := cacheEntry{
		status:    originResult.status,
		header:    header,
		body:      body,
		expiresAt: time.Now().Add(ttl),
	}
	s.storeCacheEntry(ctx, cacheKey, req, entry, ttl)
	return nil
}

func (s *edgeServer) subscribeConfigChanges() error {
	if s.natsConn == nil || s.routes == nil || !s.routes.enabled() {
		return nil
	}
	_, err := s.natsConn.Subscribe("config.changed", func(msg *nats.Msg) {
		var event configChangedEvent
		if err := json.Unmarshal(msg.Data, &event); err != nil {
			log.Printf("config change decode failed: %v", err)
			return
		}
		if err := s.routes.refresh(context.Background()); err != nil {
			log.Printf("config refresh failed resource=%s id=%d err=%v", event.Resource, event.ID, err)
			return
		}
		log.Printf("config refreshed resource=%s id=%d", event.Resource, event.ID)
	})
	if err != nil {
		return err
	}
	return s.natsConn.FlushTimeout(2 * time.Second)
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

func (s *edgeServer) readyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	checks := map[string]string{}
	status := http.StatusOK
	if s.originBase == nil {
		checks["origin"] = "missing"
		status = http.StatusServiceUnavailable
	} else {
		checks["origin"] = "ok"
	}
	if s.routes != nil && s.routes.enabled() {
		if err := s.routes.refresh(r.Context()); err != nil {
			checks["control_config"] = err.Error()
			status = http.StatusServiceUnavailable
		} else {
			checks["control_config"] = "ok"
		}
	}
	if err := s.redis.ping(r.Context()); err != nil {
		checks["redis"] = err.Error()
		status = http.StatusServiceUnavailable
	} else {
		checks["redis"] = "ok"
	}
	if s.natsConn == nil || !s.natsConn.IsConnected() {
		checks["nats"] = "not connected"
		status = http.StatusServiceUnavailable
	} else {
		checks["nats"] = "ok"
	}

	ready := status == http.StatusOK
	writeJSON(w, status, map[string]any{
		"service": "edge",
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
	w.Header().Set("Access-Control-Expose-Headers", "X-Request-ID,X-AstraCDN-Cache,X-AstraCDN-Cache-Layer")
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

func (s *edgeServer) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	memory, redisHits, misses, rateLimited := s.metricsSnapshot()
	invalidations, invalidationFailed := s.invalidationMetricsSnapshot()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintln(w, "# HELP astracdn_edge_up Service availability")
	fmt.Fprintln(w, "# TYPE astracdn_edge_up gauge")
	fmt.Fprintln(w, "astracdn_edge_up 1")
	fmt.Fprintln(w, "# HELP astracdn_edge_cache_requests_total Edge cache requests by result and layer")
	fmt.Fprintln(w, "# TYPE astracdn_edge_cache_requests_total counter")
	fmt.Fprintf(w, "astracdn_edge_cache_requests_total{result=\"hit\",layer=\"memory\"} %d\n", memory)
	fmt.Fprintf(w, "astracdn_edge_cache_requests_total{result=\"hit\",layer=\"redis\"} %d\n", redisHits)
	fmt.Fprintf(w, "astracdn_edge_cache_requests_total{result=\"miss\",layer=\"origin\"} %d\n", misses)
	byHost, byRoute := s.cacheDimensionSnapshots()
	fmt.Fprintln(w, "# HELP astracdn_edge_cache_requests_by_host_total Edge cache requests by host, result, and layer")
	fmt.Fprintln(w, "# TYPE astracdn_edge_cache_requests_by_host_total counter")
	writeCacheDimensionMetrics(w, "astracdn_edge_cache_requests_by_host_total", "host", byHost)
	fmt.Fprintln(w, "# HELP astracdn_edge_cache_requests_by_route_total Edge cache requests by route, result, and layer")
	fmt.Fprintln(w, "# TYPE astracdn_edge_cache_requests_by_route_total counter")
	writeCacheDimensionMetrics(w, "astracdn_edge_cache_requests_by_route_total", "route", byRoute)
	fill := s.cacheFillLatencySnapshot()
	fmt.Fprintln(w, "# HELP astracdn_edge_cache_fill_latency_seconds Cache fill latency from origin or shield fetches")
	fmt.Fprintln(w, "# TYPE astracdn_edge_cache_fill_latency_seconds summary")
	fmt.Fprintf(w, "astracdn_edge_cache_fill_latency_seconds_count %d\n", fill.Count)
	fmt.Fprintf(w, "astracdn_edge_cache_fill_latency_seconds_sum %.6f\n", fill.SumSeconds)
	fmt.Fprintf(w, "astracdn_edge_cache_fill_latency_seconds_max %.6f\n", fill.MaxSeconds)
	fmt.Fprintln(w, "# HELP astracdn_edge_rate_limit_blocks_total Edge requests rejected by rate limiting")
	fmt.Fprintln(w, "# TYPE astracdn_edge_rate_limit_blocks_total counter")
	fmt.Fprintf(w, "astracdn_edge_rate_limit_blocks_total %d\n", rateLimited)
	fmt.Fprintln(w, "# HELP astracdn_edge_waf_blocks_total Edge requests rejected by WAF rules")
	fmt.Fprintln(w, "# TYPE astracdn_edge_waf_blocks_total counter")
	fmt.Fprintf(w, "astracdn_edge_waf_blocks_total %d\n", s.wafMetricsSnapshot())
	fmt.Fprintln(w, "# HELP astracdn_edge_cache_invalidations_total Edge cache invalidations applied by mode")
	fmt.Fprintln(w, "# TYPE astracdn_edge_cache_invalidations_total counter")
	for _, mode := range sortedMetricKeys(invalidations) {
		fmt.Fprintf(w, "astracdn_edge_cache_invalidations_total{mode=\"%s\"} %d\n", mode, invalidations[mode])
	}
	fmt.Fprintln(w, "# HELP astracdn_edge_cache_invalidation_failures_total Edge cache invalidations that failed")
	fmt.Fprintln(w, "# TYPE astracdn_edge_cache_invalidation_failures_total counter")
	fmt.Fprintf(w, "astracdn_edge_cache_invalidation_failures_total %d\n", invalidationFailed)
}

func (s *edgeServer) cacheAnalyticsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.cacheAnalyticsSnapshot())
}

func writeCacheDimensionMetrics(w io.Writer, metric string, label string, values map[string]edgeCacheAnalyticsBreakout) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		breakout := values[key]
		for _, layer := range []string{"memory", "redis", "origin"} {
			counter := breakout.ByLayer[layer]
			if counter.Requests == 0 {
				continue
			}
			fmt.Fprintf(
				w,
				"%s{%s=\"%s\",result=\"%s\",layer=\"%s\"} %d\n",
				metric,
				label,
				prometheusLabelValue(key),
				counter.Result,
				layer,
				counter.Requests,
			)
		}
	}
}

func (s *edgeServer) edgeHandler(w http.ResponseWriter, r *http.Request) {
	route := s.routeForRequest(r)
	if s.waf.blocks(r) {
		s.recordWAFBlock()
		http.Error(w, "blocked by WAF", http.StatusForbidden)
		return
	}
	if route.waf.blocks(r) {
		s.recordWAFBlock()
		http.Error(w, "blocked by WAF", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.allowScopedRequest(r, route) {
		s.recordRateLimitBlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if !s.allowRequest(r) {
		s.recordRateLimitBlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if !s.signer.validate(r.URL) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !s.cookieSigner.validate(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.validateRequestDomain(r); err != nil {
		if err == errDomainConfigUnavailable {
			http.Error(w, "domain config unavailable", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "unknown CDN domain", http.StatusNotFound)
		return
	}

	if location, status, ok := route.rules.redirect(r); ok {
		http.Redirect(w, r, location, status)
		return
	}
	if location, status, ok := s.deliveryRules.redirect(r); ok {
		http.Redirect(w, r, location, status)
		return
	}
	cacheKey := cacheKeyForRequest(r)
	var staleIfError cacheLookup
	if route.policy.Mode != "bypass" {
		if lookup := s.getFreshCacheEntry(r.Context(), r, cacheKey); lookup.ok {
			if requestRequiresRevalidation(r) || entryRequiresRevalidation(lookup.entry) {
				if hasValidators(lookup.entry.header) && s.revalidateCacheEntry(w, r, route, cacheKey, lookup.key, lookup.entry, lookup.layer) {
					return
				}
			} else {
				s.recordCacheMetricForRequest(lookup.layer, r, route)
				s.writeCachedResponse(w, r, lookup.entry, "HIT", lookup.layer, route)
				return
			}
		}

		staleIfError = s.getStaleIfErrorEntry(r.Context(), r, cacheKey)
		if lookup := s.getStaleRevalidationEntry(r.Context(), r, cacheKey, maxStaleForPolicy(route.policy)); lookup.ok {
			if s.revalidateCacheEntry(w, r, route, cacheKey, lookup.key, lookup.entry, lookup.layer) {
				return
			}
		}
	}

	originResult, err := s.fetchOriginForRequest(r, route, cacheKey)
	if err != nil {
		log.Printf("origin fetch failed url=%s err=%v", originResult.originURL, err)
		if staleIfError.ok {
			s.recordCacheMetricForRequest(staleIfError.layer, r, route)
			s.writeCachedResponse(w, r, staleIfError.entry, "STALE", staleIfError.layer, route)
			return
		}
		http.Error(w, "origin fetch failed", http.StatusBadGateway)
		return
	}

	if originResult.status >= http.StatusInternalServerError && staleIfError.ok {
		s.recordCacheMetricForRequest(staleIfError.layer, r, route)
		s.writeCachedResponse(w, r, staleIfError.entry, "STALE", staleIfError.layer, route)
		return
	}
	if originResult.streamed {
		s.writeStreamedOriginResponse(w, r, originResult, route)
		return
	}

	body := originResult.body
	header := cloneCacheableHeaders(originResult.header)
	body, header = transformImageForDelivery(r, header, body)
	if ttl := ttlForStorage(route.policy, r, header); originResult.status == http.StatusOK && ttl > 0 && responseVaryCacheable(header) {
		entry := cacheEntry{
			status:    originResult.status,
			header:    header,
			body:      body,
			expiresAt: time.Now().Add(ttl),
		}
		s.storeCacheEntry(r.Context(), cacheKey, r, entry, ttl)
		if r.Header.Get("Range") != "" {
			s.recordCacheMetricForRequest("origin", r, route)
			s.writeCachedResponse(w, r, entry, "MISS", "origin", route)
			return
		}
	}

	copyHeader(w.Header(), header)
	if originResult.header.Get("Content-Range") != "" {
		w.Header().Set("Content-Range", originResult.header.Get("Content-Range"))
	}
	if originResult.header.Get("Accept-Ranges") != "" {
		w.Header().Set("Accept-Ranges", originResult.header.Get("Accept-Ranges"))
	}
	s.applyDeliveryHeaders(w.Header(), r.URL.Path, route)
	body = prepareDeliveryBody(r, w.Header(), body, originResult.status)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	s.recordCacheMetricForRequest("origin", r, route)
	if route.policy.Mode == "bypass" {
		w.Header().Set("X-AstraCDN-Cache", "BYPASS")
	} else {
		w.Header().Set("X-AstraCDN-Cache", "MISS")
	}
	w.Header().Set("X-AstraCDN-Cache-Layer", "origin")
	w.WriteHeader(originResult.status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func (s *edgeServer) writeStreamedOriginResponse(w http.ResponseWriter, r *http.Request, originResult originFetchResult, route requestRoute) {
	if originResult.bodyReader != nil {
		defer originResult.bodyReader.Close()
	}

	header := cloneCacheableHeaders(originResult.header)
	copyHeader(w.Header(), header)
	if originResult.header.Get("Content-Range") != "" {
		w.Header().Set("Content-Range", originResult.header.Get("Content-Range"))
	}
	if originResult.header.Get("Accept-Ranges") != "" {
		w.Header().Set("Accept-Ranges", originResult.header.Get("Accept-Ranges"))
	}
	if length := strings.TrimSpace(originResult.header.Get("Content-Length")); length != "" {
		w.Header().Set("Content-Length", length)
	}
	s.applyDeliveryHeaders(w.Header(), r.URL.Path, route)
	s.recordCacheMetricForRequest("origin", r, route)
	if route.policy.Mode == "bypass" {
		w.Header().Set("X-AstraCDN-Cache", "BYPASS")
	} else {
		w.Header().Set("X-AstraCDN-Cache", "MISS")
	}
	w.Header().Set("X-AstraCDN-Cache-Layer", "origin-stream")
	w.Header().Set("X-AstraCDN-Streaming", "1")
	w.WriteHeader(originResult.status)
	if r.Method == http.MethodHead || originResult.bodyReader == nil {
		return
	}
	if s.streamAndCacheSegments(w, r, originResult, route) {
		return
	}
	if _, err := io.Copy(w, originResult.bodyReader); err != nil {
		log.Printf("origin stream copy failed url=%s err=%v", originResult.originURL, err)
	}
}

func (s *edgeServer) streamAndCacheSegments(w http.ResponseWriter, r *http.Request, originResult originFetchResult, route requestRoute) bool {
	if !envBool("EDGE_SEGMENTED_CACHE_ENABLED", true) || s == nil || originResult.bodyReader == nil || route.policy.Mode == "bypass" {
		return false
	}
	if r.Method != http.MethodGet || strings.TrimSpace(r.Header.Get("Range")) != "" {
		return false
	}
	header := cloneCacheableHeaders(originResult.header)
	ttl := ttlForStorage(route.policy, r, header)
	if originResult.status != http.StatusOK || ttl <= 0 || !responseVaryCacheable(header) {
		return false
	}
	if originResult.header.Get("Content-Length") == "" || originResult.header.Get("Content-Encoding") != "" {
		return false
	}
	objectSize := originResult.header.Get("Content-Length")
	size, err := strconv.ParseInt(strings.TrimSpace(objectSize), 10, 64)
	if err != nil || size <= 0 {
		return false
	}
	segmentSize := envInt("EDGE_SEGMENT_SIZE_BYTES", 1024*1024)
	if segmentSize <= 0 {
		segmentSize = 1024 * 1024
	}

	baseKey := cacheKeyForRequest(r)
	if varyHeaders := varyHeaderNames(header.Get("Vary")); len(varyHeaders) > 0 {
		baseKey = varyCacheKey(baseKey, varyHeaders, r)
		s.cache.rememberVarySpec(cacheKeyForRequest(r), varyHeaders)
		s.redis.rememberVarySpec(r.Context(), cacheKeyForRequest(r), varyHeaders, redisRetentionTTLForEntry(cacheEntry{header: header, expiresAt: time.Now().Add(ttl)}, ttl))
	}
	retentionTTL := redisRetentionTTLForEntry(cacheEntry{header: header, expiresAt: time.Now().Add(ttl)}, ttl)
	expiresAt := time.Now().Add(ttl)
	buffer := make([]byte, segmentSize)
	segmentIndex := 0
	for {
		n, readErr := io.ReadFull(originResult.bodyReader, buffer)
		if n > 0 {
			chunk := append([]byte(nil), buffer[:n]...)
			if _, err := w.Write(chunk); err != nil {
				log.Printf("large object client stream failed key=%s err=%v", baseKey, err)
				return true
			}
			segment := cacheEntry{
				status:    http.StatusPartialContent,
				header:    header.Clone(),
				body:      chunk,
				expiresAt: expiresAt,
			}
			key := segmentCacheKey(baseKey, segmentIndex)
			s.cache.set(key, segment)
			s.redis.set(r.Context(), key, segment, retentionTTL)
			segmentIndex++
		}
		if readErr == nil {
			continue
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		log.Printf("large object segmented fill failed key=%s err=%v", baseKey, readErr)
		return true
	}
	if segmentIndex == 0 {
		return true
	}
	manifest := cacheEntry{
		status:       originResult.status,
		header:       header,
		expiresAt:    expiresAt,
		segmented:    true,
		objectSize:   size,
		segmentSize:  segmentSize,
		segmentCount: segmentIndex,
	}
	s.cache.set(baseKey, manifest)
	s.redis.set(r.Context(), baseKey, manifest, retentionTTL)
	return true
}

var (
	errDomainNotAllowed        = fmt.Errorf("domain not allowed")
	errDomainConfigUnavailable = fmt.Errorf("domain config unavailable")
)

func (s *edgeServer) validateRequestDomain(r *http.Request) error {
	if s == nil || !s.validateDomain {
		return nil
	}
	if s.routes == nil || !s.routes.enabled() {
		return errDomainConfigUnavailable
	}
	if err := s.routes.refreshIfStale(r.Context()); err != nil {
		log.Printf("edge domain config refresh failed: %v", err)
		return errDomainConfigUnavailable
	}
	if !s.routes.domainAllowed(routeHost(r)) {
		return errDomainNotAllowed
	}
	return nil
}

func (s *edgeServer) fetchOriginForRequest(r *http.Request, route requestRoute, cacheKey string) (originFetchResult, error) {
	fetch := func() (originFetchResult, error) {
		return s.fetchOriginForRequestUncoalesced(r, route)
	}
	if !s.shouldCoalesceOriginRequest(r, route) {
		return fetch()
	}
	key := originCoalescingKey(r, cacheKey)
	return s.coalescer.do(key, fetch)
}

func (s *edgeServer) fetchOriginForRequestUncoalesced(r *http.Request, route requestRoute) (originFetchResult, error) {
	start := time.Now()
	defer func() {
		s.recordCacheFillLatency(time.Since(start))
	}()
	if s.shouldUseOriginShield(r, route) {
		result, err := s.fetchViaOriginShield(r)
		if err == nil {
			return result, nil
		}
		log.Printf("origin shield fetch failed err=%v; falling back to direct origin", err)
	}

	originURLs := s.originURLs(r, route.originBases)
	resp, originURL, err := s.doOriginRequest(r.Context(), originURLs, func(originURL *url.URL) (*http.Request, error) {
		originReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, originURL.String(), nil)
		if err != nil {
			return nil, err
		}
		originReq.Header.Set("User-Agent", "AstraCDN/phase3")
		copyOriginRequestHeaders(originReq.Header, r.Header)
		if rangeHeader := strings.TrimSpace(r.Header.Get("Range")); rangeHeader != "" {
			originReq.Header.Set("Range", rangeHeader)
		}
		return originReq, nil
	})
	result := originFetchResult{originURL: originURLString(originURL)}
	if err != nil {
		return result, err
	}
	if shouldStreamOriginResponse(r, resp) {
		result.status = resp.StatusCode
		result.header = resp.Header.Clone()
		result.bodyReader = resp.Body
		result.streamed = true
		return result, nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, err
	}
	result.status = resp.StatusCode
	result.header = resp.Header.Clone()
	result.body = body
	return result, nil
}

func (s *edgeServer) shouldUseOriginShield(r *http.Request, route requestRoute) bool {
	if s == nil || len(s.originShield) == 0 || route.policy.Mode == "bypass" {
		return false
	}
	if strings.TrimSpace(r.Header.Get(shieldHopHeader)) != "" {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return true
}

func (s *edgeServer) fetchViaOriginShield(r *http.Request) (originFetchResult, error) {
	shieldURLs := s.shieldURLs(r)
	resp, shieldURL, err := s.doOriginRequest(r.Context(), shieldURLs, func(shieldURL *url.URL) (*http.Request, error) {
		shieldReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, shieldURL.String(), nil)
		if err != nil {
			return nil, err
		}
		shieldReq.Header.Set("User-Agent", "AstraCDN/edge-shield")
		shieldReq.Header.Set(shieldHopHeader, "1")
		copyOriginRequestHeaders(shieldReq.Header, r.Header)
		if host := routeHost(r); host != "" {
			shieldReq.Host = host
		}
		if rangeHeader := strings.TrimSpace(r.Header.Get("Range")); rangeHeader != "" {
			shieldReq.Header.Set("Range", rangeHeader)
		}
		return shieldReq, nil
	})
	result := originFetchResult{originURL: originURLString(shieldURL)}
	if err != nil {
		return result, err
	}
	if shouldStreamOriginResponse(r, resp) {
		result.status = resp.StatusCode
		result.header = resp.Header.Clone()
		result.bodyReader = resp.Body
		result.streamed = true
		return result, nil
	}
	defer resp.Body.Close()
	if retryableOriginResponse(resp) {
		_, _ = io.Copy(io.Discard, resp.Body)
		return result, fmt.Errorf("origin shield returned retryable status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, err
	}
	result.status = resp.StatusCode
	result.header = resp.Header.Clone()
	result.body = body
	return result, nil
}

func (s *edgeServer) shouldCoalesceOriginRequest(r *http.Request, route requestRoute) bool {
	if s == nil || !s.requestCoalescing || s.coalescer == nil || route.policy.Mode == "bypass" {
		return false
	}
	if r.Method != http.MethodGet || strings.TrimSpace(r.Header.Get("Range")) != "" {
		return false
	}
	if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
		return false
	}
	return true
}

func shouldStreamOriginResponse(r *http.Request, resp *http.Response) bool {
	if !envBool("EDGE_LARGE_OBJECT_STREAMING_ENABLED", true) {
		return false
	}
	if r == nil || resp == nil || resp.Body == nil {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if strings.TrimSpace(r.Header.Get("Range")) != "" {
		return false
	}
	if resp.StatusCode != http.StatusOK {
		return false
	}
	threshold := int64(envInt("EDGE_LARGE_OBJECT_THRESHOLD_BYTES", 8*1024*1024))
	if threshold <= 0 || resp.ContentLength < 0 {
		return false
	}
	return resp.ContentLength > threshold
}

func newOriginCoalescer() *originCoalescer {
	return &originCoalescer{calls: make(map[string]*originFetchCall)}
}

func (c *originCoalescer) do(key string, fn func() (originFetchResult, error)) (originFetchResult, error) {
	if c == nil {
		return fn()
	}
	c.mu.Lock()
	if call := c.calls[key]; call != nil {
		c.mu.Unlock()
		<-call.done
		return call.result, call.err
	}
	call := &originFetchCall{done: make(chan struct{})}
	c.calls[key] = call
	c.mu.Unlock()

	call.result, call.err = fn()
	close(call.done)

	c.mu.Lock()
	delete(c.calls, key)
	c.mu.Unlock()
	return call.result, call.err
}

func originCoalescingKey(r *http.Request, cacheKey string) string {
	var b strings.Builder
	b.WriteString(cacheKey)
	b.WriteString("|headers:")
	keys := make([]string, 0, len(r.Header))
	for key := range r.Header {
		keys = append(keys, strings.ToLower(key))
	}
	sort.Strings(keys)
	for _, key := range keys {
		values := r.Header.Values(key)
		sort.Strings(values)
		b.WriteString(key)
		b.WriteString("=")
		b.WriteString(strings.Join(values, ","))
		b.WriteString(";")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func (s *edgeServer) getFreshCacheEntry(ctx context.Context, r *http.Request, cacheKey string) cacheLookup {
	for _, candidate := range s.cacheLookupKeys(ctx, r, cacheKey) {
		if entry, ok := s.cache.get(candidate); ok {
			return cacheLookup{entry: entry, layer: "memory", key: candidate, ok: true}
		}
		if entry, ok := s.redis.get(ctx, candidate); ok {
			s.cache.set(candidate, entry)
			return cacheLookup{entry: entry, layer: "redis", key: candidate, ok: true}
		}
	}
	return cacheLookup{}
}

func (s *edgeServer) getStaleRevalidationEntry(ctx context.Context, r *http.Request, cacheKey string, maxStale time.Duration) cacheLookup {
	for _, candidate := range s.cacheLookupKeys(ctx, r, cacheKey) {
		if entry, ok := s.cache.getStale(candidate, maxStale); ok && hasValidators(entry.header) {
			return cacheLookup{entry: entry, layer: "memory-stale", key: candidate, ok: true}
		}
		if entry, ok := s.redis.getStale(ctx, candidate, maxStale); ok && hasValidators(entry.header) {
			s.cache.set(candidate, entry)
			return cacheLookup{entry: entry, layer: "redis-stale", key: candidate, ok: true}
		}
	}
	return cacheLookup{}
}

func (s *edgeServer) getStaleIfErrorEntry(ctx context.Context, r *http.Request, cacheKey string) cacheLookup {
	for _, candidate := range s.cacheLookupKeys(ctx, r, cacheKey) {
		if entry, ok := s.cache.getStaleIfError(candidate); ok {
			return cacheLookup{entry: entry, layer: "memory-stale", key: candidate, ok: true}
		}
		if entry, ok := s.redis.getStaleIfError(ctx, candidate); ok {
			s.cache.set(candidate, entry)
			return cacheLookup{entry: entry, layer: "redis-stale", key: candidate, ok: true}
		}
	}
	return cacheLookup{}
}

func (s *edgeServer) cacheLookupKeys(ctx context.Context, r *http.Request, baseKey string) []string {
	keys := []string{baseKey}
	seen := map[string]struct{}{baseKey: {}}
	for _, varyHeaders := range s.cache.varySpecs(baseKey) {
		key := varyCacheKey(baseKey, varyHeaders, r)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	for _, varyHeaders := range s.redis.varySpecs(ctx, baseKey) {
		key := varyCacheKey(baseKey, varyHeaders, r)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
		s.cache.rememberVarySpec(baseKey, varyHeaders)
	}
	return keys
}

func (s *edgeServer) storeCacheEntry(ctx context.Context, baseKey string, r *http.Request, entry cacheEntry, ttl time.Duration) string {
	key := baseKey
	retentionTTL := redisRetentionTTLForEntry(entry, ttl)
	if varyHeaders := varyHeaderNames(entry.header.Get("Vary")); len(varyHeaders) > 0 {
		key = varyCacheKey(baseKey, varyHeaders, r)
		s.cache.rememberVarySpec(baseKey, varyHeaders)
		s.redis.rememberVarySpec(ctx, baseKey, varyHeaders, retentionTTL)
	}
	s.cache.set(key, entry)
	tags := surrogateKeys(entry.header)
	s.cache.rememberSurrogateKeys(key, tags)
	s.redis.set(ctx, key, entry, retentionTTL)
	s.redis.rememberSurrogateKeys(ctx, key, tags, retentionTTL)
	return key
}

func (s *edgeServer) revalidateCacheEntry(w http.ResponseWriter, r *http.Request, route requestRoute, baseKey string, cacheKey string, stale cacheEntry, layer string) bool {
	originURLs := s.originURLs(r, route.originBases)
	start := time.Now()
	resp, originURL, err := s.doOriginRequest(r.Context(), originURLs, func(originURL *url.URL) (*http.Request, error) {
		originReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, originURL.String(), nil)
		if err != nil {
			return nil, err
		}
		originReq.Header.Set("User-Agent", "AstraCDN/phase3")
		copyOriginRequestHeaders(originReq.Header, r.Header)
		if etag := stale.header.Get("Etag"); etag != "" {
			originReq.Header.Set("If-None-Match", etag)
		}
		if lastModified := stale.header.Get("Last-Modified"); lastModified != "" {
			originReq.Header.Set("If-Modified-Since", lastModified)
		}
		return originReq, nil
	})
	s.recordCacheFillLatency(time.Since(start))
	if err != nil {
		log.Printf("origin revalidation failed url=%s err=%v", originURLString(originURL), err)
		if entryAllowsStaleIfError(stale) {
			s.recordCacheMetricForRequest(layer, r, route)
			s.writeCachedResponse(w, r, stale, "STALE", layer, route)
			return true
		}
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusInternalServerError && entryAllowsStaleIfError(stale) {
		s.recordCacheMetricForRequest(layer, r, route)
		s.writeCachedResponse(w, r, stale, "STALE", layer, route)
		return true
	}

	if resp.StatusCode == http.StatusNotModified {
		header := mergeCacheHeaders(stale.header, resp.Header)
		ttl := ttlForStorage(route.policy, r, header)
		if ttl <= 0 {
			s.cache.deleteKeys([]string{cacheKey})
			_ = s.redis.deleteKeys(r.Context(), []string{cacheKey})
			return false
		}
		refreshed := cacheEntry{
			status:    stale.status,
			header:    header,
			body:      stale.body,
			expiresAt: time.Now().Add(ttl),
		}
		refreshedKey := s.storeCacheEntry(r.Context(), baseKey, r, refreshed, ttl)
		if refreshedKey != cacheKey {
			s.cache.deleteKeys([]string{cacheKey})
			_ = s.redis.deleteKeys(r.Context(), []string{cacheKey})
		}
		s.recordCacheMetricForRequest("origin", r, route)
		s.writeCachedResponse(w, r, refreshed, "REVALIDATED", layer, route)
		return true
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	header := cloneCacheableHeaders(resp.Header)
	body, header = transformImageForDelivery(r, header, body)
	if ttl := ttlForStorage(route.policy, r, header); resp.StatusCode == http.StatusOK && ttl > 0 && responseVaryCacheable(header) {
		entry := cacheEntry{
			status:    resp.StatusCode,
			header:    header,
			body:      body,
			expiresAt: time.Now().Add(ttl),
		}
		refreshedKey := s.storeCacheEntry(r.Context(), baseKey, r, entry, ttl)
		if refreshedKey != cacheKey {
			s.cache.deleteKeys([]string{cacheKey})
			_ = s.redis.deleteKeys(r.Context(), []string{cacheKey})
		}
		if r.Header.Get("Range") != "" {
			s.recordCacheMetricForRequest("origin", r, route)
			s.writeCachedResponse(w, r, entry, "MISS", "origin-revalidate", route)
			return true
		}
	}

	copyHeader(w.Header(), header)
	if resp.Header.Get("Content-Range") != "" {
		w.Header().Set("Content-Range", resp.Header.Get("Content-Range"))
	}
	if resp.Header.Get("Accept-Ranges") != "" {
		w.Header().Set("Accept-Ranges", resp.Header.Get("Accept-Ranges"))
	}
	s.applyDeliveryHeaders(w.Header(), r.URL.Path, route)
	body = prepareDeliveryBody(r, w.Header(), body, resp.StatusCode)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	s.recordCacheMetricForRequest("origin", r, route)
	w.Header().Set("X-AstraCDN-Cache", "MISS")
	w.Header().Set("X-AstraCDN-Cache-Layer", "origin-revalidate")
	w.WriteHeader(resp.StatusCode)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
	return true
}

func (s *edgeServer) doOriginRequest(ctx context.Context, originURLs []*url.URL, buildRequest func(*url.URL) (*http.Request, error)) (*http.Response, *url.URL, error) {
	client := s.client
	if client == nil {
		client = http.DefaultClient
	}
	attempts := s.originAttempts
	if attempts <= 0 {
		attempts = 1
	}
	backoff := s.originBackoff
	if backoff < 0 {
		backoff = 0
	}
	if len(originURLs) == 0 {
		return nil, nil, fmt.Errorf("no origin URLs configured")
	}

	var lastErr error
	var lastURL *url.URL
	for originIndex, originURL := range originURLs {
		lastURL = originURL
		currentBackoff := backoff
		for attempt := 1; attempt <= attempts; attempt++ {
			req, err := buildRequest(originURL)
			if err != nil {
				return nil, originURL, err
			}
			resp, err := client.Do(req)
			if err == nil && !retryableOriginResponse(resp) {
				return resp, originURL, nil
			}
			lastErr = err
			lastAttemptForOrigin := attempt == attempts
			lastOrigin := originIndex == len(originURLs)-1
			if lastAttemptForOrigin && lastOrigin {
				return resp, originURL, err
			}
			if resp != nil && resp.Body != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
			if err != nil {
				log.Printf("origin attempt failed origin=%d/%d attempt=%d/%d url=%s err=%v", originIndex+1, len(originURLs), attempt, attempts, originURL.String(), err)
			} else {
				log.Printf("origin attempt retryable status origin=%d/%d attempt=%d/%d url=%s status=%d", originIndex+1, len(originURLs), attempt, attempts, originURL.String(), resp.StatusCode)
			}
			if lastAttemptForOrigin || currentBackoff <= 0 {
				continue
			}
			timer := time.NewTimer(currentBackoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				if lastErr != nil {
					return nil, originURL, lastErr
				}
				return nil, originURL, ctx.Err()
			case <-timer.C:
			}
			currentBackoff *= 2
		}
	}
	return nil, lastURL, lastErr
}

func retryableOriginResponse(resp *http.Response) bool {
	return resp != nil && resp.StatusCode >= http.StatusInternalServerError
}

func (s *edgeServer) writeCachedResponse(w http.ResponseWriter, r *http.Request, entry cacheEntry, cacheStatus string, layer string, route requestRoute) {
	if entry.segmented {
		if s.writeSegmentedCachedResponse(w, r, entry, cacheStatus, layer, route) {
			return
		}
		http.Error(w, "segmented cache incomplete", http.StatusBadGateway)
		return
	}
	writeCachedResponse(w, r, entry, cacheStatus, layer, s.deliveryRules, route.rules)
}

func (s *edgeServer) writeSegmentedCachedResponse(w http.ResponseWriter, r *http.Request, entry cacheEntry, cacheStatus string, layer string, route requestRoute) bool {
	if s == nil || entry.segmentCount <= 0 || entry.segmentSize <= 0 {
		return false
	}
	if strings.TrimSpace(r.Header.Get("Range")) != "" {
		return false
	}
	baseKey := cacheKeyForRequest(r)
	if varyHeaders := varyHeaderNames(entry.header.Get("Vary")); len(varyHeaders) > 0 {
		baseKey = varyCacheKey(baseKey, varyHeaders, r)
	}
	segments := make([]cacheEntry, 0, entry.segmentCount)
	for i := 0; i < entry.segmentCount; i++ {
		key := segmentCacheKey(baseKey, i)
		segment, ok := s.cache.get(key)
		if !ok {
			var redisOK bool
			segment, redisOK = s.redis.get(r.Context(), key)
			if !redisOK {
				return false
			}
			s.cache.set(key, segment)
		}
		segments = append(segments, segment)
	}
	copyHeader(w.Header(), entry.header)
	s.applyDeliveryHeaders(w.Header(), r.URL.Path, route)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", strconv.FormatInt(entry.objectSize, 10))
	w.Header().Set("X-AstraCDN-Cache", cacheStatus)
	w.Header().Set("X-AstraCDN-Cache-Layer", layer+"-segments")
	w.Header().Set("X-AstraCDN-Segmented-Cache", "1")
	w.WriteHeader(entry.status)
	if r.Method == http.MethodHead {
		return true
	}
	for i, segment := range segments {
		if _, err := w.Write(segment.body); err != nil {
			log.Printf("segmented cache write failed key=%s segment=%d err=%v", baseKey, i, err)
			return true
		}
	}
	return true
}

func writeCachedResponse(w http.ResponseWriter, r *http.Request, entry cacheEntry, cacheStatus string, layer string, globalRules edgeDeliveryRules, routeRules edgeDeliveryRules) {
	w.Header().Set("Accept-Ranges", "bytes")
	if rangeHeader := strings.TrimSpace(r.Header.Get("Range")); rangeHeader != "" {
		rng, ok := parseByteRange(rangeHeader, int64(len(entry.body)))
		if !ok {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", len(entry.body)))
			w.Header().Set("X-AstraCDN-Cache", cacheStatus)
			w.Header().Set("X-AstraCDN-Cache-Layer", layer)
			http.Error(w, "requested range not satisfiable", http.StatusRequestedRangeNotSatisfiable)
			return
		}

		copyHeader(w.Header(), entry.header)
		globalRules.applyHeaders(w.Header(), r.URL.Path)
		routeRules.applyHeaders(w.Header(), r.URL.Path)
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rng.start, rng.end, len(entry.body)))
		w.Header().Set("Content-Length", strconv.FormatInt(rng.end-rng.start+1, 10))
		w.Header().Set("X-AstraCDN-Cache", cacheStatus)
		w.Header().Set("X-AstraCDN-Cache-Layer", layer)
		w.WriteHeader(http.StatusPartialContent)
		if r.Method != http.MethodHead {
			_, _ = w.Write(entry.body[rng.start : rng.end+1])
		}
		return
	}

	copyHeader(w.Header(), entry.header)
	globalRules.applyHeaders(w.Header(), r.URL.Path)
	routeRules.applyHeaders(w.Header(), r.URL.Path)
	w.Header().Set("Accept-Ranges", "bytes")
	body := prepareDeliveryBody(r, w.Header(), entry.body, entry.status)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("X-AstraCDN-Cache", cacheStatus)
	w.Header().Set("X-AstraCDN-Cache-Layer", layer)
	w.WriteHeader(entry.status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func (s *edgeServer) originURLs(r *http.Request, originBases []*url.URL) []*url.URL {
	if len(originBases) == 0 {
		originBases = []*url.URL{s.originBase}
	}
	urls := make([]*url.URL, 0, len(originBases))
	for _, originBase := range originBases {
		if originBase == nil {
			continue
		}
		next := *originBase
		edgePath := strings.TrimPrefix(r.URL.Path, "/edge")
		if edgePath == "" {
			edgePath = "/"
		}
		next.Path = joinURLPath(originBase.Path, edgePath)
		next.RawQuery = originRawQuery(r.URL)
		urls = append(urls, &next)
	}
	return urls
}

func (s *edgeServer) shieldURLs(r *http.Request) []*url.URL {
	urls := make([]*url.URL, 0, len(s.originShield))
	for _, shieldBase := range s.originShield {
		if shieldBase == nil {
			continue
		}
		next := *shieldBase
		next.Path = joinURLPath(shieldBase.Path, r.URL.Path)
		next.RawQuery = originRawQuery(r.URL)
		urls = append(urls, &next)
	}
	return urls
}

func originURLString(originURL *url.URL) string {
	if originURL == nil {
		return ""
	}
	return originURL.String()
}

func (s *edgeServer) routeForRequest(r *http.Request) requestRoute {
	fallback := requestRoute{
		originBases: s.originBases(s.originBase),
		policy:      edgeCachePolicy{Mode: "origin"},
		host:        routeHost(r),
		pathPrefix:  "/",
	}
	if s.routes == nil || !s.routes.enabled() {
		return fallback
	}
	if err := s.routes.refreshIfStale(r.Context()); err != nil {
		log.Printf("edge route config refresh failed: %v", err)
	}
	if route, ok := s.routes.match(routeHost(r), edgeOriginPath(r)); ok {
		return requestRoute{
			originBases:    s.originBases(route.originBase),
			policy:         normalizeEdgeCachePolicy(route.CachePolicy),
			waf:            route.wafRules,
			rules:          route.deliveryRules,
			rateLimitRules: route.rateLimitRules,
			host:           normalizeRouteHost(route.Host),
			pathPrefix:     normalizeRoutePathPrefix(route.PathPrefix),
			matched:        true,
		}
	}
	return fallback
}

func (s *edgeServer) originBases(primary *url.URL) []*url.URL {
	bases := make([]*url.URL, 0, 1+len(s.originFailover))
	if primary != nil {
		bases = append(bases, primary)
	}
	bases = append(bases, s.originFailover...)
	return bases
}

func newRouteConfigStore(baseURL string, apiKey string, refreshInterval time.Duration) *routeConfigStore {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil
	}
	if refreshInterval <= 0 {
		refreshInterval = 15 * time.Second
	}
	return &routeConfigStore{
		baseURL:         baseURL,
		apiKey:          strings.TrimSpace(apiKey),
		refreshInterval: refreshInterval,
		client: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

func (s *routeConfigStore) enabled() bool {
	return s != nil && s.baseURL != ""
}

func (s *routeConfigStore) setAuthHeader(req *http.Request) {
	if s.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	}
}

func (s *routeConfigStore) refreshIfStale(ctx context.Context) error {
	if !s.enabled() {
		return nil
	}
	s.mu.RLock()
	stale := time.Since(s.lastRefresh) >= s.refreshInterval
	s.mu.RUnlock()
	if !stale {
		return nil
	}
	return s.refresh(ctx)
}

func (s *routeConfigStore) refresh(ctx context.Context) error {
	if !s.enabled() {
		return nil
	}
	routes, err := s.fetchRoutes(ctx)
	if err != nil {
		s.setRefreshError(err)
		return err
	}
	domains, err := s.fetchDomains(ctx)
	if err != nil {
		s.setRefreshError(err)
		return err
	}

	s.mu.Lock()
	s.routes = routes
	s.domains = domains
	s.lastRefresh = time.Now()
	s.lastErr = nil
	s.mu.Unlock()
	return nil
}

func (s *routeConfigStore) fetchRoutes(ctx context.Context) ([]edgeRouteConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/v1/routes", nil)
	if err != nil {
		return nil, err
	}
	s.setAuthHeader(req)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control route config returned status %d", resp.StatusCode)
	}

	var payload edgeRoutesResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	routes := make([]edgeRouteConfig, 0, len(payload.Routes))
	for _, route := range payload.Routes {
		route.Host = normalizeRouteHost(route.Host)
		route.PathPrefix = normalizeRoutePathPrefix(route.PathPrefix)
		route.CachePolicy = normalizeEdgeCachePolicy(route.CachePolicy)
		originBase, err := url.Parse(route.OriginBaseURL)
		if err != nil || originBase.Host == "" || (originBase.Scheme != "http" && originBase.Scheme != "https") {
			continue
		}
		route.originBase = originBase
		route.deliveryRules = route.DeliveryRules.toRuntimeRules()
		route.wafRules = route.WAFRules.toRuntimeRules()
		route.rateLimitRules = edgeRateLimitRulesFromConfig(route.RateLimitRules, route.Host, route.PathPrefix)
		routes = append(routes, route)
	}
	sort.SliceStable(routes, func(i, j int) bool {
		if routes[i].Host == routes[j].Host {
			return len(routes[i].PathPrefix) > len(routes[j].PathPrefix)
		}
		return routes[i].Host < routes[j].Host
	})
	return routes, nil
}

func (s *routeConfigStore) fetchDomains(ctx context.Context) ([]edgeDomainConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/v1/domains", nil)
	if err != nil {
		return nil, err
	}
	s.setAuthHeader(req)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control domain config returned status %d", resp.StatusCode)
	}

	var payload edgeDomainsResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	domains := make([]edgeDomainConfig, 0, len(payload.Domains))
	for _, domain := range payload.Domains {
		domain.Host = normalizeRouteHost(domain.Host)
		domain.Status = strings.ToLower(strings.TrimSpace(domain.Status))
		if domain.Host == "" || (domain.Status != "" && domain.Status != "active") {
			continue
		}
		domains = append(domains, domain)
	}
	sort.SliceStable(domains, func(i, j int) bool {
		return domains[i].Host < domains[j].Host
	})
	return domains, nil
}

func (s *routeConfigStore) setRefreshError(err error) {
	s.mu.Lock()
	s.lastErr = err
	s.mu.Unlock()
}

func (s *routeConfigStore) match(host string, path string) (edgeRouteConfig, bool) {
	host = normalizeRouteHost(host)
	path = normalizeRoutePathPrefix(path)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, route := range s.routes {
		if route.Host != "*" && route.Host != host {
			continue
		}
		if strings.HasPrefix(path, route.PathPrefix) {
			return route, true
		}
	}
	return edgeRouteConfig{}, false
}

func (s *routeConfigStore) domainAllowed(host string) bool {
	host = normalizeRouteHost(host)
	if host == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, domain := range s.domains {
		if domain.Host == host {
			return true
		}
	}
	return false
}

func routeHost(r *http.Request) string {
	host := strings.TrimSpace(r.Host)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		return parsedHost
	}
	return host
}

func edgeOriginPath(r *http.Request) string {
	path := strings.TrimPrefix(r.URL.Path, "/edge")
	if path == "" {
		return "/"
	}
	return normalizeRoutePathPrefix(path)
}

func normalizeRouteHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func normalizeRoutePathPrefix(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	return "/" + strings.TrimLeft(path, "/")
}

func normalizeEdgeCachePolicy(policy edgeCachePolicy) edgeCachePolicy {
	policy.Mode = strings.ToLower(strings.TrimSpace(policy.Mode))
	switch policy.Mode {
	case "override", "bypass":
	default:
		policy.Mode = "origin"
	}
	if policy.Mode == "bypass" {
		policy.TTLSeconds = nil
		policy.StaleWhileRevalidateSeconds = nil
	}
	return policy
}

func newEdgeMetrics() *edgeMetrics {
	return &edgeMetrics{
		byHost:        make(map[string]*edgeCacheTotals),
		byRoute:       make(map[string]*edgeCacheTotals),
		invalidations: make(map[string]uint64),
	}
}

func (s *edgeServer) recordCacheMetric(layer string) {
	s.recordCacheMetricForDimensions(layer, "", "")
}

func (s *edgeServer) recordCacheMetricForRequest(layer string, r *http.Request, route requestRoute) {
	s.recordCacheMetricForDimensions(layer, cacheMetricHost(r), cacheMetricRoute(route, r))
}

func (s *edgeServer) recordCacheMetricForDimensions(layer string, host string, route string) {
	if s.metrics == nil {
		return
	}
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	switch layer {
	case "memory":
		s.metrics.memory++
	case "redis":
		s.metrics.redis++
	case "origin":
		s.metrics.miss++
	}
	if host != "" {
		incrementCacheTotals(cacheTotalsForDimension(s.metrics.byHost, host), layer)
	}
	if route != "" {
		incrementCacheTotals(cacheTotalsForDimension(s.metrics.byRoute, route), layer)
	}
}

func (s *edgeServer) recordCacheFillLatency(latency time.Duration) {
	if s.metrics == nil || latency < 0 {
		return
	}
	seconds := latency.Seconds()
	s.metrics.mu.Lock()
	s.metrics.cacheFillCount++
	s.metrics.cacheFillTotal += seconds
	if seconds > s.metrics.cacheFillMax {
		s.metrics.cacheFillMax = seconds
	}
	s.metrics.mu.Unlock()
}

func incrementCacheTotals(totals *edgeCacheTotals, layer string) {
	switch layer {
	case "memory":
		totals.memory++
	case "redis":
		totals.redis++
	case "origin":
		totals.miss++
	}
}

func cacheTotalsForDimension(values map[string]*edgeCacheTotals, key string) *edgeCacheTotals {
	totals := values[key]
	if totals == nil {
		totals = &edgeCacheTotals{}
		values[key] = totals
	}
	return totals
}

func (s *edgeServer) recordRateLimitBlock() {
	if s.metrics == nil {
		return
	}
	s.metrics.mu.Lock()
	s.metrics.rateLimited++
	s.metrics.mu.Unlock()
}

func (s *edgeServer) recordWAFBlock() {
	if s.metrics == nil {
		return
	}
	s.metrics.mu.Lock()
	s.metrics.wafBlocked++
	s.metrics.mu.Unlock()
}

func (s *edgeServer) recordInvalidation(mode string) {
	if s.metrics == nil {
		return
	}
	s.metrics.mu.Lock()
	s.metrics.invalidations[mode]++
	s.metrics.mu.Unlock()
}

func (s *edgeServer) recordInvalidationFailure() {
	if s.metrics == nil {
		return
	}
	s.metrics.mu.Lock()
	s.metrics.invalidationFailed++
	s.metrics.mu.Unlock()
}

func (s *edgeServer) metricsSnapshot() (uint64, uint64, uint64, uint64) {
	if s.metrics == nil {
		return 0, 0, 0, 0
	}
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()
	return s.metrics.memory, s.metrics.redis, s.metrics.miss, s.metrics.rateLimited
}

func (s *edgeServer) wafMetricsSnapshot() uint64 {
	if s.metrics == nil {
		return 0
	}
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()
	return s.metrics.wafBlocked
}

func (s *edgeServer) cacheDimensionSnapshots() (map[string]edgeCacheAnalyticsBreakout, map[string]edgeCacheAnalyticsBreakout) {
	if s.metrics == nil {
		return map[string]edgeCacheAnalyticsBreakout{}, map[string]edgeCacheAnalyticsBreakout{}
	}
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()
	return analyticsBreakoutsFromTotals(s.metrics.byHost), analyticsBreakoutsFromTotals(s.metrics.byRoute)
}

func (s *edgeServer) cacheFillLatencySnapshot() edgeCacheFillLatency {
	if s.metrics == nil {
		return edgeCacheFillLatency{}
	}
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()
	avg := 0.0
	if s.metrics.cacheFillCount > 0 {
		avg = s.metrics.cacheFillTotal / float64(s.metrics.cacheFillCount)
	}
	return edgeCacheFillLatency{
		Count:      s.metrics.cacheFillCount,
		SumSeconds: s.metrics.cacheFillTotal,
		AvgSeconds: avg,
		MaxSeconds: s.metrics.cacheFillMax,
	}
}

func (s *edgeServer) cacheAnalyticsSnapshot() edgeCacheAnalyticsResponse {
	memory, redisHits, misses, _ := s.metricsSnapshot()
	hits := memory + redisHits
	requests := hits + misses
	hitRatio := 0.0
	if requests > 0 {
		hitRatio = float64(hits) / float64(requests)
	}
	byHost, byRoute := s.cacheDimensionSnapshots()
	fill := s.cacheFillLatencySnapshot()
	return edgeCacheAnalyticsResponse{
		Cache: edgeCacheAnalytics{
			Requests: requests,
			Hits:     hits,
			Misses:   misses,
			HitRatio: hitRatio,
			ByLayer: map[string]edgeCacheCounter{
				"memory": {
					Result:   "hit",
					Requests: memory,
				},
				"redis": {
					Result:   "hit",
					Requests: redisHits,
				},
				"origin": {
					Result:   "miss",
					Requests: misses,
				},
			},
			ByHost:  byHost,
			ByRoute: byRoute,
			Fill:    fill,
		},
	}
}

func analyticsBreakoutsFromTotals(values map[string]*edgeCacheTotals) map[string]edgeCacheAnalyticsBreakout {
	out := make(map[string]edgeCacheAnalyticsBreakout, len(values))
	for key, totals := range values {
		if totals == nil {
			continue
		}
		out[key] = analyticsBreakoutFromTotals(*totals)
	}
	return out
}

func analyticsBreakoutFromTotals(totals edgeCacheTotals) edgeCacheAnalyticsBreakout {
	hits := totals.memory + totals.redis
	requests := hits + totals.miss
	hitRatio := 0.0
	if requests > 0 {
		hitRatio = float64(hits) / float64(requests)
	}
	return edgeCacheAnalyticsBreakout{
		Requests: requests,
		Hits:     hits,
		Misses:   totals.miss,
		HitRatio: hitRatio,
		ByLayer: map[string]edgeCacheCounter{
			"memory": {
				Result:   "hit",
				Requests: totals.memory,
			},
			"redis": {
				Result:   "hit",
				Requests: totals.redis,
			},
			"origin": {
				Result:   "miss",
				Requests: totals.miss,
			},
		},
	}
}

func (s *edgeServer) invalidationMetricsSnapshot() (map[string]uint64, uint64) {
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

func cacheMetricHost(r *http.Request) string {
	host := normalizeRouteHost(routeHost(r))
	if host == "" {
		return "-"
	}
	return host
}

func cacheMetricRoute(route requestRoute, r *http.Request) string {
	host := normalizeRouteHost(route.host)
	if host == "" {
		host = cacheMetricHost(r)
	}
	pathPrefix := normalizeRoutePathPrefix(route.pathPrefix)
	if pathPrefix == "" {
		pathPrefix = "/"
	}
	if !route.matched {
		return host + ":fallback:" + pathPrefix
	}
	return host + ":" + pathPrefix
}

func prometheusLabelValue(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return strings.ReplaceAll(value, "\"", "\\\"")
}

func cacheKeyForURL(u *url.URL) string {
	key := *u
	key.RawQuery = originRawQuery(u)
	return key.RequestURI()
}

func cacheKeyForRequest(r *http.Request) string {
	return cacheKeyForHostURL(routeHost(r), r.URL)
}

func cacheKeyForHostURL(host string, u *url.URL) string {
	host = normalizeRouteHost(host)
	if host == "" {
		host = "-"
	}
	return "host:" + host + ":" + cacheKeyForURL(u)
}

func segmentCacheKey(baseKey string, index int) string {
	return baseKey + segmentCacheKeySeparator + strconv.Itoa(index)
}

func hostScopedInvalidationValues(host string, values []string) []string {
	host = normalizeRouteHost(host)
	if host == "" {
		return values
	}

	scoped := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.HasPrefix(value, "host:") {
			scoped = append(scoped, value)
			continue
		}
		scoped = append(scoped, "host:"+host+":"+value)
	}
	return scoped
}

func cacheKeyRequestURI(key string) (string, bool) {
	key = stripVaryCacheKeySuffix(key)
	if !strings.HasPrefix(key, "host:") {
		return "", false
	}
	index := strings.Index(key, ":/")
	if index < 0 {
		return "", false
	}
	return key[index+1:], true
}

func cacheKeyMatchesExact(cacheKey string, invalidationKey string) bool {
	invalidationKey = strings.TrimSpace(invalidationKey)
	if invalidationKey == "" {
		return false
	}
	cacheKey = stripSegmentCacheKeySuffix(cacheKey)
	if stripVaryCacheKeySuffix(cacheKey) == invalidationKey {
		return true
	}
	requestURI, ok := cacheKeyRequestURI(cacheKey)
	return ok && requestURI == invalidationKey
}

func cacheKeyMatchesPrefix(cacheKey string, prefix string) bool {
	cacheKey = stripVaryCacheKeySuffix(stripSegmentCacheKeySuffix(cacheKey))
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return false
	}
	if strings.HasPrefix(cacheKey, prefix) {
		return true
	}
	requestURI, ok := cacheKeyRequestURI(cacheKey)
	return ok && strings.HasPrefix(requestURI, prefix)
}

func cacheKeyMatchesHost(cacheKey string, host string) bool {
	host = normalizeRouteHost(host)
	if host == "" {
		return true
	}
	cacheKey = stripVaryCacheKeySuffix(stripSegmentCacheKeySuffix(cacheKey))
	return strings.HasPrefix(cacheKey, "host:"+host+":")
}

func stripSegmentCacheKeySuffix(key string) string {
	if index := strings.LastIndex(key, segmentCacheKeySeparator); index >= 0 {
		return key[:index]
	}
	return key
}

func surrogateKeys(header http.Header) []string {
	return surrogateTagsFromValues(header.Values("Surrogate-Key"))
}

func surrogateTagsFromValues(values []string) []string {
	tags := make([]string, 0)
	seen := make(map[string]struct{})
	for _, value := range values {
		for _, token := range strings.FieldsFunc(value, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
		}) {
			token = strings.TrimSpace(token)
			if !validSurrogateTag(token) {
				continue
			}
			if _, ok := seen[token]; ok {
				continue
			}
			seen[token] = struct{}{}
			tags = append(tags, token)
		}
	}
	return tags
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

func keysToRemove(keys []string, host string) []any {
	out := make([]any, 0, len(keys))
	for _, key := range keys {
		if host == "" || cacheKeyMatchesHost(key, host) {
			out = append(out, key)
		}
	}
	return out
}

func originRawQuery(u *url.URL) string {
	values := u.Query()
	values.Del("expires")
	values.Del("signature")
	return values.Encode()
}

func joinURLPath(basePath, requestPath string) string {
	basePath = strings.TrimRight(basePath, "/")
	requestPath = "/" + strings.TrimLeft(requestPath, "/")
	if basePath == "" {
		return requestPath
	}
	return basePath + requestPath
}

func parseOriginBaseURLs(raw string) []*url.URL {
	values := splitCSV(raw)
	origins := make([]*url.URL, 0, len(values))
	for _, value := range values {
		originBase, err := url.Parse(value)
		if err != nil || originBase.Host == "" || (originBase.Scheme != "http" && originBase.Scheme != "https") {
			log.Printf("ignoring invalid origin failover URL %q", value)
			continue
		}
		origins = append(origins, originBase)
	}
	return origins
}

func newMemoryCache() *memoryCache {
	return &memoryCache{
		entries:      make(map[string]cacheEntry),
		vary:         make(map[string]map[string][]string),
		surrogate:    make(map[string]map[string]struct{}),
		keySurrogate: make(map[string]map[string]struct{}),
	}
}

func (c *memoryCache) get(key string) (cacheEntry, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return cacheEntry{}, false
	}
	if time.Now().After(entry.expiresAt) {
		return cacheEntry{}, false
	}
	return entry, true
}

func (c *memoryCache) getStale(key string, maxStale time.Duration) (cacheEntry, bool) {
	if c == nil || maxStale <= 0 {
		return cacheEntry{}, false
	}

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return cacheEntry{}, false
	}
	now := time.Now()
	if now.Before(entry.expiresAt) {
		return cacheEntry{}, false
	}
	if now.After(entry.expiresAt.Add(maxStale)) {
		c.mu.Lock()
		c.deleteCacheKeyLocked(key)
		c.mu.Unlock()
		return cacheEntry{}, false
	}
	return entry, true
}

func (c *memoryCache) getStaleIfError(key string) (cacheEntry, bool) {
	if c == nil {
		return cacheEntry{}, false
	}

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || time.Now().Before(entry.expiresAt) || !entryAllowsStaleIfError(entry) {
		return cacheEntry{}, false
	}
	return entry, true
}

func (c *memoryCache) set(key string, entry cacheEntry) {
	c.mu.Lock()
	c.entries[key] = entry
	c.mu.Unlock()
}

func (c *memoryCache) rememberSurrogateKeys(key string, tags []string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeSurrogateKeyLocked(key)
	for _, tag := range tags {
		if c.surrogate[tag] == nil {
			c.surrogate[tag] = make(map[string]struct{})
		}
		if c.keySurrogate[key] == nil {
			c.keySurrogate[key] = make(map[string]struct{})
		}
		c.surrogate[tag][key] = struct{}{}
		c.keySurrogate[key][tag] = struct{}{}
	}
}

func (c *memoryCache) rememberVarySpec(baseKey string, headers []string) {
	if c == nil || len(headers) == 0 {
		return
	}
	specKey := varySpecKey(headers)
	c.mu.Lock()
	if c.vary == nil {
		c.vary = make(map[string]map[string][]string)
	}
	if c.vary[baseKey] == nil {
		c.vary[baseKey] = make(map[string][]string)
	}
	c.vary[baseKey][specKey] = append([]string(nil), headers...)
	c.mu.Unlock()
}

func (c *memoryCache) varySpecs(baseKey string) [][]string {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	specs := make([][]string, 0, len(c.vary[baseKey]))
	for _, headers := range c.vary[baseKey] {
		specs = append(specs, append([]string(nil), headers...))
	}
	return specs
}

func (c *memoryCache) deleteKeys(keys []string) {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, key := range keys {
		for cacheKey := range c.entries {
			if cacheKeyMatchesExact(cacheKey, key) {
				c.deleteCacheKeyLocked(cacheKey)
			}
		}
		for baseKey := range c.vary {
			if cacheKeyMatchesExact(baseKey, key) {
				delete(c.vary, baseKey)
			}
		}
	}
}

func (c *memoryCache) deletePrefixes(prefixes []string) {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.entries {
		for _, prefix := range prefixes {
			if cacheKeyMatchesPrefix(key, prefix) {
				c.deleteCacheKeyLocked(key)
				break
			}
		}
	}
	for baseKey := range c.vary {
		for _, prefix := range prefixes {
			if cacheKeyMatchesPrefix(baseKey, prefix) {
				delete(c.vary, baseKey)
				break
			}
		}
	}
}

func (c *memoryCache) deleteTags(tags []string, host string) {
	if c == nil || len(tags) == 0 {
		return
	}

	host = normalizeRouteHost(host)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, tag := range surrogateTagsFromValues(tags) {
		for key := range c.surrogate[tag] {
			if host != "" && !cacheKeyMatchesHost(key, host) {
				continue
			}
			c.deleteCacheKeyLocked(key)
		}
		if host == "" {
			delete(c.surrogate, tag)
		}
	}
}

func (c *memoryCache) deleteCacheKeyLocked(key string) {
	delete(c.entries, key)
	c.removeSurrogateKeyLocked(key)
}

func (c *memoryCache) removeSurrogateKeyLocked(key string) {
	for tag := range c.keySurrogate[key] {
		delete(c.surrogate[tag], key)
		if len(c.surrogate[tag]) == 0 {
			delete(c.surrogate, tag)
		}
	}
	delete(c.keySurrogate, key)
}

func newRedisCache(addr string) *redisCache {
	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		Protocol:    2,
		DialTimeout: 2 * time.Second,
		ReadTimeout: 2 * time.Second,
	})
	return &redisCache{client: client}
}

func (c *redisCache) get(ctx context.Context, key string) (cacheEntry, bool) {
	if c == nil || c.client == nil {
		return cacheEntry{}, false
	}

	payload, err := c.client.Get(ctx, redisKey(key)).Bytes()
	if err != nil {
		if err != redis.Nil {
			log.Printf("redis cache get failed key=%s err=%v", key, err)
		}
		return cacheEntry{}, false
	}

	var entry cacheEntry
	if err := json.Unmarshal(payload, &entry); err != nil {
		log.Printf("redis cache decode failed key=%s err=%v", key, err)
		return cacheEntry{}, false
	}
	if time.Now().After(entry.expiresAt) {
		return cacheEntry{}, false
	}
	return entry, true
}

func (c *redisCache) getStale(ctx context.Context, key string, maxStale time.Duration) (cacheEntry, bool) {
	if c == nil || c.client == nil || maxStale <= 0 {
		return cacheEntry{}, false
	}

	payload, err := c.client.Get(ctx, redisKey(key)).Bytes()
	if err != nil {
		if err != redis.Nil {
			log.Printf("redis stale cache get failed key=%s err=%v", key, err)
		}
		return cacheEntry{}, false
	}

	var entry cacheEntry
	if err := json.Unmarshal(payload, &entry); err != nil {
		log.Printf("redis stale cache decode failed key=%s err=%v", key, err)
		return cacheEntry{}, false
	}
	now := time.Now()
	if now.Before(entry.expiresAt) {
		return cacheEntry{}, false
	}
	if now.After(entry.expiresAt.Add(maxStale)) {
		_ = c.client.Del(ctx, redisKey(key)).Err()
		return cacheEntry{}, false
	}
	return entry, true
}

func (c *redisCache) getStaleIfError(ctx context.Context, key string) (cacheEntry, bool) {
	if c == nil || c.client == nil {
		return cacheEntry{}, false
	}

	payload, err := c.client.Get(ctx, redisKey(key)).Bytes()
	if err != nil {
		if err != redis.Nil {
			log.Printf("redis stale-if-error cache get failed key=%s err=%v", key, err)
		}
		return cacheEntry{}, false
	}

	var entry cacheEntry
	if err := json.Unmarshal(payload, &entry); err != nil {
		log.Printf("redis stale-if-error cache decode failed key=%s err=%v", key, err)
		return cacheEntry{}, false
	}
	if time.Now().Before(entry.expiresAt) || !entryAllowsStaleIfError(entry) {
		return cacheEntry{}, false
	}
	return entry, true
}

func (c *redisCache) set(ctx context.Context, key string, entry cacheEntry, ttl time.Duration) {
	if c == nil || c.client == nil {
		return
	}

	payload, err := json.Marshal(toRedisCacheEntry(entry))
	if err != nil {
		log.Printf("redis cache encode failed key=%s err=%v", key, err)
		return
	}
	if err := c.client.Set(ctx, redisKey(key), payload, ttl).Err(); err != nil {
		log.Printf("redis cache set failed key=%s err=%v", key, err)
	}
}

func (c *redisCache) rememberSurrogateKeys(ctx context.Context, cacheKey string, tags []string, ttl time.Duration) {
	if c == nil || c.client == nil || len(tags) == 0 {
		return
	}
	for _, tag := range tags {
		key := redisSurrogateKey(tag)
		if err := c.client.SAdd(ctx, key, cacheKey).Err(); err != nil {
			log.Printf("redis surrogate index set failed tag=%s key=%s err=%v", tag, cacheKey, err)
			continue
		}
		if ttl > 0 {
			_ = c.client.Expire(ctx, key, ttl).Err()
		}
	}
}

func (c *redisCache) rememberVarySpec(ctx context.Context, baseKey string, headers []string, ttl time.Duration) {
	if c == nil || c.client == nil || len(headers) == 0 {
		return
	}
	key := redisVaryKey(baseKey)
	if err := c.client.SAdd(ctx, key, varySpecKey(headers)).Err(); err != nil {
		log.Printf("redis vary index set failed key=%s err=%v", baseKey, err)
		return
	}
	if ttl > 0 {
		_ = c.client.Expire(ctx, key, ttl).Err()
	}
}

func (c *redisCache) varySpecs(ctx context.Context, baseKey string) [][]string {
	if c == nil || c.client == nil {
		return nil
	}
	values, err := c.client.SMembers(ctx, redisVaryKey(baseKey)).Result()
	if err != nil {
		if err != redis.Nil {
			log.Printf("redis vary index get failed key=%s err=%v", baseKey, err)
		}
		return nil
	}
	specs := make([][]string, 0, len(values))
	for _, value := range values {
		headers := parseVarySpecKey(value)
		if len(headers) > 0 {
			specs = append(specs, headers)
		}
	}
	return specs
}

func (c *redisCache) deleteKeys(ctx context.Context, keys []string) error {
	if c == nil || c.client == nil || len(keys) == 0 {
		return nil
	}

	redisKeys := make([]string, 0, len(keys))
	for _, key := range keys {
		redisKeys = append(redisKeys, redisKey(key))
		redisKeys = append(redisKeys, redisVaryKey(key))
	}
	if err := c.client.Del(ctx, redisKeys...).Err(); err != nil {
		return err
	}

	for _, key := range keys {
		if err := c.deleteByScan(ctx, redisKey(key)+varyCacheKeySeparator+"*", func(cacheKey string) bool {
			return cacheKeyMatchesExact(cacheKey, key)
		}); err != nil {
			return err
		}
		if err := c.deleteVaryIndexesByScan(ctx, redisVaryKey(key)+"*", func(baseKey string) bool {
			return cacheKeyMatchesExact(baseKey, key)
		}); err != nil {
			return err
		}
		if !strings.HasPrefix(strings.TrimSpace(key), "/") {
			continue
		}
		if err := c.deleteByScan(ctx, redisKey("host:*:/*"), func(cacheKey string) bool {
			return cacheKeyMatchesExact(cacheKey, key)
		}); err != nil {
			return err
		}
		if err := c.deleteVaryIndexesByScan(ctx, redisVaryKey("host:*:/*"), func(baseKey string) bool {
			return cacheKeyMatchesExact(baseKey, key)
		}); err != nil {
			return err
		}
	}
	return nil
}

func (c *redisCache) deletePrefixes(ctx context.Context, prefixes []string) error {
	if c == nil || c.client == nil || len(prefixes) == 0 {
		return nil
	}

	for _, prefix := range prefixes {
		if err := c.deleteByScan(ctx, redisScanPattern(prefix), func(cacheKey string) bool {
			return strings.HasPrefix(cacheKey, prefix)
		}); err != nil {
			return err
		}
		if err := c.deleteVaryIndexesByScan(ctx, redisVaryScanPattern(prefix), func(baseKey string) bool {
			return cacheKeyMatchesPrefix(baseKey, prefix)
		}); err != nil {
			return err
		}
		if !strings.HasPrefix(strings.TrimSpace(prefix), "/") {
			continue
		}
		if err := c.deleteByScan(ctx, redisHostScanPattern(prefix), func(cacheKey string) bool {
			return cacheKeyMatchesPrefix(cacheKey, prefix)
		}); err != nil {
			return err
		}
		if err := c.deleteVaryIndexesByScan(ctx, redisHostVaryScanPattern(prefix), func(baseKey string) bool {
			return cacheKeyMatchesPrefix(baseKey, prefix)
		}); err != nil {
			return err
		}
	}
	return nil
}

func (c *redisCache) deleteTags(ctx context.Context, tags []string, host string) error {
	if c == nil || c.client == nil || len(tags) == 0 {
		return nil
	}

	host = normalizeRouteHost(host)
	for _, tag := range surrogateTagsFromValues(tags) {
		indexKey := redisSurrogateKey(tag)
		keys, err := c.client.SMembers(ctx, indexKey).Result()
		if err != nil {
			if err == redis.Nil {
				continue
			}
			return err
		}
		redisKeys := make([]string, 0, len(keys))
		for _, key := range keys {
			if host != "" && !cacheKeyMatchesHost(key, host) {
				continue
			}
			redisKeys = append(redisKeys, redisKey(key))
		}
		if len(redisKeys) > 0 {
			if err := c.client.Del(ctx, redisKeys...).Err(); err != nil {
				return err
			}
			if err := c.client.SRem(ctx, indexKey, keysToRemove(keys, host)...).Err(); err != nil {
				return err
			}
		}
		if host == "" {
			if err := c.client.Del(ctx, indexKey).Err(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *redisCache) deleteByScan(ctx context.Context, pattern string, shouldDelete func(string) bool) error {
	var cursor uint64
	for {
		keys, nextCursor, err := c.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return err
		}
		deleteKeys := make([]string, 0, len(keys))
		for _, key := range keys {
			cacheKey := strings.TrimPrefix(key, "astracdn:edge-cache:")
			if shouldDelete(cacheKey) {
				deleteKeys = append(deleteKeys, key)
			}
		}
		if len(deleteKeys) > 0 {
			if err := c.client.Del(ctx, deleteKeys...).Err(); err != nil {
				return err
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return nil
}

func (c *redisCache) deleteVaryIndexesByScan(ctx context.Context, pattern string, shouldDelete func(string) bool) error {
	var cursor uint64
	for {
		keys, nextCursor, err := c.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return err
		}
		deleteKeys := make([]string, 0, len(keys))
		for _, key := range keys {
			baseKey := strings.TrimPrefix(key, "astracdn:edge-cache-vary:")
			if shouldDelete(baseKey) {
				deleteKeys = append(deleteKeys, key)
			}
		}
		if len(deleteKeys) > 0 {
			if err := c.client.Del(ctx, deleteKeys...).Err(); err != nil {
				return err
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return nil
}

func (c *redisCache) ping(ctx context.Context) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("redis client missing")
	}
	return c.client.Ping(ctx).Err()
}

func (c *redisCache) close() {
	if c == nil || c.client == nil {
		return
	}
	if err := c.client.Close(); err != nil {
		log.Printf("redis close failed: %v", err)
	}
}

func redisKey(key string) string {
	return "astracdn:edge-cache:" + key
}

func redisVaryKey(baseKey string) string {
	return "astracdn:edge-cache-vary:" + baseKey
}

func redisSurrogateKey(tag string) string {
	return "astracdn:edge-cache-surrogate:" + tag
}

func redisScanPattern(prefix string) string {
	return redisKey(prefix) + "*"
}

func redisHostScanPattern(prefix string) string {
	return redisKey("host:*:" + strings.TrimSpace(prefix) + "*")
}

func redisVaryScanPattern(prefix string) string {
	return redisVaryKey(prefix) + "*"
}

func redisHostVaryScanPattern(prefix string) string {
	return redisVaryKey("host:*:" + strings.TrimSpace(prefix) + "*")
}

func stripVaryCacheKeySuffix(key string) string {
	base, _, _ := strings.Cut(key, varyCacheKeySeparator)
	return base
}

func varyCacheKey(baseKey string, headers []string, r *http.Request) string {
	parts := make([]string, 0, len(headers))
	for _, header := range headers {
		parts = append(parts, header+"="+strings.Join(r.Header.Values(header), ","))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return baseKey + varyCacheKeySeparator + hex.EncodeToString(sum[:])
}

func varyHeaderNames(vary string) []string {
	seen := make(map[string]struct{})
	headers := make([]string, 0)
	for _, raw := range strings.Split(vary, ",") {
		header := http.CanonicalHeaderKey(strings.TrimSpace(raw))
		if header == "" || header == "*" {
			continue
		}
		key := strings.ToLower(header)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		headers = append(headers, header)
	}
	sort.Slice(headers, func(i, j int) bool {
		return strings.ToLower(headers[i]) < strings.ToLower(headers[j])
	})
	return headers
}

func responseVaryCacheable(header http.Header) bool {
	for _, raw := range strings.Split(header.Get("Vary"), ",") {
		if strings.TrimSpace(raw) == "*" {
			return false
		}
	}
	return true
}

func varySpecKey(headers []string) string {
	normalized := append([]string(nil), headers...)
	for i := range normalized {
		normalized[i] = http.CanonicalHeaderKey(strings.TrimSpace(normalized[i]))
	}
	sort.Slice(normalized, func(i, j int) bool {
		return strings.ToLower(normalized[i]) < strings.ToLower(normalized[j])
	})
	return strings.Join(normalized, "\n")
}

func parseVarySpecKey(value string) []string {
	headers := varyHeaderNames(strings.ReplaceAll(value, "\n", ","))
	if len(headers) == 0 {
		return nil
	}
	return headers
}

func (v signedURLValidator) validate(u *url.URL) bool {
	if !v.enabled {
		return true
	}
	if v.secret == "" {
		return false
	}

	expires := u.Query().Get("expires")
	signature := u.Query().Get("signature")
	if expires == "" || signature == "" {
		return false
	}

	expiresAt, err := strconv.ParseInt(expires, 10, 64)
	if err != nil {
		return false
	}
	now := time.Now
	if v.now != nil {
		now = v.now
	}
	if now().Unix() > expiresAt {
		return false
	}

	expected := signedURLSignature(v.secret, u.Path, originRawQuery(u), expires)
	return subtle.ConstantTimeCompare([]byte(signature), []byte(expected)) == 1
}

func signedURLSignature(secret, path, rawQuery, expires string) string {
	payload := path + "\n" + rawQuery + "\n" + expires
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func (v signedCookieValidator) validate(r *http.Request) bool {
	if !v.enabled || r == nil || r.URL == nil {
		return true
	}
	prefix, ok := v.matchingPrefix(r.URL.Path)
	if !ok {
		return true
	}
	if v.secret == "" || v.cookieName == "" {
		return false
	}
	cookie, err := r.Cookie(v.cookieName)
	if err != nil {
		return false
	}
	expires, signature, ok := strings.Cut(strings.TrimSpace(cookie.Value), ":")
	if !ok || expires == "" || signature == "" {
		return false
	}
	expiresAt, err := strconv.ParseInt(expires, 10, 64)
	if err != nil {
		return false
	}
	now := time.Now
	if v.now != nil {
		now = v.now
	}
	if now().Unix() > expiresAt {
		return false
	}
	expected := signedCookieSignature(v.secret, prefix, expires)
	return subtle.ConstantTimeCompare([]byte(signature), []byte(expected)) == 1
}

func (v signedCookieValidator) matchingPrefix(path string) (string, bool) {
	for _, prefix := range v.pathPrefixes {
		prefix = strings.TrimSpace(prefix)
		if prefix != "" && strings.HasPrefix(path, prefix) {
			return prefix, true
		}
	}
	return "", false
}

func signedCookieSignature(secret, pathPrefix, expires string) string {
	payload := "cookie\n" + pathPrefix + "\n" + expires
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *edgeServer) allowRequest(r *http.Request) bool {
	if s.limiter == nil {
		return true
	}
	return s.limiter.allow(r)
}

func (s *edgeServer) allowScopedRequest(r *http.Request, route requestRoute) bool {
	if s.scopedLimiter == nil {
		if len(route.rateLimitRules) == 0 {
			return true
		}
		s.scopedLimiter = &edgeScopedRateLimiter{
			enabled: true,
			now:     time.Now,
			buckets: make(map[string]*rateLimitBucket),
		}
	}
	if !s.scopedLimiter.allow(r) {
		return false
	}
	return s.scopedLimiter.allowRules(r, route.rateLimitRules)
}

func newEdgeWAFRulesFromEnv() edgeWAFRules {
	rules := edgeWAFRules{
		enabled: envBool("EDGE_WAF_ENABLED", false),
		methods: make(map[string]struct{}),
	}
	for _, method := range splitCSV(env("EDGE_WAF_BLOCK_METHODS", "")) {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method != "" {
			rules.methods[method] = struct{}{}
		}
	}
	for _, prefix := range splitCSV(env("EDGE_WAF_BLOCK_PATH_PREFIXES", "")) {
		if prefix != "" {
			rules.pathPrefixes = append(rules.pathPrefixes, prefix)
		}
	}
	for _, raw := range splitCSV(env("EDGE_WAF_BLOCK_HEADERS", "")) {
		name, value, ok := strings.Cut(raw, "=")
		if !ok {
			name, value, ok = strings.Cut(raw, ":")
		}
		name = http.CanonicalHeaderKey(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		if ok && name != "" && value != "" {
			rules.headers = append(rules.headers, edgeWAFHeaderRule{name: name, valueContains: strings.ToLower(value)})
		}
	}
	for _, raw := range splitCSV(env("EDGE_WAF_BLOCK_IPS", "")) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, cidr, err := net.ParseCIDR(raw); err == nil {
			rules.ips = append(rules.ips, edgeWAFIPRule{cidr: cidr})
			continue
		}
		if ip := net.ParseIP(raw); ip != nil {
			rules.ips = append(rules.ips, edgeWAFIPRule{exact: ip.String()})
		}
	}
	return rules
}

func (c edgeWAFRulesConfig) toRuntimeRules() edgeWAFRules {
	rules := edgeWAFRules{
		enabled: c.Enabled == nil || *c.Enabled,
		methods: make(map[string]struct{}),
	}
	for _, method := range c.Methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method != "" {
			rules.methods[method] = struct{}{}
		}
	}
	for _, prefix := range c.PathPrefixes {
		prefix = strings.TrimSpace(prefix)
		if prefix != "" {
			rules.pathPrefixes = append(rules.pathPrefixes, prefix)
		}
	}
	for _, rule := range c.Headers {
		name := http.CanonicalHeaderKey(strings.TrimSpace(rule.Name))
		value := strings.ToLower(strings.TrimSpace(rule.ValueContains))
		if name != "" && value != "" {
			rules.headers = append(rules.headers, edgeWAFHeaderRule{name: name, valueContains: value})
		}
	}
	for _, raw := range c.IPs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, cidr, err := net.ParseCIDR(raw); err == nil {
			rules.ips = append(rules.ips, edgeWAFIPRule{cidr: cidr})
			continue
		}
		if ip := net.ParseIP(raw); ip != nil {
			rules.ips = append(rules.ips, edgeWAFIPRule{exact: ip.String()})
		}
	}
	if len(rules.methods) == 0 && len(rules.pathPrefixes) == 0 && len(rules.headers) == 0 && len(rules.ips) == 0 {
		rules.enabled = false
	}
	return rules
}

func (w edgeWAFRules) blocks(r *http.Request) bool {
	if !w.enabled || r == nil {
		return false
	}
	if _, blocked := w.methods[strings.ToUpper(r.Method)]; blocked {
		return true
	}
	for _, prefix := range w.pathPrefixes {
		if strings.HasPrefix(r.URL.Path, prefix) {
			return true
		}
	}
	for _, rule := range w.headers {
		for _, value := range r.Header.Values(rule.name) {
			if strings.Contains(strings.ToLower(value), rule.valueContains) {
				return true
			}
		}
	}
	ip := net.ParseIP(clientIP(r))
	if ip != nil {
		normalized := ip.String()
		for _, rule := range w.ips {
			if rule.exact != "" && rule.exact == normalized {
				return true
			}
			if rule.cidr != nil && rule.cidr.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func newEdgeDeliveryRulesFromEnv() edgeDeliveryRules {
	return edgeDeliveryRules{
		setHeaders:    parseEdgeHeaderSetRules(env("EDGE_RESPONSE_SET_HEADERS", "")),
		removeHeaders: parseEdgeHeaderRemoveRules(env("EDGE_RESPONSE_REMOVE_HEADERS", "")),
		redirects:     parseEdgeRedirectRules(env("EDGE_REDIRECT_RULES", "")),
	}
}

func (s *edgeServer) applyDeliveryHeaders(header http.Header, path string, route requestRoute) {
	s.deliveryRules.applyHeaders(header, path)
	route.rules.applyHeaders(header, path)
}

func (c edgeDeliveryRulesConfig) toRuntimeRules() edgeDeliveryRules {
	rules := edgeDeliveryRules{}
	for _, rule := range c.SetHeaders {
		name := http.CanonicalHeaderKey(strings.TrimSpace(rule.Name))
		value := strings.TrimSpace(rule.Value)
		if name == "" || value == "" {
			continue
		}
		rules.setHeaders = append(rules.setHeaders, edgeHeaderSetRule{
			pathPrefix: normalizeDeliveryRulePathPrefix(rule.PathPrefix),
			name:       name,
			value:      value,
		})
	}
	for _, rule := range c.RemoveHeaders {
		name := http.CanonicalHeaderKey(strings.TrimSpace(rule.Name))
		if name == "" {
			continue
		}
		rules.removeHeaders = append(rules.removeHeaders, edgeHeaderRemoveRule{
			pathPrefix: normalizeDeliveryRulePathPrefix(rule.PathPrefix),
			name:       name,
		})
	}
	for _, rule := range c.Redirects {
		target := strings.TrimSpace(rule.Target)
		if target == "" || !validRedirectStatus(rule.Status) {
			continue
		}
		rules.redirects = append(rules.redirects, edgeRedirectRule{
			pathPrefix: normalizeDeliveryRulePathPrefix(rule.PathPrefix),
			target:     target,
			status:     rule.Status,
		})
	}
	return rules
}

func normalizeDeliveryRulePathPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return "*"
	}
	return prefix
}

func parseEdgeHeaderSetRules(raw string) []edgeHeaderSetRule {
	rules := []edgeHeaderSetRule{}
	for _, part := range splitCSV(raw) {
		scope, expression := splitScopedRule(part)
		name, value, ok := strings.Cut(expression, "=")
		name = http.CanonicalHeaderKey(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		if ok && name != "" {
			rules = append(rules, edgeHeaderSetRule{pathPrefix: scope, name: name, value: value})
		}
	}
	return rules
}

func parseEdgeHeaderRemoveRules(raw string) []edgeHeaderRemoveRule {
	rules := []edgeHeaderRemoveRule{}
	for _, part := range splitCSV(raw) {
		scope, name := splitScopedRule(part)
		name = http.CanonicalHeaderKey(strings.TrimSpace(name))
		if name != "" {
			rules = append(rules, edgeHeaderRemoveRule{pathPrefix: scope, name: name})
		}
	}
	return rules
}

func parseEdgeRedirectRules(raw string) []edgeRedirectRule {
	rules := []edgeRedirectRule{}
	for _, part := range splitCSV(raw) {
		scope, expression := splitScopedRule(part)
		target, rawStatus, _ := strings.Cut(expression, "|")
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		status := http.StatusFound
		if parsed, err := strconv.Atoi(strings.TrimSpace(rawStatus)); err == nil && validRedirectStatus(parsed) {
			status = parsed
		}
		rules = append(rules, edgeRedirectRule{pathPrefix: scope, target: target, status: status})
	}
	return rules
}

func splitScopedRule(raw string) (string, string) {
	scope, expression, ok := strings.Cut(strings.TrimSpace(raw), "|")
	if !ok {
		return "*", strings.TrimSpace(raw)
	}
	scope = strings.TrimSpace(scope)
	if scope == "" {
		scope = "*"
	}
	return scope, strings.TrimSpace(expression)
}

func validRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func (r edgeDeliveryRules) applyHeaders(header http.Header, path string) {
	if header == nil {
		return
	}
	for _, rule := range r.removeHeaders {
		if pathRuleMatches(rule.pathPrefix, path) {
			header.Del(rule.name)
		}
	}
	for _, rule := range r.setHeaders {
		if pathRuleMatches(rule.pathPrefix, path) {
			header.Set(rule.name, rule.value)
		}
	}
}

func (r edgeDeliveryRules) redirect(req *http.Request) (string, int, bool) {
	if req == nil || req.URL == nil {
		return "", 0, false
	}
	for _, rule := range r.redirects {
		if pathRuleMatches(rule.pathPrefix, req.URL.Path) {
			return expandRedirectTarget(rule.target, req), rule.status, true
		}
	}
	return "", 0, false
}

func pathRuleMatches(prefix string, path string) bool {
	prefix = strings.TrimSpace(prefix)
	return prefix == "" || prefix == "*" || strings.HasPrefix(path, prefix)
}

func expandRedirectTarget(target string, r *http.Request) string {
	replacer := strings.NewReplacer(
		"{path}", r.URL.Path,
		"{query}", r.URL.RawQuery,
	)
	return replacer.Replace(target)
}

func newRateLimiterFromEnv() *rateLimiter {
	return newRateLimiter(
		strings.ToLower(env("RATE_LIMIT_ENABLED", "true")) == "true",
		envFloat("RATE_LIMIT_RPS", 5),
		envFloat("RATE_LIMIT_BURST", 10),
	)
}

func newEdgeScopedRateLimiterFromEnv() *edgeScopedRateLimiter {
	rules := parseEdgeRateLimitRules(env("EDGE_RATE_LIMIT_RULES", ""))
	if len(rules) == 0 {
		return &edgeScopedRateLimiter{enabled: false}
	}
	return &edgeScopedRateLimiter{
		enabled: true,
		now:     time.Now,
		rules:   rules,
		buckets: make(map[string]*rateLimitBucket),
	}
}

func parseEdgeRateLimitRules(raw string) []edgeRateLimitRule {
	rules := []edgeRateLimitRule{}
	for _, part := range splitCSV(raw) {
		fields := strings.Split(part, "|")
		if len(fields) != 4 {
			continue
		}
		host := normalizeRouteHost(fields[0])
		if host == "" {
			host = "*"
		}
		pathPrefix := strings.TrimSpace(fields[1])
		if pathPrefix == "" {
			pathPrefix = "*"
		}
		rps, errRPS := strconv.ParseFloat(strings.TrimSpace(fields[2]), 64)
		burst, errBurst := strconv.ParseFloat(strings.TrimSpace(fields[3]), 64)
		if errRPS != nil || errBurst != nil || rps <= 0 || burst <= 0 {
			continue
		}
		rules = append(rules, edgeRateLimitRule{
			host:       host,
			pathPrefix: pathPrefix,
			rps:        rps,
			burst:      burst,
		})
	}
	return rules
}

func edgeRateLimitRulesFromConfig(configs []edgeRateLimitRuleConfig, routeHost string, routePathPrefix string) []edgeRateLimitRule {
	rules := make([]edgeRateLimitRule, 0, len(configs))
	defaultHost := normalizeRouteHost(routeHost)
	defaultPath := normalizeRoutePathPrefix(routePathPrefix)
	for _, config := range configs {
		host := normalizeRouteHost(config.Host)
		if host == "" {
			host = defaultHost
		}
		if host == "" {
			host = "*"
		}
		pathPrefix := strings.TrimSpace(config.PathPrefix)
		if pathPrefix == "" {
			pathPrefix = defaultPath
		}
		if pathPrefix == "" {
			pathPrefix = "*"
		}
		if config.RPS <= 0 || config.Burst <= 0 {
			continue
		}
		rules = append(rules, edgeRateLimitRule{
			host:       host,
			pathPrefix: pathPrefix,
			rps:        config.RPS,
			burst:      config.Burst,
		})
	}
	return rules
}

func (l *edgeScopedRateLimiter) allow(r *http.Request) bool {
	if l == nil || !l.enabled {
		return true
	}
	ruleIndex, rule, ok := l.match(r)
	if !ok {
		return true
	}
	now := time.Now()
	if l.now != nil {
		now = l.now()
	}

	key := fmt.Sprintf("%d:%s", ruleIndex, rateLimitKey(r))
	l.mu.Lock()
	defer l.mu.Unlock()

	bucket := l.buckets[key]
	if bucket == nil {
		bucket = &rateLimitBucket{tokens: rule.burst, last: now}
		l.buckets[key] = bucket
	}
	elapsed := now.Sub(bucket.last).Seconds()
	if elapsed > 0 {
		bucket.tokens = min(rule.burst, bucket.tokens+elapsed*rule.rps)
		bucket.last = now
	}
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func (l *edgeScopedRateLimiter) allowRules(r *http.Request, rules []edgeRateLimitRule) bool {
	if l == nil || len(rules) == 0 {
		return true
	}
	ruleIndex, rule, ok := matchEdgeRateLimitRule(rules, r)
	if !ok {
		return true
	}
	now := time.Now()
	if l.now != nil {
		now = l.now()
	}
	key := fmt.Sprintf("route:%s:%d:%s", rule.host+"|"+rule.pathPrefix, ruleIndex, rateLimitKey(r))
	return l.allowBucket(key, rule, now)
}

func (l *edgeScopedRateLimiter) allowBucket(key string, rule edgeRateLimitRule, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	bucket := l.buckets[key]
	if bucket == nil {
		bucket = &rateLimitBucket{tokens: rule.burst, last: now}
		l.buckets[key] = bucket
	}
	elapsed := now.Sub(bucket.last).Seconds()
	if elapsed > 0 {
		bucket.tokens = min(rule.burst, bucket.tokens+elapsed*rule.rps)
		bucket.last = now
	}
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func (l *edgeScopedRateLimiter) match(r *http.Request) (int, edgeRateLimitRule, bool) {
	if r == nil || r.URL == nil {
		return 0, edgeRateLimitRule{}, false
	}
	return matchEdgeRateLimitRule(l.rules, r)
}

func matchEdgeRateLimitRule(rules []edgeRateLimitRule, r *http.Request) (int, edgeRateLimitRule, bool) {
	if r == nil || r.URL == nil {
		return 0, edgeRateLimitRule{}, false
	}
	host := routeHost(r)
	path := r.URL.Path
	for i, rule := range rules {
		if rule.host != "*" && rule.host != host {
			continue
		}
		if !pathRuleMatches(rule.pathPrefix, path) {
			continue
		}
		return i, rule, true
	}
	return 0, edgeRateLimitRule{}, false
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
	if strings.ToLower(env("RATE_LIMIT_ENABLED", "true")) != "true" && !isLocalEnv() {
		return fmt.Errorf("RATE_LIMIT_ENABLED must remain true outside local development")
	}
	if strings.ToLower(env("EDGE_SIGNING_ENABLED", "false")) != "true" && strings.ToLower(env("EDGE_SIGNED_COOKIE_ENABLED", "false")) != "true" {
		return nil
	}

	secret := env("EDGE_SIGNING_SECRET", "")
	if len(secret) < 32 {
		return fmt.Errorf("EDGE_SIGNING_SECRET must be at least 32 characters when signed URLs or signed cookies are enabled")
	}
	if !isLocalEnv() && secret == "astracdn-local-signing-secret" {
		return fmt.Errorf("EDGE_SIGNING_SECRET must be set to a non-default value outside local development")
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

func toRedisCacheEntry(entry cacheEntry) redisCacheEntry {
	return redisCacheEntry{
		Status:       entry.status,
		Header:       entry.header,
		Body:         entry.body,
		ExpiresAt:    entry.expiresAt,
		Segmented:    entry.segmented,
		ObjectSize:   entry.objectSize,
		SegmentSize:  entry.segmentSize,
		SegmentCount: entry.segmentCount,
	}
}

func (entry *cacheEntry) UnmarshalJSON(data []byte) error {
	var wire redisCacheEntry
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	entry.status = wire.Status
	entry.header = wire.Header
	entry.body = wire.Body
	entry.expiresAt = wire.ExpiresAt
	entry.segmented = wire.Segmented
	entry.objectSize = wire.ObjectSize
	entry.segmentSize = wire.SegmentSize
	entry.segmentCount = wire.SegmentCount
	return nil
}

func cacheTTL(cacheControl string) time.Duration {
	directives := cacheControlDirectives(cacheControl)
	if _, ok := directives["no-store"]; ok {
		return 0
	}
	if _, ok := directives["private"]; ok {
		return 0
	}
	if value, ok := directives["s-maxage"]; ok {
		return secondsTTL(value)
	}
	if value, ok := directives["max-age"]; ok {
		return secondsTTL(value)
	}
	return 0
}

func cacheControlDirectives(cacheControl string) map[string]string {
	directives := make(map[string]string)
	for _, directive := range strings.Split(cacheControl, ",") {
		directive = strings.TrimSpace(strings.ToLower(directive))
		if directive == "" {
			continue
		}
		key, value, hasValue := strings.Cut(directive, "=")
		if hasValue {
			directives[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"`)
		} else {
			directives[directive] = ""
		}
	}
	return directives
}

func secondsTTL(raw string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func ttlForPolicy(policy edgeCachePolicy, cacheControl string) time.Duration {
	policy = normalizeEdgeCachePolicy(policy)
	if hasSharedCacheBlocker(cacheControl) {
		return 0
	}
	switch policy.Mode {
	case "bypass":
		return 0
	case "override":
		if policy.TTLSeconds == nil || *policy.TTLSeconds <= 0 {
			return 0
		}
		return time.Duration(*policy.TTLSeconds) * time.Second
	default:
		return cacheTTL(cacheControl)
	}
}

func ttlForRequest(policy edgeCachePolicy, r *http.Request, cacheControl string) time.Duration {
	policy = normalizeEdgeCachePolicy(policy)
	if r != nil && strings.TrimSpace(r.Header.Get("Authorization")) != "" && policy.Mode != "override" {
		return 0
	}
	return ttlForPolicy(policy, cacheControl)
}

func ttlForStorage(policy edgeCachePolicy, r *http.Request, header http.Header) time.Duration {
	ttl := ttlForRequest(policy, r, header.Get("Cache-Control"))
	if ttl > 0 {
		return ttl
	}
	cacheControl := header.Get("Cache-Control")
	if responseRequiresRevalidation(cacheControl) && !hasSharedCacheBlocker(cacheControl) && hasValidators(header) && ttlForRequest(policy, r, "max-age=1") > 0 {
		return time.Nanosecond
	}
	return 0
}

func requestRequiresRevalidation(r *http.Request) bool {
	if r == nil {
		return false
	}
	if hasCacheControlDirective(r.Header.Get("Cache-Control"), "no-cache") {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Pragma")), "no-cache")
}

func entryRequiresRevalidation(entry cacheEntry) bool {
	return responseRequiresRevalidation(entry.header.Get("Cache-Control"))
}

func responseRequiresRevalidation(cacheControl string) bool {
	return hasCacheControlDirective(cacheControl, "no-cache")
}

func hasCacheControlDirective(cacheControl string, directive string) bool {
	_, ok := cacheControlDirectives(cacheControl)[strings.ToLower(strings.TrimSpace(directive))]
	return ok
}

func hasSharedCacheBlocker(cacheControl string) bool {
	directives := cacheControlDirectives(cacheControl)
	_, noStore := directives["no-store"]
	_, private := directives["private"]
	return noStore || private
}

func entryAllowsStaleIfError(entry cacheEntry) bool {
	cacheControl := entry.header.Get("Cache-Control")
	if hasSharedCacheBlocker(cacheControl) {
		return false
	}

	window := staleIfErrorWindow(cacheControl)
	if window <= 0 {
		return false
	}

	now := time.Now()
	return now.After(entry.expiresAt) && !now.After(entry.expiresAt.Add(window))
}

func staleIfErrorWindow(cacheControl string) time.Duration {
	return secondsTTL(cacheControlDirectives(cacheControl)["stale-if-error"])
}

func maxStaleForPolicy(policy edgeCachePolicy) time.Duration {
	policy = normalizeEdgeCachePolicy(policy)
	if policy.StaleWhileRevalidateSeconds != nil && *policy.StaleWhileRevalidateSeconds > 0 {
		return time.Duration(*policy.StaleWhileRevalidateSeconds) * time.Second
	}
	return envDuration("EDGE_REVALIDATION_MAX_STALE", 24*time.Hour)
}

func parseByteRange(header string, size int64) (byteRange, bool) {
	if size < 0 || !strings.HasPrefix(header, "bytes=") {
		return byteRange{}, false
	}
	spec := strings.TrimSpace(strings.TrimPrefix(header, "bytes="))
	if spec == "" || strings.Contains(spec, ",") {
		return byteRange{}, false
	}
	startRaw, endRaw, ok := strings.Cut(spec, "-")
	if !ok {
		return byteRange{}, false
	}

	if startRaw == "" {
		suffixLength, err := strconv.ParseInt(strings.TrimSpace(endRaw), 10, 64)
		if err != nil || suffixLength <= 0 {
			return byteRange{}, false
		}
		if size == 0 {
			return byteRange{}, false
		}
		if suffixLength > size {
			suffixLength = size
		}
		return byteRange{start: size - suffixLength, end: size - 1}, true
	}

	start, err := strconv.ParseInt(strings.TrimSpace(startRaw), 10, 64)
	if err != nil || start < 0 || start >= size {
		return byteRange{}, false
	}
	end := size - 1
	if strings.TrimSpace(endRaw) != "" {
		end, err = strconv.ParseInt(strings.TrimSpace(endRaw), 10, 64)
		if err != nil || end < start {
			return byteRange{}, false
		}
		if end >= size {
			end = size - 1
		}
	}
	return byteRange{start: start, end: end}, true
}

func redisRetentionTTL(freshTTL time.Duration) time.Duration {
	maxStale := envDuration("EDGE_REVALIDATION_MAX_STALE", 24*time.Hour)
	if maxStale <= 0 {
		return freshTTL
	}
	return freshTTL + maxStale
}

func minDuration(a time.Duration, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func redisRetentionTTLForEntry(entry cacheEntry, freshTTL time.Duration) time.Duration {
	retentionTTL := redisRetentionTTL(freshTTL)
	staleIfErrorTTL := freshTTL + staleIfErrorWindow(entry.header.Get("Cache-Control"))
	if staleIfErrorTTL > retentionTTL {
		return staleIfErrorTTL
	}
	return retentionTTL
}

func prepareDeliveryBody(r *http.Request, header http.Header, body []byte, status int) []byte {
	encoding := deliveryCompressionEncoding(r, header, body, status)
	if encoding == "" {
		return body
	}

	var compressed bytes.Buffer
	switch encoding {
	case "br":
		br := brotli.NewWriter(&compressed)
		if _, err := br.Write(body); err != nil {
			_ = br.Close()
			return body
		}
		if err := br.Close(); err != nil {
			return body
		}
	case "gzip":
		gz := gzip.NewWriter(&compressed)
		if _, err := gz.Write(body); err != nil {
			_ = gz.Close()
			return body
		}
		if err := gz.Close(); err != nil {
			return body
		}
	default:
		return body
	}

	header.Set("Content-Encoding", encoding)
	header.Del("Content-Length")
	addVaryHeader(header, "Accept-Encoding")
	return compressed.Bytes()
}

func deliveryCompressionEncoding(r *http.Request, header http.Header, body []byte, status int) string {
	if !envBool("EDGE_COMPRESSION_ENABLED", true) {
		return ""
	}
	if r == nil || header == nil || status < http.StatusOK || status >= http.StatusMultipleChoices {
		return ""
	}
	if strings.TrimSpace(r.Header.Get("Range")) != "" {
		return ""
	}
	if strings.TrimSpace(header.Get("Content-Encoding")) != "" {
		return ""
	}
	if hasCacheControlDirective(header.Get("Cache-Control"), "no-transform") {
		return ""
	}
	if len(body) < envInt("EDGE_COMPRESSION_MIN_BYTES", 512) {
		return ""
	}
	if !compressibleContentType(header.Get("Content-Type")) {
		return ""
	}
	if envBool("EDGE_BROTLI_ENABLED", true) && requestAcceptsEncoding(r, "br") {
		return "br"
	}
	if requestAcceptsEncoding(r, "gzip") {
		return "gzip"
	}
	return ""
}

func transformImageForDelivery(r *http.Request, header http.Header, body []byte) ([]byte, http.Header) {
	if !envBool("EDGE_IMAGE_TRANSFORM_ENABLED", true) {
		return body, header
	}
	if r == nil || header == nil || len(body) == 0 {
		return body, header
	}
	if strings.TrimSpace(r.Header.Get("Range")) != "" {
		return body, header
	}
	if strings.TrimSpace(header.Get("Content-Encoding")) != "" {
		return body, header
	}
	if hasCacheControlDirective(header.Get("Cache-Control"), "no-transform") {
		return body, header
	}

	width, height, ok := requestedImageSize(r)
	if !ok {
		return body, header
	}
	if !transformableImageContentType(header.Get("Content-Type")) {
		return body, header
	}

	source, sourceFormat, err := image.Decode(bytes.NewReader(body))
	if err != nil {
		return body, header
	}
	targetWidth, targetHeight := targetImageSize(source.Bounds(), width, height)
	if targetWidth <= 0 || targetHeight <= 0 {
		return body, header
	}
	targetFormat := requestedImageFormat(r, sourceFormat)
	target := resizeNearest(source, targetWidth, targetHeight)

	var transformed bytes.Buffer
	switch targetFormat {
	case "jpeg":
		if err := jpeg.Encode(&transformed, target, &jpeg.Options{Quality: envInt("EDGE_IMAGE_TRANSFORM_JPEG_QUALITY", 82)}); err != nil {
			return body, header
		}
		header.Set("Content-Type", "image/jpeg")
	case "png":
		if err := png.Encode(&transformed, target); err != nil {
			return body, header
		}
		header.Set("Content-Type", "image/png")
	default:
		return body, header
	}

	header.Del("Content-Length")
	header.Del("Content-Encoding")
	header.Del("Etag")
	header.Set("X-AstraCDN-Image-Transform", fmt.Sprintf("width=%d;height=%d;format=%s", targetWidth, targetHeight, targetFormat))
	if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("format")), "auto") {
		addVaryHeader(header, "Accept")
	}
	return transformed.Bytes(), header
}

func requestedImageSize(r *http.Request) (int, int, bool) {
	values := r.URL.Query()
	width := boundedImageDimension(values.Get("width"))
	if width == 0 {
		width = boundedImageDimension(values.Get("w"))
	}
	height := boundedImageDimension(values.Get("height"))
	if height == 0 {
		height = boundedImageDimension(values.Get("h"))
	}
	if width == 0 && height == 0 {
		return 0, 0, false
	}
	dpr := imageDPR(values.Get("dpr"))
	if width > 0 {
		width *= dpr
	}
	if height > 0 {
		height *= dpr
	}
	maxDimension := envInt("EDGE_IMAGE_TRANSFORM_MAX_DIMENSION", 2048)
	if maxDimension <= 0 {
		maxDimension = 2048
	}
	if width > maxDimension {
		width = maxDimension
	}
	if height > maxDimension {
		height = maxDimension
	}
	return width, height, true
}

func boundedImageDimension(raw string) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return 0
	}
	return value
}

func imageDPR(raw string) int {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil || value <= 1 {
		return 1
	}
	if value > 4 {
		value = 4
	}
	return int(value + 0.5)
}

func targetImageSize(bounds image.Rectangle, requestedWidth int, requestedHeight int) (int, int) {
	sourceWidth := bounds.Dx()
	sourceHeight := bounds.Dy()
	if sourceWidth <= 0 || sourceHeight <= 0 {
		return 0, 0
	}
	width := requestedWidth
	height := requestedHeight
	if width <= 0 {
		width = (height*sourceWidth + sourceHeight/2) / sourceHeight
	}
	if height <= 0 {
		height = (width*sourceHeight + sourceWidth/2) / sourceWidth
	}
	if width <= 0 || height <= 0 {
		return 0, 0
	}
	return width, height
}

func requestedImageFormat(r *http.Request, sourceFormat string) string {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	switch format {
	case "jpg":
		return "jpeg"
	case "jpeg", "png":
		return format
	case "auto":
		if requestAcceptsMediaType(r, "image/jpeg") {
			return "jpeg"
		}
		if requestAcceptsMediaType(r, "image/png") {
			return "png"
		}
	}
	if sourceFormat == "jpeg" || sourceFormat == "png" {
		return sourceFormat
	}
	return "png"
}

func requestAcceptsMediaType(r *http.Request, mediaType string) bool {
	for _, value := range strings.Split(r.Header.Get("Accept"), ",") {
		token := strings.TrimSpace(value)
		coding, _, _ := strings.Cut(token, ";")
		coding = strings.TrimSpace(coding)
		if coding == "" {
			continue
		}
		if strings.EqualFold(coding, mediaType) || strings.EqualFold(coding, "image/*") || strings.EqualFold(coding, "*/*") {
			return true
		}
	}
	return false
}

func transformableImageContentType(contentType string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	return mediaType == "image/jpeg" || mediaType == "image/png"
}

func resizeNearest(source image.Image, width int, height int) image.Image {
	bounds := source.Bounds()
	target := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		sourceY := bounds.Min.Y + y*bounds.Dy()/height
		for x := 0; x < width; x++ {
			sourceX := bounds.Min.X + x*bounds.Dx()/width
			target.Set(x, y, source.At(sourceX, sourceY))
		}
	}
	return target
}

func requestAcceptsEncoding(r *http.Request, encoding string) bool {
	for _, value := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		token := strings.TrimSpace(value)
		if token == "" {
			continue
		}
		coding, params, _ := strings.Cut(token, ";")
		if !strings.EqualFold(strings.TrimSpace(coding), encoding) {
			continue
		}
		if encodingQualityZero(params) {
			return false
		}
		return true
	}
	return false
}

func encodingQualityZero(params string) bool {
	for _, param := range strings.Split(params, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(param), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "q") {
			continue
		}
		quality, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		return err == nil && quality <= 0
	}
	return false
}

func compressibleContentType(contentType string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if strings.HasPrefix(mediaType, "text/") {
		return true
	}
	switch mediaType {
	case "application/javascript", "application/json", "application/manifest+json",
		"application/rss+xml", "application/xml", "image/svg+xml":
		return true
	default:
		return strings.HasSuffix(mediaType, "+json") || strings.HasSuffix(mediaType, "+xml")
	}
}

func addVaryHeader(header http.Header, value string) {
	value = http.CanonicalHeaderKey(strings.TrimSpace(value))
	if value == "" {
		return
	}
	for _, existing := range varyHeaderNames(header.Get("Vary")) {
		if strings.EqualFold(existing, value) {
			return
		}
	}
	header.Add("Vary", value)
}

func hasValidators(header http.Header) bool {
	return header.Get("Etag") != "" || header.Get("Last-Modified") != ""
}

func copyOriginRequestHeaders(dst http.Header, src http.Header) {
	for key, values := range src {
		if skipOriginRequestHeader(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func skipOriginRequestHeader(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailer", "transfer-encoding", "upgrade", strings.ToLower(shieldHopHeader):
		return true
	default:
		return false
	}
}

func cloneCacheableHeaders(header http.Header) http.Header {
	clone := make(http.Header)
	for _, key := range []string{"Cache-Control", "Content-Encoding", "Content-Type", "Etag", "Last-Modified", "Surrogate-Key", "Vary"} {
		if values, ok := header[key]; ok {
			clone[key] = append([]string(nil), values...)
		}
	}
	return clone
}

func mergeCacheHeaders(cached, updated http.Header) http.Header {
	merged := cloneCacheableHeaders(cached)
	for _, key := range []string{"Cache-Control", "Content-Encoding", "Content-Type", "Etag", "Last-Modified", "Surrogate-Key", "Vary"} {
		if values, ok := updated[key]; ok {
			merged[key] = append([]string(nil), values...)
		}
	}
	return merged
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
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

func envInt(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
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

func openNATS() (*nats.Conn, error) {
	return nats.Connect(
		env("NATS_URL", nats.DefaultURL),
		nats.Name("astra-cdn-edge"),
		nats.Timeout(2*time.Second),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(20),
		nats.ReconnectWait(500*time.Millisecond),
	)
}
