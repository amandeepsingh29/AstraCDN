package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
)

type inferRequest struct {
	Model  string         `json:"model,omitempty"`
	Prompt string         `json:"prompt"`
	Params map[string]any `json:"params,omitempty"`
	Stream bool           `json:"stream,omitempty"`
}

type inferResponse struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Cached   bool   `json:"cached"`
	Response string `json:"response"`
	Prompt   string `json:"prompt"`
	CacheKey string `json:"cache_key"`
	CacheHit string `json:"cache_hit"`
}

type inferenceServer struct {
	cache         promptCache
	semanticCache semanticCache
	provider      modelProvider
	apiKey        string
	limiter       *rateLimiter
	metrics       *inferenceMetrics
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

type inferenceMetrics struct {
	mu              sync.RWMutex
	exact           uint64
	semantic        uint64
	miss            uint64
	rateLimited     uint64
	providerLatency map[string]providerLatencyMetric
}

type providerLatencyMetric struct {
	count        uint64
	totalSeconds float64
}

type promptCache interface {
	get(ctx context.Context, key string) (inferResponse, bool)
	set(ctx context.Context, key string, response inferResponse, ttl time.Duration)
	ready(ctx context.Context) error
	close()
}

type redisPromptCache struct {
	client *redis.Client
}

type semanticCache interface {
	get(ctx context.Context, req inferRequest, providerName string, model string) (inferResponse, bool)
	set(ctx context.Context, req inferRequest, providerName string, model string, response inferResponse)
}

type memorySemanticCache struct {
	mu        sync.RWMutex
	entries   []semanticCacheEntry
	threshold float64
}

type semanticCacheEntry struct {
	Provider  string
	Model     string
	ParamsKey string
	Prompt    string
	Embedding []float64
	Response  inferResponse
}

type modelProvider interface {
	Name() string
	DefaultModel() string
	Infer(ctx context.Context, req inferRequest) (providerResult, error)
	Stream(ctx context.Context, req inferRequest) (<-chan streamEvent, error)
}

type providerResult struct {
	Model    string
	Response string
}

type streamEvent struct {
	Type  string `json:"type"`
	Model string `json:"model,omitempty"`
	Token string `json:"token,omitempty"`
	Error string `json:"error,omitempty"`
}

type mockProvider struct {
	model string
}

type openAICompatibleProvider struct {
	name    string
	baseURL string
	apiKey  string
	model   string
	client  *http.Client
}

type ollamaProvider struct {
	baseURL string
	apiKey  string
	model   string
	client  *http.Client
}

type openAIResponsesProvider struct {
	baseURL       string
	apiKey        string
	model         string
	clientName    string
	clientVersion string
	client        *http.Client
}

func main() {
	if err := validateSecureConfig(); err != nil {
		log.Fatalf("secure config: %v", err)
	}

	port := env("INFERENCE_PORT", "8082")
	app := &inferenceServer{
		cache:         newRedisPromptCache(env("REDIS_ADDR", "localhost:6379")),
		semanticCache: newSemanticCacheFromEnv(),
		provider:      newProviderFromEnv(),
		apiKey:        env("ASTRACDN_API_KEY", ""),
		limiter:       newRateLimiterFromEnv(),
		metrics:       newInferenceMetrics(),
	}
	defer app.cache.close()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler("inference"))
	mux.HandleFunc("/ready", app.readyHandler)
	mux.HandleFunc("/metrics", app.metricsHandler)
	mux.HandleFunc("/v1/infer", app.inferHandler)

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           observabilityMiddleware("inference", corsMiddleware(mux)),
		ReadHeaderTimeout: envDuration("HTTP_READ_HEADER_TIMEOUT", 5*time.Second),
		ReadTimeout:       envDuration("HTTP_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:      envDuration("HTTP_WRITE_TIMEOUT", 0),
		IdleTimeout:       envDuration("HTTP_IDLE_TIMEOUT", 60*time.Second),
	}

	log.Printf("inference service listening on :%s", port)
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

func (s *inferenceServer) readyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	checks := map[string]string{}
	status := http.StatusOK
	if s.provider == nil {
		checks["provider"] = "provider missing"
		status = http.StatusServiceUnavailable
	} else {
		checks["provider"] = s.provider.Name()
	}
	if s.cache == nil {
		checks["redis"] = "cache client missing"
		status = http.StatusServiceUnavailable
	} else if err := s.cache.ready(r.Context()); err != nil {
		checks["redis"] = err.Error()
		status = http.StatusServiceUnavailable
	} else {
		checks["redis"] = "ok"
	}

	ready := status == http.StatusOK
	writeJSON(w, status, map[string]any{
		"service": "inference",
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

func (s *inferenceServer) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	exact, semantic, misses, rateLimited := s.metricsSnapshot()
	providerLatency := s.providerLatencySnapshot()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintln(w, "# HELP astracdn_inference_up Service availability")
	fmt.Fprintln(w, "# TYPE astracdn_inference_up gauge")
	fmt.Fprintln(w, "astracdn_inference_up 1")
	fmt.Fprintln(w, "# HELP astracdn_inference_cache_requests_total Inference cache requests by result")
	fmt.Fprintln(w, "# TYPE astracdn_inference_cache_requests_total counter")
	fmt.Fprintf(w, "astracdn_inference_cache_requests_total{result=\"hit\",layer=\"exact\"} %d\n", exact)
	fmt.Fprintf(w, "astracdn_inference_cache_requests_total{result=\"hit\",layer=\"semantic\"} %d\n", semantic)
	fmt.Fprintf(w, "astracdn_inference_cache_requests_total{result=\"miss\",layer=\"provider\"} %d\n", misses)
	fmt.Fprintln(w, "# HELP astracdn_inference_rate_limit_blocks_total Inference requests rejected by rate limiting")
	fmt.Fprintln(w, "# TYPE astracdn_inference_rate_limit_blocks_total counter")
	fmt.Fprintf(w, "astracdn_inference_rate_limit_blocks_total %d\n", rateLimited)
	fmt.Fprintln(w, "# HELP astracdn_inference_provider_latency_seconds_total Total provider call latency by provider")
	fmt.Fprintln(w, "# TYPE astracdn_inference_provider_latency_seconds_total counter")
	for provider, metric := range providerLatency {
		fmt.Fprintf(w, "astracdn_inference_provider_latency_seconds_total{provider=\"%s\"} %.6f\n", provider, metric.totalSeconds)
	}
	fmt.Fprintln(w, "# HELP astracdn_inference_provider_requests_total Provider calls by provider")
	fmt.Fprintln(w, "# TYPE astracdn_inference_provider_requests_total counter")
	for provider, metric := range providerLatency {
		fmt.Fprintf(w, "astracdn_inference_provider_requests_total{provider=\"%s\"} %d\n", provider, metric.count)
	}
}

func (s *inferenceServer) inferHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !s.allowRequest(r) {
		s.recordRateLimitBlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	var req inferRequest
	if !decodeJSONBody(w, r, &req, envInt64("HTTP_MAX_REQUEST_BODY_BYTES", 1048576)) {
		return
	}
	if req.Prompt == "" {
		http.Error(w, "prompt is required", http.StatusBadRequest)
		return
	}
	provider := s.provider
	if provider == nil {
		provider = newMockProvider("mock")
	}
	if req.Stream {
		s.streamInferHandler(w, r, req, provider)
		return
	}

	providerName := provider.Name()
	model := selectedModel(req, provider.DefaultModel())
	cacheKey, err := promptCacheKey(req, providerName, model)
	if err != nil {
		http.Error(w, "invalid inference request", http.StatusBadRequest)
		return
	}
	if cached, ok := s.cachedResponse(r.Context(), cacheKey); ok {
		s.recordCacheMetric("exact")
		writeJSON(w, http.StatusOK, cached)
		return
	}
	if s.semanticCache != nil {
		if cached, ok := s.semanticCache.get(r.Context(), req, providerName, model); ok {
			s.recordCacheMetric("semantic")
			cached.Cached = true
			cached.CacheHit = "semantic"
			writeJSON(w, http.StatusOK, cached)
			return
		}
	}

	providerStart := time.Now()
	result, err := provider.Infer(r.Context(), req)
	s.recordProviderLatency(provider.Name(), time.Since(providerStart))
	if err != nil {
		log.Printf("inference provider failed provider=%s err=%v", provider.Name(), err)
		http.Error(w, "inference provider failed", http.StatusBadGateway)
		return
	}

	resp := inferResponse{
		Provider: provider.Name(),
		Model:    result.Model,
		Cached:   false,
		Response: result.Response,
		Prompt:   req.Prompt,
		CacheKey: cacheKey,
		CacheHit: "miss",
	}
	if s.cache != nil {
		s.cache.set(r.Context(), cacheKey, resp, 10*time.Minute)
	}
	if s.semanticCache != nil {
		s.semanticCache.set(r.Context(), req, providerName, model, resp)
	}
	s.recordCacheMetric("provider")
	writeJSON(w, http.StatusOK, resp)
}

func (s *inferenceServer) streamInferHandler(w http.ResponseWriter, r *http.Request, req inferRequest, provider modelProvider) {
	events, err := provider.Stream(r.Context(), req)
	if err != nil {
		log.Printf("inference stream failed provider=%s err=%v", provider.Name(), err)
		http.Error(w, "inference stream failed", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	for event := range events {
		writeSSE(w, event.Type, event)
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func newInferenceMetrics() *inferenceMetrics {
	return &inferenceMetrics{
		providerLatency: make(map[string]providerLatencyMetric),
	}
}

func (s *inferenceServer) recordCacheMetric(layer string) {
	if s.metrics == nil {
		return
	}
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	switch layer {
	case "exact":
		s.metrics.exact++
	case "semantic":
		s.metrics.semantic++
	case "provider":
		s.metrics.miss++
	}
}

func (s *inferenceServer) recordRateLimitBlock() {
	if s.metrics == nil {
		return
	}
	s.metrics.mu.Lock()
	s.metrics.rateLimited++
	s.metrics.mu.Unlock()
}

func (s *inferenceServer) recordProviderLatency(provider string, duration time.Duration) {
	if s.metrics == nil {
		return
	}
	if provider == "" {
		provider = "unknown"
	}
	s.metrics.mu.Lock()
	metric := s.metrics.providerLatency[provider]
	metric.count++
	metric.totalSeconds += duration.Seconds()
	s.metrics.providerLatency[provider] = metric
	s.metrics.mu.Unlock()
}

func (s *inferenceServer) metricsSnapshot() (uint64, uint64, uint64, uint64) {
	if s.metrics == nil {
		return 0, 0, 0, 0
	}
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()
	return s.metrics.exact, s.metrics.semantic, s.metrics.miss, s.metrics.rateLimited
}

func (s *inferenceServer) providerLatencySnapshot() map[string]providerLatencyMetric {
	if s.metrics == nil {
		return map[string]providerLatencyMetric{}
	}
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()
	snapshot := make(map[string]providerLatencyMetric, len(s.metrics.providerLatency))
	for provider, metric := range s.metrics.providerLatency {
		snapshot[provider] = metric
	}
	return snapshot
}

func (s *inferenceServer) authorize(r *http.Request) bool {
	return authorizeAPIKey(r, s.apiKey)
}

func (s *inferenceServer) allowRequest(r *http.Request) bool {
	if s.limiter == nil {
		return true
	}
	return s.limiter.allow(r)
}

func authorizeAPIKey(r *http.Request, expected string) bool {
	if expected == "" {
		return true
	}
	actual := r.Header.Get("X-AstraCDN-API-Key")
	if actual == "" {
		actual = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if actual == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
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
	if strings.ToLower(env("RATE_LIMIT_ENABLED", "true")) != "true" {
		return errors.New("RATE_LIMIT_ENABLED must remain true outside local development")
	}

	provider := strings.ToLower(env("INFERENCE_PROVIDER", "openai"))
	if (provider == "openai" || provider == "openai-chat") && env("OPENAI_API_KEY", "") == "" {
		return errors.New("OPENAI_API_KEY must be set for OpenAI providers outside local development")
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

func (s *inferenceServer) cachedResponse(ctx context.Context, cacheKey string) (inferResponse, bool) {
	if s.cache == nil {
		return inferResponse{}, false
	}
	if cached, ok := s.cache.get(ctx, cacheKey); ok {
		cached.Cached = true
		cached.CacheHit = "exact"
		return cached, true
	}
	return inferResponse{}, false
}

func newSemanticCacheFromEnv() semanticCache {
	if strings.ToLower(env("SEMANTIC_CACHE_ENABLED", "false")) != "true" {
		return nil
	}
	return newMemorySemanticCache(0.96)
}

func newProviderFromEnv() modelProvider {
	switch strings.ToLower(env("INFERENCE_PROVIDER", "openai")) {
	case "openai":
		return newOpenAIResponsesProvider(
			env("OPENAI_BASE_URL", "https://api.openai.com/v1"),
			env("OPENAI_API_KEY", ""),
			env("INFERENCE_MODEL", "gpt-4o-mini"),
			env("OPENAI_CLIENT", "astra-cdn"),
			env("OPENAI_CLIENT_VERSION", "0"),
		)
	case "openai-chat":
		return newOpenAICompatibleProvider(
			"openai-chat",
			env("OPENAI_BASE_URL", "https://api.openai.com/v1"),
			env("OPENAI_API_KEY", ""),
			env("INFERENCE_MODEL", "gpt-4o-mini"),
		)
	case "openai-compatible":
		return newOpenAICompatibleProvider(
			"openai-compatible",
			env("OPENAI_COMPAT_BASE_URL", "http://localhost:8000/v1"),
			env("OPENAI_COMPAT_API_KEY", ""),
			env("INFERENCE_MODEL", "local-model"),
		)
	case "vllm":
		return newOpenAICompatibleProvider(
			"vllm",
			env("VLLM_BASE_URL", "http://localhost:8000/v1"),
			env("VLLM_API_KEY", ""),
			env("INFERENCE_MODEL", "local-model"),
		)
	case "ollama":
		return newOllamaProvider(
			env("OLLAMA_BASE_URL", "http://localhost:11434"),
			env("OLLAMA_API_KEY", ""),
			env("INFERENCE_MODEL", "llama3.2"),
		)
	default:
		return newMockProvider(env("INFERENCE_MODEL", "mock"))
	}
}

func newMockProvider(model string) mockProvider {
	return mockProvider{model: model}
}

func (p mockProvider) Name() string {
	return "mock"
}

func (p mockProvider) DefaultModel() string {
	return p.model
}

func (p mockProvider) Infer(_ context.Context, req inferRequest) (providerResult, error) {
	model := selectedModel(req, p.DefaultModel())
	return providerResult{
		Model:    model,
		Response: fmt.Sprintf("mock inference response for: %s", req.Prompt),
	}, nil
}

func (p mockProvider) Stream(ctx context.Context, req inferRequest) (<-chan streamEvent, error) {
	model := selectedModel(req, p.DefaultModel())
	out := make(chan streamEvent)
	go func() {
		defer close(out)
		words := strings.Fields(fmt.Sprintf("mock inference response for: %s", req.Prompt))
		for _, word := range words {
			select {
			case <-ctx.Done():
				return
			case out <- streamEvent{Type: "token", Model: model, Token: word}:
			}
		}
		select {
		case <-ctx.Done():
			return
		case out <- streamEvent{Type: "done", Model: model}:
		}
	}()
	return out, nil
}

func newOpenAICompatibleProvider(name, baseURL, apiKey, model string) openAICompatibleProvider {
	return openAICompatibleProvider{
		name:    name,
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		model:   model,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (p openAICompatibleProvider) Name() string {
	return p.name
}

func (p openAICompatibleProvider) DefaultModel() string {
	return p.model
}

func (p openAICompatibleProvider) Infer(ctx context.Context, req inferRequest) (providerResult, error) {
	model := selectedModel(req, p.DefaultModel())
	payload := p.chatCompletionsPayload(req, model)
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return providerResult{}, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/chat/completions", bytes.NewReader(rawPayload))
	if err != nil {
		return providerResult{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if p.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return providerResult{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return providerResult{}, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return providerResult{}, fmt.Errorf("provider status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return providerResult{}, err
	}
	if len(parsed.Choices) == 0 || parsed.Choices[0].Message.Content == "" {
		return providerResult{}, errors.New("provider returned no message content")
	}

	return providerResult{
		Model:    model,
		Response: parsed.Choices[0].Message.Content,
	}, nil
}

func (p openAICompatibleProvider) Stream(ctx context.Context, req inferRequest) (<-chan streamEvent, error) {
	return nil, errors.New("streaming is not implemented for openai-compatible provider")
}

func (p openAICompatibleProvider) chatCompletionsPayload(req inferRequest, model string) map[string]any {
	payload := make(map[string]any, len(req.Params)+3)
	for key, value := range req.Params {
		payload[key] = value
	}
	payload["model"] = model
	payload["stream"] = false
	payload["messages"] = []map[string]string{
		{
			"role":    "user",
			"content": req.Prompt,
		},
	}
	return payload
}

func newOllamaProvider(baseURL, apiKey, model string) ollamaProvider {
	return ollamaProvider{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		model:   model,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (p ollamaProvider) Name() string {
	return "ollama"
}

func (p ollamaProvider) DefaultModel() string {
	return p.model
}

func (p ollamaProvider) Infer(ctx context.Context, req inferRequest) (providerResult, error) {
	model := selectedModel(req, p.DefaultModel())
	payload := p.chatPayload(req, model)
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return providerResult{}, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/api/chat", bytes.NewReader(rawPayload))
	if err != nil {
		return providerResult{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if p.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return providerResult{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return providerResult{}, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return providerResult{}, fmt.Errorf("provider status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var parsed struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return providerResult{}, err
	}
	if parsed.Message.Content == "" {
		return providerResult{}, errors.New("provider returned no message content")
	}

	return providerResult{
		Model:    model,
		Response: parsed.Message.Content,
	}, nil
}

func (p ollamaProvider) Stream(ctx context.Context, req inferRequest) (<-chan streamEvent, error) {
	return nil, errors.New("streaming is not implemented for ollama provider")
}

func (p ollamaProvider) chatPayload(req inferRequest, model string) map[string]any {
	payload := make(map[string]any, len(req.Params)+3)
	for key, value := range req.Params {
		payload[key] = value
	}
	payload["model"] = model
	payload["stream"] = false
	payload["messages"] = []map[string]string{
		{
			"role":    "user",
			"content": req.Prompt,
		},
	}
	return payload
}

func newOpenAIResponsesProvider(baseURL, apiKey, model, clientName, clientVersion string) openAIResponsesProvider {
	return openAIResponsesProvider{
		baseURL:       strings.TrimRight(baseURL, "/"),
		apiKey:        apiKey,
		model:         model,
		clientName:    clientName,
		clientVersion: clientVersion,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (p openAIResponsesProvider) Name() string {
	return "openai"
}

func (p openAIResponsesProvider) DefaultModel() string {
	return p.model
}

func (p openAIResponsesProvider) Infer(ctx context.Context, req inferRequest) (providerResult, error) {
	model := selectedModel(req, p.DefaultModel())
	payload := p.responsesPayload(req, model)
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return providerResult{}, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/responses", bytes.NewReader(rawPayload))
	if err != nil {
		return providerResult{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if p.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	}
	if p.clientName != "" {
		httpReq.Header.Set("client", p.clientName)
	}
	if p.clientVersion != "" {
		httpReq.Header.Set("client-version", p.clientVersion)
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return providerResult{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return providerResult{}, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return providerResult{}, fmt.Errorf("provider status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	content, err := parseOpenAIResponseContent(body)
	if err != nil {
		return providerResult{}, err
	}

	return providerResult{
		Model:    model,
		Response: content,
	}, nil
}

func (p openAIResponsesProvider) Stream(ctx context.Context, req inferRequest) (<-chan streamEvent, error) {
	return nil, errors.New("streaming is not implemented for openai responses provider")
}

func (p openAIResponsesProvider) responsesPayload(req inferRequest, model string) map[string]any {
	payload := make(map[string]any, len(req.Params)+2)
	for key, value := range req.Params {
		payload[key] = value
	}
	payload["model"] = model
	payload["input"] = req.Prompt
	return payload
}

func parseOpenAIResponseContent(body []byte) (string, error) {
	if strings.HasPrefix(strings.TrimSpace(string(body)), "data:") {
		return parseOpenAIResponseContentFromSSE(body)
	}
	return parseOpenAIResponseContentFromJSON(body)
}

func parseOpenAIResponseContentFromJSON(body []byte) (string, error) {
	var parsed struct {
		OutputText string `json:"output_text"`
		Output     []struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", err
	}
	if parsed.OutputText != "" {
		return parsed.OutputText, nil
	}
	for _, output := range parsed.Output {
		for _, content := range output.Content {
			if content.Text != "" {
				return content.Text, nil
			}
		}
	}
	return "", errors.New("provider returned no response content")
}

func parseOpenAIResponseContentFromSSE(body []byte) (string, error) {
	var parts []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		rawJSON, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue
		}
		rawJSON = strings.TrimSpace(rawJSON)
		if rawJSON == "" || rawJSON == "[DONE]" {
			continue
		}
		content, err := parseOpenAIResponseContentFromJSON([]byte(rawJSON))
		if err != nil {
			continue
		}
		parts = append(parts, content)
	}
	if len(parts) == 0 {
		return "", errors.New("provider returned no SSE response content")
	}
	return strings.Join(parts, ""), nil
}

func newMemorySemanticCache(threshold float64) *memorySemanticCache {
	return &memorySemanticCache{
		threshold: threshold,
	}
}

func (c *memorySemanticCache) get(_ context.Context, req inferRequest, providerName string, model string) (inferResponse, bool) {
	if c == nil {
		return inferResponse{}, false
	}

	paramsKey, err := paramsCacheKey(req.Params)
	if err != nil {
		return inferResponse{}, false
	}
	embedding := mockEmbedding(req.Prompt)

	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, entry := range c.entries {
		if entry.Provider != providerName || entry.Model != model || entry.ParamsKey != paramsKey {
			continue
		}
		if cosineSimilarity(embedding, entry.Embedding) >= c.threshold {
			response := entry.Response
			response.Prompt = req.Prompt
			return response, true
		}
	}
	return inferResponse{}, false
}

func (c *memorySemanticCache) set(_ context.Context, req inferRequest, providerName string, model string, response inferResponse) {
	if c == nil {
		return
	}

	paramsKey, err := paramsCacheKey(req.Params)
	if err != nil {
		log.Printf("semantic cache params encode failed: %v", err)
		return
	}
	entry := semanticCacheEntry{
		Provider:  providerName,
		Model:     model,
		ParamsKey: paramsKey,
		Prompt:    req.Prompt,
		Embedding: mockEmbedding(req.Prompt),
		Response:  response,
	}

	c.mu.Lock()
	c.entries = append(c.entries, entry)
	c.mu.Unlock()
}

func paramsCacheKey(params map[string]any) (string, error) {
	if len(params) == 0 {
		return "{}", nil
	}
	payload, err := json.Marshal(params)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func mockEmbedding(text string) []float64 {
	embedding := make([]float64, 16)
	for _, token := range strings.Fields(strings.ToLower(text)) {
		sum := sha256.Sum256([]byte(token))
		index := int(sum[0]) % len(embedding)
		embedding[index] += 1
	}
	return embedding
}

func cosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}

	var dot, normA, normB float64
	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}

func selectedModel(req inferRequest, defaultModel string) string {
	if req.Model != "" {
		return req.Model
	}
	return defaultModel
}

func promptCacheKey(req inferRequest, providerName string, model string) (string, error) {
	payload, err := json.Marshal(struct {
		Provider string         `json:"provider"`
		Model    string         `json:"model"`
		Prompt   string         `json:"prompt"`
		Params   map[string]any `json:"params,omitempty"`
	}{
		Provider: providerName,
		Model:    model,
		Prompt:   req.Prompt,
		Params:   req.Params,
	})
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(payload)
	return "astracdn:inference-cache:" + hex.EncodeToString(sum[:]), nil
}

func newRedisPromptCache(addr string) *redisPromptCache {
	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		Protocol:    2,
		DialTimeout: 2 * time.Second,
		ReadTimeout: 2 * time.Second,
	})
	return &redisPromptCache{client: client}
}

func (c *redisPromptCache) get(ctx context.Context, key string) (inferResponse, bool) {
	if c == nil || c.client == nil {
		return inferResponse{}, false
	}

	payload, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if err != redis.Nil {
			log.Printf("inference cache get failed key=%s err=%v", key, err)
		}
		return inferResponse{}, false
	}

	var response inferResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		log.Printf("inference cache decode failed key=%s err=%v", key, err)
		return inferResponse{}, false
	}
	return response, true
}

func (c *redisPromptCache) set(ctx context.Context, key string, response inferResponse, ttl time.Duration) {
	if c == nil || c.client == nil {
		return
	}

	response.Cached = false
	payload, err := json.Marshal(response)
	if err != nil {
		log.Printf("inference cache encode failed key=%s err=%v", key, err)
		return
	}
	if err := c.client.Set(ctx, key, payload, ttl).Err(); err != nil {
		log.Printf("inference cache set failed key=%s err=%v", key, err)
	}
}

func (c *redisPromptCache) ready(ctx context.Context) error {
	if c == nil || c.client == nil {
		return errors.New("redis client missing")
	}
	return c.client.Ping(ctx).Err()
}

func (c *redisPromptCache) close() {
	if c == nil || c.client == nil {
		return
	}
	if err := c.client.Close(); err != nil {
		log.Printf("redis close failed: %v", err)
	}
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

func writeSSE(w io.Writer, eventName string, payload any) {
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		rawPayload = []byte(`{"type":"error","error":"failed to encode event"}`)
		eventName = "error"
	}
	fmt.Fprintf(w, "event: %s\n", eventName)
	fmt.Fprintf(w, "data: %s\n\n", rawPayload)
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
