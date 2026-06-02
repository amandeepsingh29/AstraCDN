package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
)

func signedCookieValue(secret, pathPrefix, expires string) string {
	payload := "cookie\n" + pathPrefix + "\n" + expires
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	return expires + ":" + hex.EncodeToString(mac.Sum(nil))
}

func TestEdgeHandlerCachesOriginGET(t *testing.T) {
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "public, max-age=60")
		fmt.Fprintf(w, "origin hit %d path=%s query=%s", originHits, r.URL.Path, r.URL.RawQuery)
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/assets/app.js?v=1", nil)
	first := httptest.NewRecorder()
	app.edgeHandler(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d", first.Code)
	}
	if got := first.Header().Get("X-AstraCDN-Cache"); got != "MISS" {
		t.Fatalf("first cache header = %q", got)
	}

	second := httptest.NewRecorder()
	app.edgeHandler(second, req)
	if second.Code != http.StatusOK {
		t.Fatalf("second status = %d", second.Code)
	}
	if got := second.Header().Get("X-AstraCDN-Cache"); got != "HIT" {
		t.Fatalf("second cache header = %q", got)
	}
	if originHits != 1 {
		t.Fatalf("originHits = %d, want 1", originHits)
	}
	if first.Body.String() != second.Body.String() {
		t.Fatalf("cached body mismatch: first=%q second=%q", first.Body.String(), second.Body.String())
	}

	memoryHits, redisHits, misses, rateLimited := app.metricsSnapshot()
	if memoryHits != 1 || redisHits != 0 || misses != 1 || rateLimited != 0 {
		t.Fatalf("cache metrics memory=%d redis=%d miss=%d, want 1/0/1", memoryHits, redisHits, misses)
	}
}

func TestEdgeHandlerBlocksWAFPathPrefix(t *testing.T) {
	originHits := 0
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
		waf: edgeWAFRules{
			enabled:      true,
			pathPrefixes: []string{"/edge/private"},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/private/app.js", nil)
	rec := httptest.NewRecorder()
	app.edgeHandler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if originHits != 0 {
		t.Fatalf("originHits = %d, want 0", originHits)
	}
	if got := app.wafMetricsSnapshot(); got != 1 {
		t.Fatalf("waf blocks = %d, want 1", got)
	}
}

func TestEdgeWAFBlocksHeadersAndIPs(t *testing.T) {
	_, cidr, err := net.ParseCIDR("203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	rules := edgeWAFRules{
		enabled: true,
		headers: []edgeWAFHeaderRule{
			{name: "User-Agent", valueContains: "badbot"},
		},
		ips: []edgeWAFIPRule{{cidr: cidr}},
	}

	headerReq := httptest.NewRequest(http.MethodGet, "/edge/app.js", nil)
	headerReq.Header.Set("User-Agent", "VeryBadBot/1.0")
	if !rules.blocks(headerReq) {
		t.Fatal("WAF did not block matching header")
	}

	ipReq := httptest.NewRequest(http.MethodGet, "/edge/app.js", nil)
	ipReq.Header.Set("X-Forwarded-For", "203.0.113.42")
	if !rules.blocks(ipReq) {
		t.Fatal("WAF did not block matching CIDR")
	}

	allowedReq := httptest.NewRequest(http.MethodGet, "/edge/app.js", nil)
	allowedReq.Header.Set("User-Agent", "Browser")
	allowedReq.Header.Set("X-Forwarded-For", "198.51.100.10")
	if rules.blocks(allowedReq) {
		t.Fatal("WAF blocked allowed request")
	}
}

func TestEdgeHandlerRequiresSignedCookieForProtectedPath(t *testing.T) {
	originHits := 0
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("protected"))
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	secret := "0123456789abcdef0123456789abcdef"
	now := time.Unix(100, 0)
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
		cookieSigner: signedCookieValidator{
			enabled:      true,
			secret:       secret,
			cookieName:   "AstraCDN-Signature",
			pathPrefixes: []string{"/edge/protected"},
			now:          func() time.Time { return now },
		},
	}

	missing := httptest.NewRecorder()
	app.edgeHandler(missing, httptest.NewRequest(http.MethodGet, "/edge/protected/file.txt", nil))
	if missing.Code != http.StatusForbidden {
		t.Fatalf("missing cookie status = %d, want %d", missing.Code, http.StatusForbidden)
	}

	expiredReq := httptest.NewRequest(http.MethodGet, "/edge/protected/file.txt", nil)
	expiredReq.AddCookie(&http.Cookie{
		Name:  "AstraCDN-Signature",
		Value: signedCookieValue(secret, "/edge/protected", "99"),
	})
	expired := httptest.NewRecorder()
	app.edgeHandler(expired, expiredReq)
	if expired.Code != http.StatusForbidden {
		t.Fatalf("expired cookie status = %d, want %d", expired.Code, http.StatusForbidden)
	}

	validReq := httptest.NewRequest(http.MethodGet, "/edge/protected/file.txt", nil)
	validReq.AddCookie(&http.Cookie{
		Name:  "AstraCDN-Signature",
		Value: signedCookieValue(secret, "/edge/protected", "101"),
	})
	valid := httptest.NewRecorder()
	app.edgeHandler(valid, validReq)
	if valid.Code != http.StatusOK {
		t.Fatalf("valid cookie status = %d, want %d body=%s", valid.Code, http.StatusOK, valid.Body.String())
	}
	if originHits != 1 {
		t.Fatalf("originHits = %d, want 1", originHits)
	}

	unprotected := httptest.NewRecorder()
	app.edgeHandler(unprotected, httptest.NewRequest(http.MethodGet, "/edge/public/file.txt", nil))
	if unprotected.Code != http.StatusOK {
		t.Fatalf("unprotected status = %d, want %d", unprotected.Code, http.StatusOK)
	}
}

func TestEdgeHandlerAppliesResponseHeaderRules(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Server", "origin-test")
		_, _ = w.Write([]byte("asset"))
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
		deliveryRules: edgeDeliveryRules{
			setHeaders: []edgeHeaderSetRule{
				{pathPrefix: "/edge/assets", name: "X-Frame-Options", value: "DENY"},
			},
			removeHeaders: []edgeHeaderRemoveRule{
				{pathPrefix: "/edge/assets", name: "Server"},
			},
		},
	}

	first := httptest.NewRecorder()
	app.edgeHandler(first, httptest.NewRequest(http.MethodGet, "/edge/assets/app.js", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d", first.Code)
	}
	if got := first.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("first X-Frame-Options = %q, want DENY", got)
	}
	if got := first.Header().Get("Server"); got != "" {
		t.Fatalf("first Server header = %q, want removed", got)
	}

	second := httptest.NewRecorder()
	app.edgeHandler(second, httptest.NewRequest(http.MethodGet, "/edge/assets/app.js", nil))
	if second.Code != http.StatusOK {
		t.Fatalf("second status = %d", second.Code)
	}
	if got := second.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("cached X-Frame-Options = %q, want DENY", got)
	}
	if got := second.Header().Get("Server"); got != "" {
		t.Fatalf("cached Server header = %q, want removed", got)
	}
}

func TestEdgeHandlerAppliesRedirectRules(t *testing.T) {
	originHits := 0
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
		deliveryRules: edgeDeliveryRules{
			redirects: []edgeRedirectRule{
				{pathPrefix: "/edge/old", target: "https://cdn.example/new{path}?{query}", status: http.StatusMovedPermanently},
			},
		},
	}

	rec := httptest.NewRecorder()
	app.edgeHandler(rec, httptest.NewRequest(http.MethodGet, "/edge/old/app.js?v=1", nil))

	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMovedPermanently)
	}
	if got := rec.Header().Get("Location"); got != "https://cdn.example/new/edge/old/app.js?v=1" {
		t.Fatalf("location = %q", got)
	}
	if originHits != 0 {
		t.Fatalf("originHits = %d, want 0", originHits)
	}
}

func TestEdgeHandlerAppliesScopedRateLimit(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("origin"))
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
		scopedLimiter: &edgeScopedRateLimiter{
			enabled: true,
			now:     func() time.Time { return time.Unix(100, 0) },
			rules: []edgeRateLimitRule{
				{host: "cdn.example", pathPrefix: "/edge/limited", rps: 1, burst: 1},
			},
			buckets: make(map[string]*rateLimitBucket),
		},
	}

	first := httptest.NewRequest(http.MethodGet, "/edge/limited/app.js", nil)
	first.Host = "cdn.example"
	first.Header.Set("X-Forwarded-For", "198.51.100.1")
	firstRec := httptest.NewRecorder()
	app.edgeHandler(firstRec, first)
	if firstRec.Code != http.StatusOK {
		t.Fatalf("first status = %d, want %d", firstRec.Code, http.StatusOK)
	}

	second := httptest.NewRequest(http.MethodGet, "/edge/limited/app.js", nil)
	second.Host = "cdn.example"
	second.Header.Set("X-Forwarded-For", "198.51.100.1")
	secondRec := httptest.NewRecorder()
	app.edgeHandler(secondRec, second)
	if secondRec.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want %d", secondRec.Code, http.StatusTooManyRequests)
	}

	otherClient := httptest.NewRequest(http.MethodGet, "/edge/limited/app.js", nil)
	otherClient.Host = "cdn.example"
	otherClient.Header.Set("X-Forwarded-For", "198.51.100.2")
	otherClientRec := httptest.NewRecorder()
	app.edgeHandler(otherClientRec, otherClient)
	if otherClientRec.Code != http.StatusOK {
		t.Fatalf("other client status = %d, want %d", otherClientRec.Code, http.StatusOK)
	}

	unmatched := httptest.NewRequest(http.MethodGet, "/edge/unlimited/app.js", nil)
	unmatched.Host = "cdn.example"
	unmatched.Header.Set("X-Forwarded-For", "198.51.100.1")
	unmatchedRec := httptest.NewRecorder()
	app.edgeHandler(unmatchedRec, unmatched)
	if unmatchedRec.Code != http.StatusOK {
		t.Fatalf("unmatched status = %d, want %d", unmatchedRec.Code, http.StatusOK)
	}
}

func TestParseEdgeRateLimitRules(t *testing.T) {
	rules := parseEdgeRateLimitRules("cdn.example|/edge/assets|2.5|10,*|/edge/public|1|2,bad")
	if len(rules) != 2 {
		t.Fatalf("rules = %+v", rules)
	}
	if rules[0].host != "cdn.example" || rules[0].pathPrefix != "/edge/assets" || rules[0].rps != 2.5 || rules[0].burst != 10 {
		t.Fatalf("unexpected first rule: %+v", rules[0])
	}
	if rules[1].host != "*" || rules[1].pathPrefix != "/edge/public" || rules[1].rps != 1 || rules[1].burst != 2 {
		t.Fatalf("unexpected second rule: %+v", rules[1])
	}
}

func TestEdgeHandlerCoalescesConcurrentCacheMisses(t *testing.T) {
	var mu sync.Mutex
	originHits := 0
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		originHits++
		hit := originHits
		mu.Unlock()
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "public, max-age=60")
		fmt.Fprintf(w, "origin hit %d", hit)
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase:        originBase,
		requestCoalescing: true,
		coalescer:         newOriginCoalescer(),
		client:            origin.Client(),
		cache:             newMemoryCache(),
		metrics:           newEdgeMetrics(),
	}

	const requestCount = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	codes := make(chan int, requestCount)
	bodies := make(chan string, requestCount)
	for i := 0; i < requestCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req := httptest.NewRequest(http.MethodGet, "/edge/coalesce.txt", nil)
			rec := httptest.NewRecorder()
			app.edgeHandler(rec, req)
			codes <- rec.Code
			bodies <- rec.Body.String()
		}()
	}
	close(start)
	wg.Wait()
	close(codes)
	close(bodies)

	for code := range codes {
		if code != http.StatusOK {
			t.Fatalf("status = %d, want %d", code, http.StatusOK)
		}
	}
	for body := range bodies {
		if body != "origin hit 1" {
			t.Fatalf("body = %q, want coalesced origin body", body)
		}
	}
	mu.Lock()
	gotOriginHits := originHits
	mu.Unlock()
	if gotOriginHits != 1 {
		t.Fatalf("originHits = %d, want 1", gotOriginHits)
	}
}

func TestApplyCachePrewarmFetchesAndCachesPaths(t *testing.T) {
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "public, max-age=60")
		fmt.Fprintf(w, "prewarm path=%s", r.URL.Path)
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase:        originBase,
		requestCoalescing: true,
		coalescer:         newOriginCoalescer(),
		client:            origin.Client(),
		cache:             newMemoryCache(),
		metrics:           newEdgeMetrics(),
	}
	warmed, failed := app.applyCachePrewarm(context.Background(), cachePrewarmEvent{
		ID:    9,
		Host:  "cdn.example",
		Paths: []string{"/edge/assets/app.js"},
	})
	if warmed != 1 || failed != 0 {
		t.Fatalf("warmed=%d failed=%d, want 1/0", warmed, failed)
	}
	if originHits != 1 {
		t.Fatalf("originHits = %d, want 1", originHits)
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/assets/app.js", nil)
	req.Host = "cdn.example"
	rec := httptest.NewRecorder()
	app.edgeHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("X-AstraCDN-Cache"); got != "HIT" {
		t.Fatalf("cache = %q, want HIT", got)
	}
	if originHits != 1 {
		t.Fatalf("originHits after hit = %d, want 1", originHits)
	}
}

func gunzipBody(t *testing.T, body string) string {
	t.Helper()
	reader, err := gzip.NewReader(strings.NewReader(body))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer reader.Close()
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("gzip read: %v", err)
	}
	return string(raw)
}

func brotliBody(t *testing.T, body string) string {
	t.Helper()
	raw, err := io.ReadAll(brotli.NewReader(strings.NewReader(body)))
	if err != nil {
		t.Fatalf("brotli read: %v", err)
	}
	return string(raw)
}

func TestEdgeHandlerSupportsHEADWithCache(t *testing.T) {
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = w.Write([]byte("head-cache-body"))
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	head := httptest.NewRecorder()
	app.edgeHandler(head, httptest.NewRequest(http.MethodHead, "/edge/head.txt", nil))
	if head.Code != http.StatusOK {
		t.Fatalf("HEAD status = %d, want %d", head.Code, http.StatusOK)
	}
	if got := head.Body.String(); got != "" {
		t.Fatalf("HEAD body = %q, want empty", got)
	}
	if got := head.Header().Get("X-AstraCDN-Cache"); got != "MISS" {
		t.Fatalf("HEAD cache = %q, want MISS", got)
	}

	get := httptest.NewRecorder()
	app.edgeHandler(get, httptest.NewRequest(http.MethodGet, "/edge/head.txt", nil))
	if get.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", get.Code, http.StatusOK)
	}
	if got := get.Header().Get("X-AstraCDN-Cache"); got != "HIT" {
		t.Fatalf("GET cache = %q, want HIT", got)
	}
	if got := get.Body.String(); got != "head-cache-body" {
		t.Fatalf("GET body = %q, want cached body", got)
	}
	if originHits != 1 {
		t.Fatalf("originHits = %d, want 1", originHits)
	}
}

func TestEdgeHandlerGzipsCompressibleResponse(t *testing.T) {
	body := strings.Repeat("edge compression body ", 80)
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = w.Write([]byte(body))
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/compress.txt", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	first := httptest.NewRecorder()
	app.edgeHandler(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", first.Code, http.StatusOK)
	}
	if got := first.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("content-encoding = %q, want gzip", got)
	}
	if got := first.Header().Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Fatalf("vary = %q, want Accept-Encoding", got)
	}
	if got := gunzipBody(t, first.Body.String()); got != body {
		t.Fatalf("decompressed body mismatch")
	}

	second := httptest.NewRecorder()
	app.edgeHandler(second, req)
	if got := second.Header().Get("X-AstraCDN-Cache"); got != "HIT" {
		t.Fatalf("second cache = %q, want HIT", got)
	}
	if got := gunzipBody(t, second.Body.String()); got != body {
		t.Fatalf("cached decompressed body mismatch")
	}
	if originHits != 1 {
		t.Fatalf("originHits = %d, want 1", originHits)
	}
}

func TestEdgeHandlerBrotliCompressesPreferredResponse(t *testing.T) {
	body := strings.Repeat("edge brotli compression body ", 80)
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = w.Write([]byte(body))
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/compress-br.txt", nil)
	req.Header.Set("Accept-Encoding", "gzip, br")
	first := httptest.NewRecorder()
	app.edgeHandler(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", first.Code, http.StatusOK)
	}
	if got := first.Header().Get("Content-Encoding"); got != "br" {
		t.Fatalf("content-encoding = %q, want br", got)
	}
	if got := first.Header().Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Fatalf("vary = %q, want Accept-Encoding", got)
	}
	if got := brotliBody(t, first.Body.String()); got != body {
		t.Fatalf("decompressed body mismatch")
	}

	second := httptest.NewRecorder()
	app.edgeHandler(second, req)
	if got := second.Header().Get("X-AstraCDN-Cache"); got != "HIT" {
		t.Fatalf("second cache = %q, want HIT", got)
	}
	if got := second.Header().Get("Content-Encoding"); got != "br" {
		t.Fatalf("second content-encoding = %q, want br", got)
	}
	if got := brotliBody(t, second.Body.String()); got != body {
		t.Fatalf("cached decompressed body mismatch")
	}
	if originHits != 1 {
		t.Fatalf("originHits = %d, want 1", originHits)
	}
}

func TestEdgeHandlerSkipsBrotliWhenDisabled(t *testing.T) {
	t.Setenv("EDGE_BROTLI_ENABLED", "false")
	body := strings.Repeat("edge gzip fallback body ", 80)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = w.Write([]byte(body))
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/compress-gzip-fallback.txt", nil)
	req.Header.Set("Accept-Encoding", "br, gzip")
	rec := httptest.NewRecorder()
	app.edgeHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("content-encoding = %q, want gzip", got)
	}
	if got := gunzipBody(t, rec.Body.String()); got != body {
		t.Fatalf("decompressed body mismatch")
	}
}

func TestEdgeHandlerRetriesOrigin5xx(t *testing.T) {
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		if originHits == 1 {
			http.Error(w, "temporary origin failure", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = w.Write([]byte("origin recovered"))
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase:     originBase,
		originAttempts: 2,
		originBackoff:  0,
		client:         origin.Client(),
		cache:          newMemoryCache(),
		metrics:        newEdgeMetrics(),
	}

	rec := httptest.NewRecorder()
	app.edgeHandler(rec, httptest.NewRequest(http.MethodGet, "/edge/retry.txt", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Header().Get("X-AstraCDN-Cache"); got != "MISS" {
		t.Fatalf("cache = %q, want MISS", got)
	}
	if got := rec.Body.String(); got != "origin recovered" {
		t.Fatalf("body = %q, want origin recovered", got)
	}
	if originHits != 2 {
		t.Fatalf("originHits = %d, want 2", originHits)
	}
}

func TestEdgeHandlerFailsOverToBackupOrigin(t *testing.T) {
	var primaryHits int
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryHits++
		http.Error(w, "primary failed", http.StatusBadGateway)
	}))
	defer primary.Close()

	var backupHits int
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backupHits++
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "public, max-age=60")
		fmt.Fprintf(w, "backup path=%s", r.URL.Path)
	}))
	defer backup.Close()

	primaryBase, err := url.Parse(primary.URL)
	if err != nil {
		t.Fatal(err)
	}
	backupBase, err := url.Parse(backup.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase:     primaryBase,
		originFailover: []*url.URL{backupBase},
		originAttempts: 1,
		originBackoff:  0,
		client:         primary.Client(),
		cache:          newMemoryCache(),
		metrics:        newEdgeMetrics(),
	}

	rec := httptest.NewRecorder()
	app.edgeHandler(rec, httptest.NewRequest(http.MethodGet, "/edge/failover.txt", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Body.String(); got != "backup path=/failover.txt" {
		t.Fatalf("body = %q, want backup response", got)
	}
	if primaryHits != 1 || backupHits != 1 {
		t.Fatalf("hits primary=%d backup=%d, want 1/1", primaryHits, backupHits)
	}
}

func TestEdgeHandlerUsesOriginShield(t *testing.T) {
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		http.Error(w, "direct origin should not be used", http.StatusInternalServerError)
	}))
	defer origin.Close()

	var shieldHits int
	shield := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shieldHits++
		if got := r.Header.Get(shieldHopHeader); got != "1" {
			t.Fatalf("shield hop header = %q, want 1", got)
		}
		if got := r.Host; got != "cdn.localhost" {
			t.Fatalf("shield host = %q, want cdn.localhost", got)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "public, max-age=60")
		fmt.Fprintf(w, "shield path=%s", r.URL.Path)
	}))
	defer shield.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	shieldBase, err := url.Parse(shield.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase:     originBase,
		originShield:   []*url.URL{shieldBase},
		originAttempts: 1,
		client:         shield.Client(),
		cache:          newMemoryCache(),
		metrics:        newEdgeMetrics(),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/shield.txt", nil)
	req.Host = "cdn.localhost"
	rec := httptest.NewRecorder()
	app.edgeHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Body.String(); got != "shield path=/edge/shield.txt" {
		t.Fatalf("body = %q, want shield response", got)
	}
	if originHits != 0 || shieldHits != 1 {
		t.Fatalf("hits origin=%d shield=%d, want 0/1", originHits, shieldHits)
	}
}

func TestEdgeHandlerFallsBackWhenOriginShieldFails(t *testing.T) {
	var shieldHits int
	shield := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shieldHits++
		http.Error(w, "shield failed", http.StatusBadGateway)
	}))
	defer shield.Close()

	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "public, max-age=60")
		fmt.Fprintf(w, "origin path=%s", r.URL.Path)
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	shieldBase, err := url.Parse(shield.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase:     originBase,
		originShield:   []*url.URL{shieldBase},
		originAttempts: 1,
		client:         origin.Client(),
		cache:          newMemoryCache(),
		metrics:        newEdgeMetrics(),
	}

	rec := httptest.NewRecorder()
	app.edgeHandler(rec, httptest.NewRequest(http.MethodGet, "/edge/fallback.txt", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Body.String(); got != "origin path=/fallback.txt" {
		t.Fatalf("body = %q, want direct origin response", got)
	}
	if shieldHits != 1 || originHits != 1 {
		t.Fatalf("hits shield=%d origin=%d, want 1/1", shieldHits, originHits)
	}
}

func TestEdgeHandlerDoesNotGzipRangeResponse(t *testing.T) {
	app := &edgeServer{
		cache:   newMemoryCache(),
		metrics: newEdgeMetrics(),
	}
	req := httptest.NewRequest(http.MethodGet, "/edge/range-compress.txt", nil)
	app.cache.set(cacheKeyForRequest(req), cacheEntry{
		status: http.StatusOK,
		header: http.Header{
			"Cache-Control": []string{"public, max-age=60"},
			"Content-Type":  []string{"text/plain"},
		},
		body:      []byte(strings.Repeat("0123456789", 80)),
		expiresAt: time.Now().Add(time.Minute),
	})

	req.Header.Set("Range", "bytes=2-5")
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	app.edgeHandler(rec, req)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusPartialContent)
	}
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("content-encoding = %q, want empty", got)
	}
	if got := rec.Body.String(); got != "2345" {
		t.Fatalf("body = %q, want 2345", got)
	}
}

func TestEdgeHandlerDoesNotCacheAuthorizedRequestByDefault(t *testing.T) {
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		w.Header().Set("Cache-Control", "public, max-age=60")
		fmt.Fprintf(w, "authorized hit %d", originHits)
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/edge/auth.txt", nil)
		req.Header.Set("Authorization", "Bearer user-token")
		rec := httptest.NewRecorder()
		app.edgeHandler(rec, req)
		if got := rec.Header().Get("X-AstraCDN-Cache"); got != "MISS" {
			t.Fatalf("request %d cache = %q, want MISS", i+1, got)
		}
	}
	if originHits != 2 {
		t.Fatalf("originHits = %d, want 2", originHits)
	}
}

func TestEdgeHandlerDoesNotCachePrivateResponse(t *testing.T) {
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		w.Header().Set("Cache-Control", "private, max-age=60")
		fmt.Fprintf(w, "private hit %d", originHits)
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		app.edgeHandler(rec, httptest.NewRequest(http.MethodGet, "/edge/private-cache.txt", nil))
		if got := rec.Header().Get("X-AstraCDN-Cache"); got != "MISS" {
			t.Fatalf("request %d cache = %q, want MISS", i+1, got)
		}
	}
	if originHits != 2 {
		t.Fatalf("originHits = %d, want 2", originHits)
	}
}

func TestEdgeHandlerRespectsVaryHeader(t *testing.T) {
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		lang := r.Header.Get("Accept-Language")
		if lang == "" {
			lang = "default"
		}
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Vary", "Accept-Language")
		fmt.Fprintf(w, "lang=%s hit=%d", lang, originHits)
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	firstENReq := httptest.NewRequest(http.MethodGet, "/edge/vary.txt", nil)
	firstENReq.Header.Set("Accept-Language", "en")
	firstEN := httptest.NewRecorder()
	app.edgeHandler(firstEN, firstENReq)
	if got := firstEN.Header().Get("X-AstraCDN-Cache"); got != "MISS" {
		t.Fatalf("first EN cache = %q, want MISS", got)
	}
	if got := firstEN.Body.String(); got != "lang=en hit=1" {
		t.Fatalf("first EN body = %q", got)
	}

	firstFRReq := httptest.NewRequest(http.MethodGet, "/edge/vary.txt", nil)
	firstFRReq.Header.Set("Accept-Language", "fr")
	firstFR := httptest.NewRecorder()
	app.edgeHandler(firstFR, firstFRReq)
	if got := firstFR.Header().Get("X-AstraCDN-Cache"); got != "MISS" {
		t.Fatalf("first FR cache = %q, want MISS", got)
	}
	if got := firstFR.Body.String(); got != "lang=fr hit=2" {
		t.Fatalf("first FR body = %q", got)
	}

	secondENReq := httptest.NewRequest(http.MethodGet, "/edge/vary.txt", nil)
	secondENReq.Header.Set("Accept-Language", "en")
	secondEN := httptest.NewRecorder()
	app.edgeHandler(secondEN, secondENReq)
	if got := secondEN.Header().Get("X-AstraCDN-Cache"); got != "HIT" {
		t.Fatalf("second EN cache = %q, want HIT", got)
	}
	if got := secondEN.Body.String(); got != "lang=en hit=1" {
		t.Fatalf("second EN body = %q", got)
	}
	if originHits != 2 {
		t.Fatalf("originHits = %d, want 2", originHits)
	}
}

func TestEdgeHandlerDoesNotCacheVaryStarResponse(t *testing.T) {
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Vary", "*")
		fmt.Fprintf(w, "vary-star hit %d", originHits)
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	for i := 1; i <= 2; i++ {
		rec := httptest.NewRecorder()
		app.edgeHandler(rec, httptest.NewRequest(http.MethodGet, "/edge/vary-star.txt", nil))
		if got := rec.Header().Get("X-AstraCDN-Cache"); got != "MISS" {
			t.Fatalf("request %d cache = %q, want MISS", i, got)
		}
		if got := rec.Body.String(); got != fmt.Sprintf("vary-star hit %d", i) {
			t.Fatalf("request %d body = %q", i, got)
		}
	}
	if originHits != 2 {
		t.Fatalf("originHits = %d, want 2", originHits)
	}
}

func TestEdgeHandlerCacheIsolatesHosts(t *testing.T) {
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		w.Header().Set("Cache-Control", "public, max-age=60")
		fmt.Fprintf(w, "origin hit %d", originHits)
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	hostA := httptest.NewRequest(http.MethodGet, "/edge/assets/app.js", nil)
	hostA.Host = "cdn-a.example"
	firstA := httptest.NewRecorder()
	app.edgeHandler(firstA, hostA)
	if got := firstA.Header().Get("X-AstraCDN-Cache"); got != "MISS" {
		t.Fatalf("first host A cache = %q, want MISS", got)
	}

	hostB := httptest.NewRequest(http.MethodGet, "/edge/assets/app.js", nil)
	hostB.Host = "cdn-b.example"
	firstB := httptest.NewRecorder()
	app.edgeHandler(firstB, hostB)
	if got := firstB.Header().Get("X-AstraCDN-Cache"); got != "MISS" {
		t.Fatalf("first host B cache = %q, want MISS", got)
	}
	if firstA.Body.String() == firstB.Body.String() {
		t.Fatalf("host B reused host A body: %q", firstB.Body.String())
	}

	secondA := httptest.NewRecorder()
	app.edgeHandler(secondA, hostA)
	if got := secondA.Header().Get("X-AstraCDN-Cache"); got != "HIT" {
		t.Fatalf("second host A cache = %q, want HIT", got)
	}
	if secondA.Body.String() != firstA.Body.String() {
		t.Fatalf("host A cached body = %q, want %q", secondA.Body.String(), firstA.Body.String())
	}

	secondB := httptest.NewRecorder()
	app.edgeHandler(secondB, hostB)
	if got := secondB.Header().Get("X-AstraCDN-Cache"); got != "HIT" {
		t.Fatalf("second host B cache = %q, want HIT", got)
	}
	if secondB.Body.String() != firstB.Body.String() {
		t.Fatalf("host B cached body = %q, want %q", secondB.Body.String(), firstB.Body.String())
	}
	if originHits != 2 {
		t.Fatalf("originHits = %d, want 2", originHits)
	}
}

func TestEdgeHandlerRevalidatesStaleETagCacheEntry(t *testing.T) {
	var originHits int
	var ifNoneMatch string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		ifNoneMatch = r.Header.Get("If-None-Match")
		w.Header().Set("Cache-Control", "public, max-age=30")
		w.Header().Set("ETag", `"asset-v1"`)
		w.WriteHeader(http.StatusNotModified)
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/assets/app.js", nil)
	app.cache.set(cacheKeyForRequest(req), cacheEntry{
		status: http.StatusOK,
		header: http.Header{
			"Cache-Control": []string{"public, max-age=1"},
			"Content-Type":  []string{"application/javascript"},
			"Etag":          []string{`"asset-v1"`},
		},
		body:      []byte("cached-v1"),
		expiresAt: time.Now().Add(-time.Second),
	})

	rec := httptest.NewRecorder()
	app.edgeHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Header().Get("X-AstraCDN-Cache"); got != "REVALIDATED" {
		t.Fatalf("cache status = %q, want REVALIDATED", got)
	}
	if got := rec.Body.String(); got != "cached-v1" {
		t.Fatalf("body = %q, want cached-v1", got)
	}
	if ifNoneMatch != `"asset-v1"` {
		t.Fatalf("If-None-Match = %q", ifNoneMatch)
	}
	if originHits != 1 {
		t.Fatalf("originHits = %d, want 1", originHits)
	}

	second := httptest.NewRecorder()
	app.edgeHandler(second, httptest.NewRequest(http.MethodGet, "/edge/assets/app.js", nil))
	if got := second.Header().Get("X-AstraCDN-Cache"); got != "HIT" {
		t.Fatalf("second cache status = %q, want HIT", got)
	}
	if originHits != 1 {
		t.Fatalf("originHits after fresh hit = %d, want 1", originHits)
	}
}

func TestEdgeHandlerRevalidatesFreshCacheOnRequestNoCache(t *testing.T) {
	var originHits int
	var ifNoneMatch string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		ifNoneMatch = r.Header.Get("If-None-Match")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("ETag", `"asset-v1"`)
		if ifNoneMatch == `"asset-v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte("cached-v1"))
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	first := httptest.NewRecorder()
	app.edgeHandler(first, httptest.NewRequest(http.MethodGet, "/edge/no-cache-request.js", nil))
	if got := first.Header().Get("X-AstraCDN-Cache"); got != "MISS" {
		t.Fatalf("first cache = %q, want MISS", got)
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/no-cache-request.js", nil)
	req.Header.Set("Cache-Control", "no-cache")
	second := httptest.NewRecorder()
	app.edgeHandler(second, req)
	if got := second.Header().Get("X-AstraCDN-Cache"); got != "REVALIDATED" {
		t.Fatalf("second cache = %q, want REVALIDATED", got)
	}
	if ifNoneMatch != `"asset-v1"` {
		t.Fatalf("If-None-Match = %q", ifNoneMatch)
	}
	if originHits != 2 {
		t.Fatalf("originHits = %d, want 2", originHits)
	}
}

func TestEdgeHandlerStoresNoCacheResponseAndRevalidatesBeforeReuse(t *testing.T) {
	var originHits int
	var ifNoneMatch string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		ifNoneMatch = r.Header.Get("If-None-Match")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("ETag", `"asset-v1"`)
		if ifNoneMatch == `"asset-v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte("cached-v1"))
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	first := httptest.NewRecorder()
	app.edgeHandler(first, httptest.NewRequest(http.MethodGet, "/edge/no-cache-response.js", nil))
	if got := first.Header().Get("X-AstraCDN-Cache"); got != "MISS" {
		t.Fatalf("first cache = %q, want MISS", got)
	}

	second := httptest.NewRecorder()
	app.edgeHandler(second, httptest.NewRequest(http.MethodGet, "/edge/no-cache-response.js", nil))
	if got := second.Header().Get("X-AstraCDN-Cache"); got != "REVALIDATED" {
		t.Fatalf("second cache = %q, want REVALIDATED", got)
	}
	if got := second.Body.String(); got != "cached-v1" {
		t.Fatalf("second body = %q, want cached-v1", got)
	}
	if ifNoneMatch != `"asset-v1"` {
		t.Fatalf("If-None-Match = %q", ifNoneMatch)
	}
	if originHits != 2 {
		t.Fatalf("originHits = %d, want 2", originHits)
	}
}

func TestEdgeHandlerServesStaleIfErrorOnOriginRevalidationFailure(t *testing.T) {
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		w.Header().Set("Cache-Control", "public, max-age=30")
		http.Error(w, "origin failed", http.StatusInternalServerError)
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/stale-if-error.js", nil)
	app.cache.set(cacheKeyForRequest(req), cacheEntry{
		status: http.StatusOK,
		header: http.Header{
			"Cache-Control": []string{"public, max-age=1, stale-if-error=60"},
			"Content-Type":  []string{"application/javascript"},
			"Etag":          []string{`"asset-v1"`},
		},
		body:      []byte("cached-stale"),
		expiresAt: time.Now().Add(-time.Second),
	})

	rec := httptest.NewRecorder()
	app.edgeHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Header().Get("X-AstraCDN-Cache"); got != "STALE" {
		t.Fatalf("cache status = %q, want STALE", got)
	}
	if got := rec.Body.String(); got != "cached-stale" {
		t.Fatalf("body = %q, want cached-stale", got)
	}
	if originHits != 1 {
		t.Fatalf("originHits = %d, want 1", originHits)
	}
}

func TestEdgeHandlerDoesNotServeStaleIfErrorOutsideWindow(t *testing.T) {
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		http.Error(w, "origin failed", http.StatusInternalServerError)
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/stale-if-error-expired.js", nil)
	app.cache.set(cacheKeyForRequest(req), cacheEntry{
		status: http.StatusOK,
		header: http.Header{
			"Cache-Control": []string{"public, max-age=1, stale-if-error=1"},
			"Etag":          []string{`"asset-v1"`},
		},
		body:      []byte("too-old-stale"),
		expiresAt: time.Now().Add(-2 * time.Second),
	})

	rec := httptest.NewRecorder()
	app.edgeHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	if got := rec.Header().Get("X-AstraCDN-Cache"); got != "MISS" {
		t.Fatalf("cache status = %q, want MISS", got)
	}
	if got := rec.Body.String(); !strings.Contains(got, "origin failed") {
		t.Fatalf("body = %q, want origin failure", got)
	}
	if originHits != 1 {
		t.Fatalf("originHits = %d, want 1", originHits)
	}
}

func TestEdgeHandlerRevalidatesStaleLastModifiedCacheEntry(t *testing.T) {
	var ifModifiedSince string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ifModifiedSince = r.Header.Get("If-Modified-Since")
		w.Header().Set("Cache-Control", "public, max-age=30")
		w.Header().Set("Last-Modified", "Sun, 24 May 2026 09:00:00 GMT")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/assets/app.css", nil)
	app.cache.set(cacheKeyForRequest(req), cacheEntry{
		status: http.StatusOK,
		header: http.Header{
			"Cache-Control": []string{"public, max-age=1"},
			"Last-Modified": []string{"Sun, 24 May 2026 09:00:00 GMT"},
		},
		body:      []byte("cached-css"),
		expiresAt: time.Now().Add(-time.Second),
	})

	rec := httptest.NewRecorder()
	app.edgeHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Header().Get("X-AstraCDN-Cache"); got != "REVALIDATED" {
		t.Fatalf("cache status = %q, want REVALIDATED", got)
	}
	if ifModifiedSince != "Sun, 24 May 2026 09:00:00 GMT" {
		t.Fatalf("If-Modified-Since = %q", ifModifiedSince)
	}
}

func TestEdgeHandlerServesByteRangeFromCachedObject(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	warm := httptest.NewRecorder()
	app.edgeHandler(warm, httptest.NewRequest(http.MethodGet, "/edge/range.txt", nil))
	if warm.Code != http.StatusOK {
		t.Fatalf("warm status = %d", warm.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/range.txt", nil)
	req.Header.Set("Range", "bytes=2-5")
	rec := httptest.NewRecorder()
	app.edgeHandler(rec, req)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusPartialContent, rec.Body.String())
	}
	if got := rec.Body.String(); got != "2345" {
		t.Fatalf("body = %q, want 2345", got)
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes 2-5/10" {
		t.Fatalf("content-range = %q", got)
	}
	if got := rec.Header().Get("Content-Length"); got != "4" {
		t.Fatalf("content-length = %q", got)
	}
	if got := rec.Header().Get("Accept-Ranges"); got != "bytes" {
		t.Fatalf("accept-ranges = %q", got)
	}
	if got := rec.Header().Get("X-AstraCDN-Cache"); got != "HIT" {
		t.Fatalf("cache = %q, want HIT", got)
	}
}

func TestEdgeHandlerServesSuffixByteRangeFromCachedObject(t *testing.T) {
	app := &edgeServer{
		cache:   newMemoryCache(),
		metrics: newEdgeMetrics(),
	}
	req := httptest.NewRequest(http.MethodGet, "/edge/range.txt", nil)
	app.cache.set(cacheKeyForRequest(req), cacheEntry{
		status:    http.StatusOK,
		header:    http.Header{"Cache-Control": []string{"public, max-age=60"}},
		body:      []byte("0123456789"),
		expiresAt: time.Now().Add(time.Minute),
	})

	req.Header.Set("Range", "bytes=-3")
	rec := httptest.NewRecorder()
	app.edgeHandler(rec, req)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusPartialContent, rec.Body.String())
	}
	if got := rec.Body.String(); got != "789" {
		t.Fatalf("body = %q, want 789", got)
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes 7-9/10" {
		t.Fatalf("content-range = %q", got)
	}
}

func TestEdgeHandlerRejectsUnsatisfiableCachedByteRange(t *testing.T) {
	app := &edgeServer{
		cache:   newMemoryCache(),
		metrics: newEdgeMetrics(),
	}
	req := httptest.NewRequest(http.MethodGet, "/edge/range.txt", nil)
	app.cache.set(cacheKeyForRequest(req), cacheEntry{
		status:    http.StatusOK,
		header:    http.Header{"Cache-Control": []string{"public, max-age=60"}},
		body:      []byte("0123456789"),
		expiresAt: time.Now().Add(time.Minute),
	})

	req.Header.Set("Range", "bytes=99-100")
	rec := httptest.NewRecorder()
	app.edgeHandler(rec, req)

	if rec.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestedRangeNotSatisfiable)
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes */10" {
		t.Fatalf("content-range = %q", got)
	}
}

func TestEdgeHandlerUsesControlPlaneRouteOrigin(t *testing.T) {
	fallbackOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("fallback"))
	}))
	defer fallbackOrigin.Close()

	routedOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		fmt.Fprintf(w, "routed path=%s", r.URL.Path)
	}))
	defer routedOrigin.Close()

	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"routes": []map[string]any{
				{
					"host":            "cdn.example",
					"path_prefix":     "/assets/",
					"origin_base_url": routedOrigin.URL,
					"cache_policy":    map[string]any{"mode": "origin"},
				},
			},
		})
	}))
	defer control.Close()

	fallbackBase, err := url.Parse(fallbackOrigin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: fallbackBase,
		client:     routedOrigin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
		routes:     newRouteConfigStore(control.URL, "", time.Nanosecond),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/assets/app.js", nil)
	req.Host = "cdn.example"
	rec := httptest.NewRecorder()
	app.edgeHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Body.String(); got != "routed path=/assets/app.js" {
		t.Fatalf("body = %q", got)
	}
}

func TestEdgeHandlerAppliesControlPlaneRouteDeliveryHeaders(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "origin")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()

	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"routes": []map[string]any{
				{
					"host":            "cdn.example",
					"path_prefix":     "/assets/",
					"origin_base_url": origin.URL,
					"cache_policy":    map[string]any{"mode": "origin"},
					"delivery_rules": map[string]any{
						"set_headers": []map[string]any{
							{"path_prefix": "/edge/assets/", "name": "X-AstraCDN-Control-Rule", "value": "yes"},
						},
						"remove_headers": []map[string]any{
							{"path_prefix": "/edge/assets/", "name": "Server"},
						},
					},
				},
			},
		})
	}))
	defer control.Close()

	fallbackBase, err := url.Parse("http://fallback.invalid")
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: fallbackBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
		routes:     newRouteConfigStore(control.URL, "", time.Nanosecond),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/assets/app.js", nil)
	req.Host = "cdn.example"
	rec := httptest.NewRecorder()
	app.edgeHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Header().Get("X-AstraCDN-Control-Rule"); got != "yes" {
		t.Fatalf("control rule header = %q, want yes", got)
	}
	if got := rec.Header().Get("Server"); got != "" {
		t.Fatalf("server header = %q, want removed", got)
	}
}

func TestEdgeHandlerAppliesControlPlaneRouteRedirect(t *testing.T) {
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		_, _ = w.Write([]byte("origin"))
	}))
	defer origin.Close()

	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"routes": []map[string]any{
				{
					"host":            "cdn.example",
					"path_prefix":     "/legacy/",
					"origin_base_url": origin.URL,
					"cache_policy":    map[string]any{"mode": "origin"},
					"delivery_rules": map[string]any{
						"redirects": []map[string]any{
							{"path_prefix": "/edge/legacy/", "target": "https://cdn.example/new{path}", "status": 308},
						},
					},
				},
			},
		})
	}))
	defer control.Close()

	fallbackBase, err := url.Parse("http://fallback.invalid")
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: fallbackBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
		routes:     newRouteConfigStore(control.URL, "", time.Nanosecond),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/legacy/app.js", nil)
	req.Host = "cdn.example"
	rec := httptest.NewRecorder()
	app.edgeHandler(rec, req)

	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusPermanentRedirect, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "https://cdn.example/new/edge/legacy/app.js" {
		t.Fatalf("location = %q", got)
	}
	if originHits != 0 {
		t.Fatalf("originHits = %d, want 0", originHits)
	}
}

func TestEdgeHandlerAppliesControlPlaneRouteWAFRules(t *testing.T) {
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		_, _ = w.Write([]byte("origin"))
	}))
	defer origin.Close()

	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"routes": []map[string]any{
				{
					"host":            "cdn.example",
					"path_prefix":     "/admin/",
					"origin_base_url": origin.URL,
					"cache_policy":    map[string]any{"mode": "origin"},
					"waf_rules": map[string]any{
						"enabled": true,
						"headers": []map[string]any{
							{"name": "User-Agent", "value_contains": "badbot"},
						},
					},
				},
			},
		})
	}))
	defer control.Close()

	fallbackBase, err := url.Parse("http://fallback.invalid")
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: fallbackBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
		routes:     newRouteConfigStore(control.URL, "", time.Nanosecond),
	}

	blockedReq := httptest.NewRequest(http.MethodGet, "/edge/admin/panel", nil)
	blockedReq.Host = "cdn.example"
	blockedReq.Header.Set("User-Agent", "BadBot/1.0")
	blocked := httptest.NewRecorder()
	app.edgeHandler(blocked, blockedReq)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("blocked status = %d, want %d body=%s", blocked.Code, http.StatusForbidden, blocked.Body.String())
	}
	if got := app.wafMetricsSnapshot(); got != 1 {
		t.Fatalf("waf blocks = %d, want 1", got)
	}

	allowedReq := httptest.NewRequest(http.MethodGet, "/edge/admin/panel", nil)
	allowedReq.Host = "cdn.example"
	allowed := httptest.NewRecorder()
	app.edgeHandler(allowed, allowedReq)
	if allowed.Code != http.StatusOK {
		t.Fatalf("allowed status = %d, want %d body=%s", allowed.Code, http.StatusOK, allowed.Body.String())
	}
	if originHits != 1 {
		t.Fatalf("originHits = %d, want 1", originHits)
	}
}

func TestEdgeHandlerAppliesControlPlaneRouteRateLimitRules(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("origin"))
	}))
	defer origin.Close()

	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"routes": []map[string]any{
				{
					"host":            "cdn.example",
					"path_prefix":     "/limited/",
					"origin_base_url": origin.URL,
					"cache_policy":    map[string]any{"mode": "origin"},
					"rate_limit_rules": []map[string]any{
						{"host": "cdn.example", "path_prefix": "/edge/limited/", "rps": 1, "burst": 1},
					},
				},
			},
		})
	}))
	defer control.Close()

	fallbackBase, err := url.Parse("http://fallback.invalid")
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: fallbackBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
		routes:     newRouteConfigStore(control.URL, "", time.Nanosecond),
		scopedLimiter: &edgeScopedRateLimiter{
			enabled: true,
			now:     func() time.Time { return time.Unix(100, 0) },
			buckets: make(map[string]*rateLimitBucket),
		},
	}

	first := httptest.NewRequest(http.MethodGet, "/edge/limited/app.js", nil)
	first.Host = "cdn.example"
	first.Header.Set("X-Forwarded-For", "198.51.100.10")
	firstRec := httptest.NewRecorder()
	app.edgeHandler(firstRec, first)
	if firstRec.Code != http.StatusOK {
		t.Fatalf("first status = %d, want %d body=%s", firstRec.Code, http.StatusOK, firstRec.Body.String())
	}

	second := httptest.NewRequest(http.MethodGet, "/edge/limited/app.js", nil)
	second.Host = "cdn.example"
	second.Header.Set("X-Forwarded-For", "198.51.100.10")
	secondRec := httptest.NewRecorder()
	app.edgeHandler(secondRec, second)
	if secondRec.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want %d body=%s", secondRec.Code, http.StatusTooManyRequests, secondRec.Body.String())
	}
}

func TestEdgeHandlerRejectsUnconfiguredDomainWhenValidationEnabled(t *testing.T) {
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		_, _ = w.Write([]byte("origin"))
	}))
	defer origin.Close()

	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/routes":
			writeJSON(w, http.StatusOK, map[string]any{"routes": []map[string]any{}})
		case "/v1/domains":
			writeJSON(w, http.StatusOK, map[string]any{
				"domains": []map[string]any{
					{"host": "cdn.example", "tls_mode": "managed", "status": "active"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer control.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase:     originBase,
		validateDomain: true,
		client:         origin.Client(),
		cache:          newMemoryCache(),
		metrics:        newEdgeMetrics(),
		routes:         newRouteConfigStore(control.URL, "", time.Nanosecond),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/assets/app.js", nil)
	req.Host = "unknown.example"
	rec := httptest.NewRecorder()
	app.edgeHandler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
	if originHits != 0 {
		t.Fatalf("originHits = %d, want 0", originHits)
	}
}

func TestEdgeHandlerAllowsConfiguredDomainWhenValidationEnabled(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("allowed"))
	}))
	defer origin.Close()

	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/routes":
			writeJSON(w, http.StatusOK, map[string]any{"routes": []map[string]any{}})
		case "/v1/domains":
			writeJSON(w, http.StatusOK, map[string]any{
				"domains": []map[string]any{
					{"host": "CDN.Example.", "tls_mode": "managed", "status": "active"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer control.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase:     originBase,
		validateDomain: true,
		client:         origin.Client(),
		cache:          newMemoryCache(),
		metrics:        newEdgeMetrics(),
		routes:         newRouteConfigStore(control.URL, "", time.Nanosecond),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/assets/app.js", nil)
	req.Host = "cdn.example:8443"
	rec := httptest.NewRecorder()
	app.edgeHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Body.String(); got != "allowed" {
		t.Fatalf("body = %q, want allowed", got)
	}
}

func TestEdgeHandlerRouteOverridePolicyCachesWithoutOriginCacheHeader(t *testing.T) {
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		fmt.Fprintf(w, "origin hit %d", originHits)
	}))
	defer origin.Close()

	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"routes": []map[string]any{
				{
					"host":            "cdn.example",
					"path_prefix":     "/assets/",
					"origin_base_url": origin.URL,
					"cache_policy": map[string]any{
						"mode":        "override",
						"ttl_seconds": 60,
					},
				},
			},
		})
	}))
	defer control.Close()

	originBase, err := url.Parse("http://fallback.invalid")
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
		routes:     newRouteConfigStore(control.URL, "", time.Nanosecond),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/assets/app.js", nil)
	req.Host = "cdn.example"
	first := httptest.NewRecorder()
	app.edgeHandler(first, req)
	if got := first.Header().Get("X-AstraCDN-Cache"); got != "MISS" {
		t.Fatalf("first cache = %q", got)
	}

	second := httptest.NewRecorder()
	app.edgeHandler(second, req)
	if got := second.Header().Get("X-AstraCDN-Cache"); got != "HIT" {
		t.Fatalf("second cache = %q", got)
	}
	if originHits != 1 {
		t.Fatalf("originHits = %d, want 1", originHits)
	}
}

func TestEdgeHandlerRouteBypassPolicySkipsCache(t *testing.T) {
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		w.Header().Set("Cache-Control", "public, max-age=60")
		fmt.Fprintf(w, "origin hit %d", originHits)
	}))
	defer origin.Close()

	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"routes": []map[string]any{
				{
					"host":            "cdn.example",
					"path_prefix":     "/private/",
					"origin_base_url": origin.URL,
					"cache_policy":    map[string]any{"mode": "bypass"},
				},
			},
		})
	}))
	defer control.Close()

	originBase, err := url.Parse("http://fallback.invalid")
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
		routes:     newRouteConfigStore(control.URL, "", time.Nanosecond),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/private/data.json", nil)
	req.Host = "cdn.example"
	first := httptest.NewRecorder()
	app.edgeHandler(first, req)
	if got := first.Header().Get("X-AstraCDN-Cache"); got != "BYPASS" {
		t.Fatalf("first cache = %q", got)
	}

	second := httptest.NewRecorder()
	app.edgeHandler(second, req)
	if got := second.Header().Get("X-AstraCDN-Cache"); got != "BYPASS" {
		t.Fatalf("second cache = %q", got)
	}
	if originHits != 2 {
		t.Fatalf("originHits = %d, want 2", originHits)
	}
}

func TestRouteConfigStoreRefreshReplacesRoutes(t *testing.T) {
	firstOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer firstOrigin.Close()
	secondOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer secondOrigin.Close()

	var originBaseURL = firstOrigin.URL
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"routes": []map[string]any{
				{
					"host":            "cdn.example",
					"path_prefix":     "/assets/",
					"origin_base_url": originBaseURL,
					"cache_policy":    map[string]any{"mode": "origin"},
				},
			},
		})
	}))
	defer control.Close()

	store := newRouteConfigStore(control.URL, "", time.Hour)
	if err := store.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	firstRoute, ok := store.match("cdn.example", "/assets/app.js")
	if !ok || firstRoute.OriginBaseURL != firstOrigin.URL {
		t.Fatalf("first route = %+v ok=%v", firstRoute, ok)
	}

	originBaseURL = secondOrigin.URL
	if err := store.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	secondRoute, ok := store.match("cdn.example", "/assets/app.js")
	if !ok || secondRoute.OriginBaseURL != secondOrigin.URL {
		t.Fatalf("second route = %+v ok=%v", secondRoute, ok)
	}
}

func TestEdgeHandlerForwardsRangeOnCacheMiss(t *testing.T) {
	var gotRange string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRange = r.Header.Get("Range")
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Range", "bytes 2-5/10")
		w.Header().Set("Accept-Ranges", "bytes")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write([]byte("2345"))
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/range.txt", nil)
	req.Header.Set("Range", "bytes=2-5")
	rec := httptest.NewRecorder()
	app.edgeHandler(rec, req)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusPartialContent, rec.Body.String())
	}
	if gotRange != "bytes=2-5" {
		t.Fatalf("origin range = %q", gotRange)
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes 2-5/10" {
		t.Fatalf("content-range = %q", got)
	}
	if _, ok := app.cache.get(cacheKeyForRequest(req)); ok {
		t.Fatal("partial origin response should not be cached as a full object")
	}
}

func TestEdgeHandlerStreamsAndCachesLargeOriginResponseAsSegments(t *testing.T) {
	t.Setenv("EDGE_LARGE_OBJECT_STREAMING_ENABLED", "true")
	t.Setenv("EDGE_LARGE_OBJECT_THRESHOLD_BYTES", "32")
	t.Setenv("EDGE_SEGMENTED_CACHE_ENABLED", "true")
	t.Setenv("EDGE_SEGMENT_SIZE_BYTES", "25")
	body := strings.Repeat("large-object-", 16)
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = w.Write([]byte(body))
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/large.bin", nil)
	req.Header.Set("Accept-Encoding", "gzip, br")
	first := httptest.NewRecorder()
	app.edgeHandler(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", first.Code, http.StatusOK)
	}
	if got := first.Header().Get("X-AstraCDN-Cache-Layer"); got != "origin-stream" {
		t.Fatalf("cache layer = %q, want origin-stream", got)
	}
	if got := first.Header().Get("X-AstraCDN-Streaming"); got != "1" {
		t.Fatalf("streaming header = %q, want 1", got)
	}
	if got := first.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("content-encoding = %q, want empty for streamed large object", got)
	}
	if got := first.Body.String(); got != body {
		t.Fatalf("body mismatch")
	}
	manifest, ok := app.cache.get(cacheKeyForRequest(req))
	if !ok {
		t.Fatal("large streamed response should store segmented manifest")
	}
	if !manifest.segmented || manifest.segmentCount < 2 {
		t.Fatalf("manifest segmented=%v segmentCount=%d", manifest.segmented, manifest.segmentCount)
	}

	second := httptest.NewRecorder()
	app.edgeHandler(second, req)
	if got := second.Header().Get("X-AstraCDN-Cache"); got != "HIT" {
		t.Fatalf("second cache = %q, want HIT", got)
	}
	if got := second.Header().Get("X-AstraCDN-Segmented-Cache"); got != "1" {
		t.Fatalf("segmented cache header = %q, want 1", got)
	}
	if got := second.Body.String(); got != body {
		t.Fatalf("segmented cached body mismatch")
	}
	if originHits != 1 {
		t.Fatalf("originHits = %d, want 1 because second response is served from segments", originHits)
	}
}

func TestEdgeHandlerTransformsAndCachesImageVariant(t *testing.T) {
	t.Setenv("EDGE_IMAGE_TRANSFORM_ENABLED", "true")
	t.Setenv("EDGE_IMAGE_TRANSFORM_MAX_DIMENSION", "64")
	source := image.NewRGBA(image.Rect(0, 0, 4, 2))
	for y := 0; y < 2; y++ {
		for x := 0; x < 4; x++ {
			source.Set(x, y, color.RGBA{R: uint8(30 + x*20), G: uint8(60 + y*40), B: 120, A: 255})
		}
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, source); err != nil {
		t.Fatal(err)
	}
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Etag", `"source-image"`)
		_, _ = w.Write(encoded.Bytes())
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/image.png?width=2&format=png", nil)
	first := httptest.NewRecorder()
	app.edgeHandler(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", first.Code, http.StatusOK)
	}
	if got := first.Header().Get("Content-Type"); got != "image/png" {
		t.Fatalf("content-type = %q, want image/png", got)
	}
	if got := first.Header().Get("X-AstraCDN-Image-Transform"); got != "width=2;height=1;format=png" {
		t.Fatalf("transform header = %q", got)
	}
	if got := first.Header().Get("Etag"); got != "" {
		t.Fatalf("etag = %q, want removed for transformed body", got)
	}
	decoded, _, err := image.Decode(strings.NewReader(first.Body.String()))
	if err != nil {
		t.Fatalf("decode transformed image: %v", err)
	}
	if got := decoded.Bounds().Dx(); got != 2 {
		t.Fatalf("width = %d, want 2", got)
	}
	if got := decoded.Bounds().Dy(); got != 1 {
		t.Fatalf("height = %d, want 1", got)
	}

	second := httptest.NewRecorder()
	app.edgeHandler(second, req)
	if got := second.Header().Get("X-AstraCDN-Cache"); got != "HIT" {
		t.Fatalf("second cache = %q, want HIT", got)
	}
	if originHits != 1 {
		t.Fatalf("originHits = %d, want 1", originHits)
	}
}

func TestObservabilityMiddlewareAddsRequestID(t *testing.T) {
	handler := observabilityMiddleware("edge", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := requestIDFromContext(r.Context()); got != "req-edge-1" {
			t.Fatalf("request id in context = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Request-ID", "req-edge-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if got := rec.Header().Get("X-Request-ID"); got != "req-edge-1" {
		t.Fatalf("response request id = %q", got)
	}
}

func TestCORSMiddlewareHandlesAllowedPreflight(t *testing.T) {
	t.Setenv("CORS_ENABLED", "true")
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://dashboard.example")

	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("preflight should not reach next handler")
	}))

	req := httptest.NewRequest(http.MethodOptions, "/edge/assets/app.js", nil)
	req.Header.Set("Origin", "https://dashboard.example")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://dashboard.example" {
		t.Fatalf("allow origin = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Expose-Headers"); !strings.Contains(got, "X-AstraCDN-Cache") {
		t.Fatalf("expose headers = %q, want cache headers", got)
	}
}

func TestCORSMiddlewareRejectsDisallowedPreflight(t *testing.T) {
	t.Setenv("CORS_ENABLED", "true")
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://dashboard.example")

	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("disallowed preflight should not reach next handler")
	}))

	req := httptest.NewRequest(http.MethodOptions, "/edge/assets/app.js", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestReadyHandlerRejectsMissingDependencies(t *testing.T) {
	app := &edgeServer{}

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	app.readyHandler(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rec.Body.String(), `"ready":false`) {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestMetricsHandlerReportsCacheCounters(t *testing.T) {
	app := &edgeServer{metrics: newEdgeMetrics()}
	app.recordCacheMetric("memory")
	app.recordCacheMetric("redis")
	app.recordCacheMetric("origin")
	app.recordCacheFillLatency(250 * time.Millisecond)
	reqMetric := httptest.NewRequest(http.MethodGet, "/edge/assets/app.js", nil)
	reqMetric.Host = "cdn.example"
	app.recordCacheMetricForRequest("memory", reqMetric, requestRoute{host: "cdn.example", pathPrefix: "/assets", matched: true})
	app.recordRateLimitBlock()
	app.recordWAFBlock()
	app.recordInvalidation("keys")
	app.recordInvalidationFailure()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	app.metricsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`astracdn_edge_cache_requests_total{result="hit",layer="memory"} 2`,
		`astracdn_edge_cache_requests_total{result="hit",layer="redis"} 1`,
		`astracdn_edge_cache_requests_total{result="miss",layer="origin"} 1`,
		`astracdn_edge_cache_requests_by_host_total{host="cdn.example",result="hit",layer="memory"} 1`,
		`astracdn_edge_cache_requests_by_route_total{route="cdn.example:/assets",result="hit",layer="memory"} 1`,
		`astracdn_edge_cache_fill_latency_seconds_count 1`,
		`astracdn_edge_cache_fill_latency_seconds_sum 0.250000`,
		`astracdn_edge_cache_fill_latency_seconds_max 0.250000`,
		`astracdn_edge_rate_limit_blocks_total 1`,
		`astracdn_edge_waf_blocks_total 1`,
		`astracdn_edge_cache_invalidations_total{mode="keys"} 1`,
		`astracdn_edge_cache_invalidation_failures_total 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q:\n%s", want, body)
		}
	}
}

func TestCacheAnalyticsHandlerReportsHitRatio(t *testing.T) {
	app := &edgeServer{metrics: newEdgeMetrics()}
	app.recordCacheMetric("memory")
	app.recordCacheMetric("redis")
	app.recordCacheMetric("origin")
	app.recordCacheFillLatency(250 * time.Millisecond)
	reqMetric := httptest.NewRequest(http.MethodGet, "/edge/assets/app.js", nil)
	reqMetric.Host = "cdn.example"
	app.recordCacheMetricForRequest("memory", reqMetric, requestRoute{host: "cdn.example", pathPrefix: "/assets", matched: true})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cache/analytics", nil)
	app.cacheAnalyticsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var payload edgeCacheAnalyticsResponse
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Cache.Requests != 4 {
		t.Fatalf("requests = %d, want 4", payload.Cache.Requests)
	}
	if payload.Cache.Hits != 3 || payload.Cache.Misses != 1 {
		t.Fatalf("hits/misses = %d/%d, want 3/1", payload.Cache.Hits, payload.Cache.Misses)
	}
	if payload.Cache.HitRatio != 0.75 {
		t.Fatalf("hit ratio = %f, want 0.75", payload.Cache.HitRatio)
	}
	if got := payload.Cache.ByLayer["memory"].Requests; got != 2 {
		t.Fatalf("memory requests = %d, want 2", got)
	}
	if got := payload.Cache.ByLayer["origin"].Result; got != "miss" {
		t.Fatalf("origin result = %q, want miss", got)
	}
	if got := payload.Cache.ByHost["cdn.example"].Hits; got != 1 {
		t.Fatalf("host hits = %d, want 1", got)
	}
	if got := payload.Cache.ByRoute["cdn.example:/assets"].Hits; got != 1 {
		t.Fatalf("route hits = %d, want 1", got)
	}
	if payload.Cache.Fill.Count != 1 || payload.Cache.Fill.AvgSeconds != 0.25 {
		t.Fatalf("fill latency = %+v, want count=1 avg=0.25", payload.Cache.Fill)
	}
}

func TestCacheAnalyticsHandlerRejectsPost(t *testing.T) {
	app := &edgeServer{metrics: newEdgeMetrics()}
	rec := httptest.NewRecorder()
	app.cacheAnalyticsHandler(rec, httptest.NewRequest(http.MethodPost, "/v1/cache/analytics", nil))

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestEdgeHandlerRejectsInvalidSignedURL(t *testing.T) {
	originBase, err := url.Parse("http://origin.example")
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     http.DefaultClient,
		cache:      newMemoryCache(),
		signer: signedURLValidator{
			enabled: true,
			secret:  "secret",
			now:     func() time.Time { return time.Unix(1000, 0) },
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/assets/app.js?expires=2000&signature=bad", nil)
	rec := httptest.NewRecorder()
	app.edgeHandler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestEdgeHandlerRateLimitsRequests(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		limiter:    newRateLimiter(true, 0.001, 1),
		metrics:    newEdgeMetrics(),
	}

	first := httptest.NewRecorder()
	app.edgeHandler(first, httptest.NewRequest(http.MethodGet, "/edge/assets/app.js", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want %d", first.Code, http.StatusOK)
	}

	second := httptest.NewRecorder()
	app.edgeHandler(second, httptest.NewRequest(http.MethodGet, "/edge/assets/app.js", nil))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want %d", second.Code, http.StatusTooManyRequests)
	}
	_, _, _, rateLimited := app.metricsSnapshot()
	if rateLimited != 1 {
		t.Fatalf("rate limited metric = %d, want 1", rateLimited)
	}
}

func TestRateLimiterSeparatesClientIPs(t *testing.T) {
	limiter := newRateLimiter(true, 0.001, 1)

	first := httptest.NewRequest(http.MethodGet, "/edge/a", nil)
	first.Header.Set("X-Forwarded-For", "203.0.113.10")
	if !limiter.allow(first) {
		t.Fatal("first client should be allowed")
	}
	if limiter.allow(first) {
		t.Fatal("first client should exceed burst")
	}

	second := httptest.NewRequest(http.MethodGet, "/edge/a", nil)
	second.Header.Set("X-Forwarded-For", "203.0.113.11")
	if !limiter.allow(second) {
		t.Fatal("second client should have an independent bucket")
	}
}

func TestValidateSecureConfigRejectsShortSigningSecret(t *testing.T) {
	t.Setenv("ASTRACDN_ENV", "local")
	t.Setenv("EDGE_SIGNING_ENABLED", "true")
	t.Setenv("EDGE_SIGNING_SECRET", "short")

	if err := validateSecureConfig(); err == nil {
		t.Fatal("expected short signing secret to be rejected")
	}
}

func TestValidateSecureConfigRejectsDisabledRateLimitOutsideLocal(t *testing.T) {
	t.Setenv("ASTRACDN_ENV", "production")
	t.Setenv("EDGE_SIGNING_ENABLED", "false")
	t.Setenv("RATE_LIMIT_ENABLED", "false")

	if err := validateSecureConfig(); err == nil {
		t.Fatal("expected disabled production rate limiting to be rejected")
	}
}

func TestSignedURLValidator(t *testing.T) {
	expires := "2000"
	u, err := url.Parse("/edge/assets/app.js?v=1&expires=" + expires)
	if err != nil {
		t.Fatal(err)
	}
	signature := signedURLSignature("secret", u.Path, originRawQuery(u), expires)
	u.RawQuery += "&signature=" + signature

	validator := signedURLValidator{
		enabled: true,
		secret:  "secret",
		now:     func() time.Time { return time.Unix(1000, 0) },
	}
	if !validator.validate(u) {
		t.Fatal("valid signed URL was rejected")
	}

	validator.now = func() time.Time { return time.Unix(3000, 0) }
	if validator.validate(u) {
		t.Fatal("expired signed URL was accepted")
	}

	validator.now = func() time.Time { return time.Unix(1000, 0) }
	badSignature, err := url.Parse("/edge/assets/app.js?v=1&expires=2000&signature=bad")
	if err != nil {
		t.Fatal(err)
	}
	if validator.validate(badSignature) {
		t.Fatal("bad signature was accepted")
	}
}

func TestOriginRawQueryRemovesSigningParams(t *testing.T) {
	u, err := url.Parse("/edge/assets/app.js?signature=sig&b=2&expires=123&a=1")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := originRawQuery(u), "a=1&b=2"; got != want {
		t.Fatalf("originRawQuery = %q, want %q", got, want)
	}
	if got, want := cacheKeyForURL(u), "/edge/assets/app.js?a=1&b=2"; got != want {
		t.Fatalf("cacheKeyForURL = %q, want %q", got, want)
	}
	req := httptest.NewRequest(http.MethodGet, "/edge/assets/app.js?signature=sig&b=2&expires=123&a=1", nil)
	req.Host = "CDN.Example."
	if got, want := cacheKeyForRequest(req), "host:cdn.example:/edge/assets/app.js?a=1&b=2"; got != want {
		t.Fatalf("cacheKeyForRequest = %q, want %q", got, want)
	}
}

func TestRedisCacheEntryRoundTrip(t *testing.T) {
	expiresAt := time.Now().Add(time.Minute).UTC().Truncate(time.Second)
	original := cacheEntry{
		status: http.StatusOK,
		header: http.Header{
			"Content-Type":  []string{"text/plain"},
			"Cache-Control": []string{"public, max-age=60"},
		},
		body:      []byte("cached body"),
		expiresAt: expiresAt,
	}

	payload, err := json.Marshal(toRedisCacheEntry(original))
	if err != nil {
		t.Fatal(err)
	}

	var decoded cacheEntry
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.status != original.status {
		t.Fatalf("status = %d, want %d", decoded.status, original.status)
	}
	if decoded.header.Get("Content-Type") != "text/plain" {
		t.Fatalf("content-type = %q", decoded.header.Get("Content-Type"))
	}
	if string(decoded.body) != string(original.body) {
		t.Fatalf("body = %q, want %q", decoded.body, original.body)
	}
	if !decoded.expiresAt.Equal(original.expiresAt) {
		t.Fatalf("expiresAt = %s, want %s", decoded.expiresAt, original.expiresAt)
	}
}

func TestMemoryCacheInvalidation(t *testing.T) {
	cache := newMemoryCache()
	entry := cacheEntry{
		status:    http.StatusOK,
		header:    http.Header{"Cache-Control": []string{"public, max-age=60"}},
		body:      []byte("cached"),
		expiresAt: time.Now().Add(time.Minute),
	}
	cache.set("/edge/assets/app.js?v=1", entry)
	cache.set("/edge/assets/app.css?v=1", entry)
	cache.set("/edge/images/logo.svg", entry)
	cache.set("host:cdn-a.example:/edge/assets/app.js?v=1", entry)
	cache.set("host:cdn-b.example:/edge/assets/app.css?v=1", entry)
	cache.set("host:cdn-b.example:/edge/images/logo.svg", entry)

	cache.deleteKeys([]string{"/edge/assets/app.js?v=1"})
	if _, ok := cache.get("/edge/assets/app.js?v=1"); ok {
		t.Fatal("exact key was not invalidated")
	}
	if _, ok := cache.get("host:cdn-a.example:/edge/assets/app.js?v=1"); ok {
		t.Fatal("host-isolated exact key was not invalidated by path-only key")
	}
	if _, ok := cache.get("/edge/assets/app.css?v=1"); !ok {
		t.Fatal("unmatched key was invalidated")
	}
	if _, ok := cache.get("host:cdn-b.example:/edge/assets/app.css?v=1"); !ok {
		t.Fatal("unmatched host-isolated key was invalidated")
	}

	cache.deletePrefixes([]string{"/edge/assets/"})
	if _, ok := cache.get("/edge/assets/app.css?v=1"); ok {
		t.Fatal("prefix key was not invalidated")
	}
	if _, ok := cache.get("host:cdn-b.example:/edge/assets/app.css?v=1"); ok {
		t.Fatal("host-isolated prefix key was not invalidated by path-only prefix")
	}
	if _, ok := cache.get("/edge/images/logo.svg"); !ok {
		t.Fatal("non-prefix key was invalidated")
	}
	if _, ok := cache.get("host:cdn-b.example:/edge/images/logo.svg"); !ok {
		t.Fatal("host-isolated non-prefix key was invalidated")
	}
}

func TestMemoryCacheSurrogateKeyInvalidation(t *testing.T) {
	cache := newMemoryCache()
	entry := cacheEntry{
		status:    http.StatusOK,
		header:    http.Header{"Cache-Control": []string{"public, max-age=60"}},
		body:      []byte("cached"),
		expiresAt: time.Now().Add(time.Minute),
	}
	cache.set("host:cdn-a.example:/edge/products/hero", entry)
	cache.rememberSurrogateKeys("host:cdn-a.example:/edge/products/hero", []string{"product:hero", "release-2026"})
	cache.set("host:cdn-b.example:/edge/products/hero", entry)
	cache.rememberSurrogateKeys("host:cdn-b.example:/edge/products/hero", []string{"product:hero"})
	cache.set("host:cdn-a.example:/edge/products/footer", entry)
	cache.rememberSurrogateKeys("host:cdn-a.example:/edge/products/footer", []string{"product:footer"})

	cache.deleteTags([]string{"product:hero"}, "cdn-a.example")
	if _, ok := cache.get("host:cdn-a.example:/edge/products/hero"); ok {
		t.Fatal("host A surrogate-tagged key was not invalidated")
	}
	if _, ok := cache.get("host:cdn-b.example:/edge/products/hero"); !ok {
		t.Fatal("host B surrogate-tagged key was invalidated by host A purge")
	}
	if _, ok := cache.get("host:cdn-a.example:/edge/products/footer"); !ok {
		t.Fatal("unmatched surrogate tag was invalidated")
	}

	cache.deleteTags([]string{"product:hero"}, "")
	if _, ok := cache.get("host:cdn-b.example:/edge/products/hero"); ok {
		t.Fatal("global surrogate-tagged key was not invalidated")
	}
}

func TestStoreCacheEntryIndexesSurrogateKeyHeader(t *testing.T) {
	app := &edgeServer{
		cache: newMemoryCache(),
		redis: &redisCache{},
	}
	req := httptest.NewRequest(http.MethodGet, "/edge/products/hero", nil)
	entry := cacheEntry{
		status: http.StatusOK,
		header: http.Header{
			"Cache-Control": []string{"public, max-age=60"},
			"Surrogate-Key": []string{"product:hero release-2026, ignored space"},
		},
		body:      []byte("cached"),
		expiresAt: time.Now().Add(time.Minute),
	}

	key := app.storeCacheEntry(context.Background(), "host:cdn-a.example:/edge/products/hero", req, entry, time.Minute)
	if key != "host:cdn-a.example:/edge/products/hero" {
		t.Fatalf("stored key = %q", key)
	}
	if _, ok := app.cache.get(key); !ok {
		t.Fatal("cache entry was not stored")
	}
	app.cache.deleteTags([]string{"release-2026"}, "cdn-a.example")
	if _, ok := app.cache.get(key); ok {
		t.Fatal("surrogate-tagged stored entry was not invalidated")
	}
}

func TestInvalidateCacheWithHostOnlyPurgesThatHost(t *testing.T) {
	app := &edgeServer{
		cache: newMemoryCache(),
		redis: &redisCache{},
	}
	entry := cacheEntry{
		status:    http.StatusOK,
		header:    http.Header{"Cache-Control": []string{"public, max-age=60"}},
		body:      []byte("cached"),
		expiresAt: time.Now().Add(time.Minute),
	}
	app.cache.set("host:cdn-a.example:/edge/assets/app.js?v=1", entry)
	app.cache.set("host:cdn-b.example:/edge/assets/app.js?v=1", entry)

	err := app.invalidateCache(context.Background(), cacheInvalidationEvent{
		Host:   "CDN-A.Example.",
		Mode:   "keys",
		Values: []string{"/edge/assets/app.js?v=1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := app.cache.get("host:cdn-a.example:/edge/assets/app.js?v=1"); ok {
		t.Fatal("host A key was not invalidated")
	}
	if _, ok := app.cache.get("host:cdn-b.example:/edge/assets/app.js?v=1"); !ok {
		t.Fatal("host B key was invalidated by host A purge")
	}
}

func TestInvalidateCacheWithHostPrefixOnlyPurgesThatHost(t *testing.T) {
	app := &edgeServer{
		cache: newMemoryCache(),
		redis: &redisCache{},
	}
	entry := cacheEntry{
		status:    http.StatusOK,
		header:    http.Header{"Cache-Control": []string{"public, max-age=60"}},
		body:      []byte("cached"),
		expiresAt: time.Now().Add(time.Minute),
	}
	app.cache.set("host:cdn-a.example:/edge/assets/app.js", entry)
	app.cache.set("host:cdn-a.example:/edge/images/logo.svg", entry)
	app.cache.set("host:cdn-b.example:/edge/assets/app.js", entry)

	err := app.invalidateCache(context.Background(), cacheInvalidationEvent{
		Host:   "cdn-a.example",
		Mode:   "prefixes",
		Values: []string{"/edge/assets/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := app.cache.get("host:cdn-a.example:/edge/assets/app.js"); ok {
		t.Fatal("host A prefix key was not invalidated")
	}
	if _, ok := app.cache.get("host:cdn-a.example:/edge/images/logo.svg"); !ok {
		t.Fatal("host A non-prefix key was invalidated")
	}
	if _, ok := app.cache.get("host:cdn-b.example:/edge/assets/app.js"); !ok {
		t.Fatal("host B prefix key was invalidated by host A purge")
	}
}

func TestInvalidateCacheBySurrogateTag(t *testing.T) {
	app := &edgeServer{
		cache: newMemoryCache(),
		redis: &redisCache{},
	}
	entry := cacheEntry{
		status:    http.StatusOK,
		header:    http.Header{"Cache-Control": []string{"public, max-age=60"}},
		body:      []byte("cached"),
		expiresAt: time.Now().Add(time.Minute),
	}
	app.cache.set("host:cdn-a.example:/edge/products/hero", entry)
	app.cache.rememberSurrogateKeys("host:cdn-a.example:/edge/products/hero", []string{"product:hero"})
	app.cache.set("host:cdn-b.example:/edge/products/hero", entry)
	app.cache.rememberSurrogateKeys("host:cdn-b.example:/edge/products/hero", []string{"product:hero"})

	err := app.invalidateCache(context.Background(), cacheInvalidationEvent{
		Host:   "cdn-a.example",
		Mode:   "tags",
		Values: []string{"product:hero"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := app.cache.get("host:cdn-a.example:/edge/products/hero"); ok {
		t.Fatal("host A surrogate-tagged key was not invalidated")
	}
	if _, ok := app.cache.get("host:cdn-b.example:/edge/products/hero"); !ok {
		t.Fatal("host B surrogate-tagged key was invalidated by host A purge")
	}
}

func TestAcknowledgeCacheInvalidationPostsDelivery(t *testing.T) {
	var got cacheInvalidationDeliveryRequest
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/cache/invalidation-deliveries" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if gotAuth := r.Header.Get("Authorization"); gotAuth != "Bearer secret" {
			t.Fatalf("authorization = %q", gotAuth)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
	}))
	defer control.Close()

	app := &edgeServer{
		controlBaseURL: control.URL,
		controlAPIKey:  "secret",
		nodeID:         "edge-1",
		client:         control.Client(),
	}
	app.acknowledgeCacheInvalidation(context.Background(), cacheInvalidationEvent{ID: 42}, "applied", "")

	if got.InvalidationID != 42 || got.NodeID != "edge-1" || got.Status != "applied" {
		t.Fatalf("unexpected ack payload: %+v", got)
	}
}

func TestAcknowledgeCacheInvalidationRetriesTransientFailure(t *testing.T) {
	var attempts int
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			http.Error(w, "temporary failure", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
	}))
	defer control.Close()

	app := &edgeServer{
		controlBaseURL: control.URL,
		controlAPIKey:  "secret",
		nodeID:         "edge-1",
		ackAttempts:    2,
		ackBackoff:     time.Millisecond,
		client:         control.Client(),
	}
	app.acknowledgeCacheInvalidation(context.Background(), cacheInvalidationEvent{ID: 42}, "applied", "")

	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestPushCacheAnalyticsSnapshotPostsToControl(t *testing.T) {
	var got cacheAnalyticsSnapshotRequest
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/analytics/cache-snapshots" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if gotAuth := r.Header.Get("Authorization"); gotAuth != "Bearer secret" {
			t.Fatalf("authorization = %q", gotAuth)
		}
		if gotContentType := r.Header.Get("Content-Type"); gotContentType != "application/json" {
			t.Fatalf("content-type = %q", gotContentType)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
	}))
	defer control.Close()

	app := &edgeServer{
		controlBaseURL: control.URL,
		controlAPIKey:  "secret",
		nodeID:         "edge-1",
		client:         control.Client(),
		metrics:        newEdgeMetrics(),
	}
	app.recordCacheMetric("memory")
	app.recordCacheMetric("origin")
	app.recordCacheFillLatency(300 * time.Millisecond)
	reqMetric := httptest.NewRequest(http.MethodGet, "/edge/assets/app.js", nil)
	reqMetric.Host = "cdn.example"
	app.recordCacheMetricForRequest("memory", reqMetric, requestRoute{host: "cdn.example", pathPrefix: "/assets", matched: true})

	if err := app.pushCacheAnalyticsSnapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got.EdgeNodeID != "edge-1" {
		t.Fatalf("edge node id = %q", got.EdgeNodeID)
	}
	if got.Cache.Requests != 3 || got.Cache.Hits != 2 || got.Cache.Misses != 1 || got.Cache.HitRatio < 0.66 || got.Cache.HitRatio > 0.67 {
		t.Fatalf("unexpected cache analytics payload: %+v", got.Cache)
	}
	if got.Cache.ByHost["cdn.example"].Hits != 1 {
		t.Fatalf("host analytics missing: %+v", got.Cache.ByHost)
	}
	if got.Cache.ByRoute["cdn.example:/assets"].Hits != 1 {
		t.Fatalf("route analytics missing: %+v", got.Cache.ByRoute)
	}
	if got.Cache.Fill.Count != 1 || got.Cache.Fill.AvgSeconds != 0.3 {
		t.Fatalf("fill latency missing: %+v", got.Cache.Fill)
	}
	if got.ObservedAt.IsZero() {
		t.Fatal("observed_at was not set")
	}
}

func TestPushEdgeHealthRegistersNode(t *testing.T) {
	var got edgeRegistrationRequest
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/edge/register" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if gotAuth := r.Header.Get("Authorization"); gotAuth != "Bearer secret" {
			t.Fatalf("authorization = %q", gotAuth)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
	}))
	defer control.Close()

	app := &edgeServer{
		controlBaseURL: control.URL,
		controlAPIKey:  "secret",
		nodeID:         "edge-1",
		publicURL:      "http://edge-1:8080",
		client:         control.Client(),
	}
	if err := app.pushEdgeHealth(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got.NodeID != "edge-1" || got.Address != "http://edge-1:8080" || len(got.Capabilities) != 3 {
		t.Fatalf("unexpected registration: %+v", got)
	}
}

func TestPushCacheAnalyticsSnapshotReturnsControlError(t *testing.T) {
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer control.Close()

	app := &edgeServer{
		controlBaseURL: control.URL,
		nodeID:         "edge-1",
		client:         control.Client(),
		metrics:        newEdgeMetrics(),
	}
	if err := app.pushCacheAnalyticsSnapshot(context.Background()); err == nil {
		t.Fatal("expected control error")
	}
}

func TestRedisKeyNaming(t *testing.T) {
	if got, want := redisKey("/edge/assets/app.js?v=1"), "astracdn:edge-cache:/edge/assets/app.js?v=1"; got != want {
		t.Fatalf("redisKey = %q, want %q", got, want)
	}
	if got, want := redisScanPattern("/edge/assets/"), "astracdn:edge-cache:/edge/assets/*"; got != want {
		t.Fatalf("redisScanPattern = %q, want %q", got, want)
	}
	if got, want := redisKey("host:cdn.example:/edge/assets/app.js?v=1"), "astracdn:edge-cache:host:cdn.example:/edge/assets/app.js?v=1"; got != want {
		t.Fatalf("host redisKey = %q, want %q", got, want)
	}
	if got, want := redisHostScanPattern("/edge/assets/"), "astracdn:edge-cache:host:*:/edge/assets/*"; got != want {
		t.Fatalf("redisHostScanPattern = %q, want %q", got, want)
	}
}

func TestInvalidateCacheRejectsUnknownMode(t *testing.T) {
	app := &edgeServer{
		cache:   newMemoryCache(),
		metrics: newEdgeMetrics(),
	}

	err := app.invalidateCache(context.TODO(), cacheInvalidationEvent{Mode: "everything"})
	if err == nil {
		t.Fatal("expected unknown mode error")
	}
	app.recordInvalidationFailure()
	_, failures := app.invalidationMetricsSnapshot()
	if failures != 1 {
		t.Fatalf("invalidation failures = %d, want 1", failures)
	}
}

func TestCacheTTL(t *testing.T) {
	tests := []struct {
		name         string
		cacheControl string
		wantTTL      time.Duration
	}{
		{name: "max age", cacheControl: "public, max-age=30", wantTTL: 30 * time.Second},
		{name: "s-maxage wins over max age", cacheControl: "public, max-age=0, s-maxage=60", wantTTL: time.Minute},
		{name: "no store", cacheControl: "no-store, s-maxage=60, max-age=30", wantTTL: 0},
		{name: "private", cacheControl: "private, s-maxage=60", wantTTL: 0},
		{name: "missing", cacheControl: "", wantTTL: 0},
		{name: "zero", cacheControl: "max-age=0", wantTTL: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cacheTTL(tt.cacheControl)
			if got != tt.wantTTL {
				t.Fatalf("cacheTTL(%q) = %s, want %s", tt.cacheControl, got, tt.wantTTL)
			}
		})
	}
}

func BenchmarkEdgeHandlerMemoryCacheHit(b *testing.B) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = w.Write([]byte("benchmark cached body"))
	}))
	defer origin.Close()

	originBase, err := url.Parse(origin.URL)
	if err != nil {
		b.Fatal(err)
	}
	app := &edgeServer{
		originBase: originBase,
		client:     origin.Client(),
		cache:      newMemoryCache(),
		metrics:    newEdgeMetrics(),
	}

	req := httptest.NewRequest(http.MethodGet, "/edge/bench.txt", nil)
	warm := httptest.NewRecorder()
	app.edgeHandler(warm, req)
	if warm.Code != http.StatusOK {
		b.Fatalf("warm status = %d", warm.Code)
	}
	if got := warm.Header().Get("X-AstraCDN-Cache"); got != "MISS" {
		b.Fatalf("warm cache = %q, want MISS", got)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		app.edgeHandler(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("status = %d", rec.Code)
		}
		if got := rec.Header().Get("X-AstraCDN-Cache"); got != "HIT" {
			b.Fatalf("cache = %q, want HIT", got)
		}
	}
}
