package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	port := env("ORIGIN_PORT", "9000")
	assetStorage := newAssetStorageFromEnv()

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           newOriginHandlerWithStorage(assetStorage),
		ReadHeaderTimeout: envDuration("HTTP_READ_HEADER_TIMEOUT", 5*time.Second),
		ReadTimeout:       envDuration("HTTP_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:      envDuration("HTTP_WRITE_TIMEOUT", 30*time.Second),
		IdleTimeout:       envDuration("HTTP_IDLE_TIMEOUT", 60*time.Second),
	}

	log.Printf("example origin listening on :%s asset_storage=%s", port, assetStorage.Description())
	if err := listenAndShutdown(server, envDuration("HTTP_SHUTDOWN_TIMEOUT", 10*time.Second)); err != nil {
		log.Fatal(err)
	}
}

func newOriginHandler(assetDir string) http.Handler {
	return newOriginHandlerWithStorage(localAssetStorage{dir: assetDir})
}

func newOriginHandlerWithStorage(assetStorage assetStorage) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			serveAsset(w, r, assetStorage)
			return
		}
		if r.URL.Path == "/large-object-smoke" {
			const size = 8192
			w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", envInt("ORIGIN_CACHE_MAX_AGE", 60)))
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(size))
			_, _ = io.CopyN(w, strings.NewReader(strings.Repeat("x", size)), size)
			return
		}
		if r.URL.Path == "/image-smoke.png" {
			img := image.NewRGBA(image.Rect(0, 0, 4, 2))
			for y := 0; y < 2; y++ {
				for x := 0; x < 4; x++ {
					img.Set(x, y, color.RGBA{R: uint8(40 + x*40), G: uint8(80 + y*80), B: 160, A: 255})
				}
			}
			w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", envInt("ORIGIN_CACHE_MAX_AGE", 60)))
			w.Header().Set("Content-Type", "image/png")
			_ = png.Encode(w, img)
			return
		}
		if r.URL.Path == "/surrogate-smoke" {
			w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", envInt("ORIGIN_CACHE_MAX_AGE", 60)))
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Surrogate-Key", "smoke-tag release-2026")
			fmt.Fprintln(w, "surrogate tagged smoke response")
			return
		}

		etag := fmt.Sprintf(`"astra-origin-%x"`, r.URL.RequestURI())
		lastModified := env("ORIGIN_LAST_MODIFIED", "Sun, 24 May 2026 09:00:00 GMT")

		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", envInt("ORIGIN_CACHE_MAX_AGE", 60)))
		w.Header().Set("ETag", etag)
		w.Header().Set("Last-Modified", lastModified)
		if r.Header.Get("If-None-Match") == etag || r.Header.Get("If-Modified-Since") == lastModified {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "origin response path=%s query=%s\n", r.URL.Path, r.URL.RawQuery)
	})
	return mux
}

type assetStorage interface {
	ServeAsset(w http.ResponseWriter, r *http.Request, rel string)
	Description() string
}

type localAssetStorage struct {
	dir string
}

func newAssetStorageFromEnv() assetStorage {
	mode := strings.ToLower(strings.TrimSpace(env("ORIGIN_STORAGE_MODE", "local")))
	if mode == "s3" {
		return s3AssetStorage{
			endpoint:        strings.TrimRight(env("ORIGIN_S3_ENDPOINT", ""), "/"),
			bucket:          env("ORIGIN_S3_BUCKET", ""),
			region:          env("ORIGIN_S3_REGION", "us-east-1"),
			accessKeyID:     env("ORIGIN_S3_ACCESS_KEY_ID", ""),
			secretAccessKey: env("ORIGIN_S3_SECRET_ACCESS_KEY", ""),
			sessionToken:    env("ORIGIN_S3_SESSION_TOKEN", ""),
			prefix:          strings.Trim(strings.TrimSpace(env("ORIGIN_S3_PREFIX", "")), "/"),
			forcePathStyle:  envBool("ORIGIN_S3_FORCE_PATH_STYLE", true),
			client: &http.Client{
				Timeout: envDuration("ORIGIN_S3_TIMEOUT", 30*time.Second),
			},
		}
	}
	return localAssetStorage{dir: env("ORIGIN_ASSET_DIR", "/var/lib/astra-cdn/origin")}
}

func serveAsset(w http.ResponseWriter, r *http.Request, storage assetStorage) {
	if storage == nil {
		http.NotFound(w, r)
		return
	}

	rel := strings.TrimPrefix(r.URL.Path, "/assets/")
	rel = filepath.Clean("/" + rel)
	if rel == "/" || strings.HasPrefix(rel, "/..") {
		http.NotFound(w, r)
		return
	}
	storage.ServeAsset(w, r, strings.TrimPrefix(rel, "/"))
}

func (s localAssetStorage) Description() string {
	if s.dir == "" {
		return "local:disabled"
	}
	return "local:" + s.dir
}

func (s localAssetStorage) ServeAsset(w http.ResponseWriter, r *http.Request, rel string) {
	if s.dir == "" {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(s.dir, filepath.FromSlash(rel))
	file, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", envInt("ORIGIN_CACHE_MAX_AGE", 60)))
	if tags := assetSurrogateKeys("/" + rel); tags != "" {
		w.Header().Set("Surrogate-Key", tags)
	}
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}

type s3AssetStorage struct {
	endpoint        string
	bucket          string
	region          string
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	prefix          string
	forcePathStyle  bool
	client          *http.Client
}

func (s s3AssetStorage) Description() string {
	if s.endpoint == "" || s.bucket == "" {
		return "s3:disabled"
	}
	return "s3:" + s.bucket
}

func (s s3AssetStorage) ServeAsset(w http.ResponseWriter, r *http.Request, rel string) {
	if s.endpoint == "" || s.bucket == "" {
		http.NotFound(w, r)
		return
	}
	method := r.Method
	if method != http.MethodHead {
		method = http.MethodGet
	}
	target, err := s.objectURL(rel)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), method, target, nil)
	if err != nil {
		http.Error(w, "failed to build object request", http.StatusInternalServerError)
		return
	}
	copyObjectRequestHeaders(req.Header, r.Header)
	if s.accessKeyID != "" && s.secretAccessKey != "" {
		s.sign(req, time.Now().UTC())
	}

	client := s.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("s3 asset fetch failed bucket=%s key=%s err=%v", s.bucket, s.objectKey(rel), err)
		http.Error(w, "object storage unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
		http.NotFound(w, r)
		return
	}
	if resp.StatusCode >= 500 {
		http.Error(w, "object storage unavailable", http.StatusBadGateway)
		return
	}

	copyObjectResponseHeaders(w.Header(), resp.Header)
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", envInt("ORIGIN_CACHE_MAX_AGE", 60)))
	}
	if tags := assetSurrogateKeys("/" + rel); tags != "" {
		w.Header().Set("Surrogate-Key", tags)
	}
	w.WriteHeader(resp.StatusCode)
	if r.Method != http.MethodHead {
		_, _ = io.Copy(w, resp.Body)
	}
}

func (s s3AssetStorage) objectURL(rel string) (string, error) {
	base, err := http.NewRequest(http.MethodGet, s.endpoint, nil)
	if err != nil {
		return "", err
	}
	u := *base.URL
	key := s.objectKey(rel)
	if s.forcePathStyle {
		u.Path = joinURLPath(joinURLPath(u.Path, s.bucket), key)
		return u.String(), nil
	}
	u.Host = s.bucket + "." + u.Host
	u.Path = joinURLPath(u.Path, key)
	return u.String(), nil
}

func (s s3AssetStorage) objectKey(rel string) string {
	rel = strings.Trim(strings.ReplaceAll(rel, "\\", "/"), "/")
	if s.prefix == "" {
		return rel
	}
	return s.prefix + "/" + rel
}

func (s s3AssetStorage) sign(req *http.Request, now time.Time) {
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	payloadHash := "UNSIGNED-PAYLOAD"
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if s.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", s.sessionToken)
	}

	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if s.sessionToken != "" {
		signedHeaders = append(signedHeaders, "x-amz-security-token")
	}
	canonicalHeaders := "host:" + req.URL.Host + "\n" +
		"x-amz-content-sha256:" + payloadHash + "\n" +
		"x-amz-date:" + amzDate + "\n"
	if s.sessionToken != "" {
		canonicalHeaders += "x-amz-security-token:" + strings.TrimSpace(s.sessionToken) + "\n"
	}
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL.EscapedPath()),
		req.URL.RawQuery,
		canonicalHeaders,
		strings.Join(signedHeaders, ";"),
		payloadHash,
	}, "\n")
	scope := dateStamp + "/" + s.region + "/s3/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex(canonicalRequest),
	}, "\n")
	signature := hex.EncodeToString(hmacSHA256(signingKey(s.secretAccessKey, dateStamp, s.region), stringToSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.accessKeyID+"/"+scope+", SignedHeaders="+strings.Join(signedHeaders, ";")+", Signature="+signature)
}

func copyObjectRequestHeaders(dst, src http.Header) {
	for _, key := range []string{"Range", "If-None-Match", "If-Modified-Since"} {
		if value := src.Get(key); value != "" {
			dst.Set(key, value)
		}
	}
}

func copyObjectResponseHeaders(dst, src http.Header) {
	for _, key := range []string{
		"Accept-Ranges",
		"Cache-Control",
		"Content-Disposition",
		"Content-Encoding",
		"Content-Language",
		"Content-Length",
		"Content-Range",
		"Content-Type",
		"ETag",
		"Last-Modified",
	} {
		if value := src.Get(key); value != "" {
			dst.Set(key, value)
		}
	}
}

func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func signingKey(secret, dateStamp, region string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, "s3")
	return hmacSHA256(kService, "aws4_request")
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func joinURLPath(base, add string) string {
	base = strings.TrimRight(base, "/")
	add = strings.TrimLeft(add, "/")
	if base == "" {
		return "/" + add
	}
	if add == "" {
		return base
	}
	return base + "/" + add
}

func assetSurrogateKeys(rel string) string {
	rel = strings.Trim(strings.TrimPrefix(rel, "/"), "/")
	if rel == "" {
		return ""
	}
	parts := strings.Split(rel, "/")
	tags := []string{"asset"}
	if len(parts) > 1 {
		tags = append(tags, "asset:"+safeSurrogateToken(parts[0]))
	}
	tags = append(tags, "asset:"+safeSurrogateToken(strings.TrimSuffix(filepath.Base(rel), filepath.Ext(rel))))
	return strings.Join(tags, " ")
}

func safeSurrogateToken(value string) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == ':' || r == '-' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "unknown"
	}
	return out
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

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
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
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
