package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:embed static/*
var staticFiles embed.FS

type dashboardServer struct {
	client           *http.Client
	apiKey           string
	accessToken      string
	controlBaseURL   *url.URL
	edgeBaseURL      *url.URL
	inferenceBaseURL *url.URL
	publicCDNBaseURL *url.URL
	assetDir         string
	assetStore       dashboardAssetStore
	maxUploadBytes   int64
}

func main() {
	port := env("DASHBOARD_PORT", "3000")
	app := newDashboardServer()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/cdn/fetch", app.requireDashboardAuth(app.cdnFetchHandler))
	mux.HandleFunc("/api/assets", app.requireDashboardAuth(app.assetHandler))
	mux.HandleFunc("/api/assets/purge", app.requireDashboardAuth(app.assetPurgeHandler))
	mux.HandleFunc("/api/assets/storage", app.requireDashboardAuth(app.assetStorageHandler))
	mux.HandleFunc("/api/assets/upload", app.requireDashboardAuth(app.assetUploadHandler))
	mux.HandleFunc("/api/control/", app.requireDashboardAuth(app.proxyHandler("control", app.controlBaseURL, "/api/control")))
	mux.HandleFunc("/api/edge/", app.requireDashboardAuth(app.proxyHandler("edge", app.edgeBaseURL, "/api/edge")))
	mux.HandleFunc("/api/inference/", app.requireDashboardAuth(app.proxyHandler("inference", app.inferenceBaseURL, "/api/inference")))
	mux.Handle("/", staticHandler())

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: envDuration("HTTP_READ_HEADER_TIMEOUT", 5*time.Second),
		ReadTimeout:       envDuration("HTTP_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:      envDuration("HTTP_WRITE_TIMEOUT", 30*time.Second),
		IdleTimeout:       envDuration("HTTP_IDLE_TIMEOUT", 60*time.Second),
	}

	log.Printf("dashboard listening on :%s", port)
	if err := listenAndShutdown(server, envDuration("HTTP_SHUTDOWN_TIMEOUT", 10*time.Second)); err != nil {
		log.Fatal(err)
	}
}

func newDashboardServer() *dashboardServer {
	apiKey := env("ASTRACDN_API_KEY", "astracdn-local-dev-key")
	return &dashboardServer{
		client: &http.Client{
			Timeout: envDuration("DASHBOARD_PROXY_TIMEOUT", 10*time.Second),
		},
		apiKey:           apiKey,
		accessToken:      env("DASHBOARD_ACCESS_TOKEN", apiKey),
		controlBaseURL:   mustParseBaseURL(env("DASHBOARD_CONTROL_BASE_URL", "http://localhost:8081")),
		edgeBaseURL:      mustParseBaseURL(env("DASHBOARD_EDGE_BASE_URL", "http://localhost:8080")),
		inferenceBaseURL: mustParseBaseURL(env("DASHBOARD_INFERENCE_BASE_URL", "http://localhost:8082")),
		publicCDNBaseURL: mustParseBaseURL(env("DASHBOARD_PUBLIC_CDN_BASE_URL", "http://cdn.localhost:8080")),
		assetDir:         env("DASHBOARD_ASSET_DIR", "data/origin"),
		assetStore:       newDashboardAssetStoreFromEnv(),
		maxUploadBytes:   envInt64("DASHBOARD_MAX_UPLOAD_BYTES", 100*1024*1024),
	}
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, `{"status":"ok","service":"dashboard"}`)
}

func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			index, err := fs.ReadFile(sub, "index.html")
			if err != nil {
				http.Error(w, "dashboard index missing", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(index)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

func (s *dashboardServer) requireDashboardAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, `{"error":"dashboard token required"}`)
			return
		}
		next(w, r)
	}
}

func (s *dashboardServer) authorized(r *http.Request) bool {
	if s == nil || s.accessToken == "" {
		return true
	}
	token := strings.TrimSpace(r.Header.Get("X-AstraCDN-Dashboard-Token"))
	if token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.accessToken)) == 1
}

func (s *dashboardServer) proxyHandler(service string, targetBase *url.URL, prefix string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if targetBase == nil {
			http.Error(w, service+" upstream is not configured", http.StatusBadGateway)
			return
		}

		target := *targetBase
		target.Path = joinURLPath(targetBase.Path, strings.TrimPrefix(r.URL.Path, prefix))
		target.RawQuery = r.URL.RawQuery

		req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
		if err != nil {
			http.Error(w, "failed to build upstream request", http.StatusInternalServerError)
			return
		}
		copyProxyHeaders(req.Header, r.Header)
		req.Header.Del("X-AstraCDN-Dashboard-Token")
		if s.apiKey != "" && req.Header.Get("Authorization") == "" && req.Header.Get("X-AstraCDN-API-Key") == "" {
			req.Header.Set("Authorization", "Bearer "+s.apiKey)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			log.Printf("dashboard proxy failed service=%s url=%s err=%v", service, target.String(), err)
			http.Error(w, service+" upstream unavailable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		copyProxyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
}

func (s *dashboardServer) cdnFetchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.edgeBaseURL == nil {
		http.Error(w, "edge upstream is not configured", http.StatusBadGateway)
		return
	}

	host := strings.TrimSpace(r.URL.Query().Get("host"))
	path := strings.TrimSpace(r.URL.Query().Get("path"))
	if host == "" || !validCDNFetchHost(host) || !strings.HasPrefix(path, "/edge/") {
		http.Error(w, "host and /edge/ path are required", http.StatusBadRequest)
		return
	}

	target := *s.edgeBaseURL
	target.Path = joinURLPath(s.edgeBaseURL.Path, path)
	target.RawQuery = r.URL.Query().Get("query")

	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), nil)
	if err != nil {
		http.Error(w, "failed to build edge request", http.StatusInternalServerError)
		return
	}
	req.Host = host
	req.Header.Set("Accept", "*/*")

	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("dashboard CDN fetch failed url=%s host=%s err=%v", target.String(), host, err)
		http.Error(w, "edge upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	preview := ""
	if r.Method != http.MethodHead {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			http.Error(w, "failed to read edge response", http.StatusBadGateway)
			return
		}
		preview = string(body)
	}

	writeJSONValue(w, http.StatusOK, map[string]any{
		"host":         host,
		"path":         path,
		"status":       resp.StatusCode,
		"cache":        resp.Header.Get("X-AstraCDN-Cache"),
		"cache_layer":  resp.Header.Get("X-AstraCDN-Cache-Layer"),
		"content_type": resp.Header.Get("Content-Type"),
		"body_preview": preview,
		"headers": map[string]string{
			"cache_control": resp.Header.Get("Cache-Control"),
			"etag":          resp.Header.Get("Etag"),
			"last_modified": resp.Header.Get("Last-Modified"),
			"surrogate_key": resp.Header.Get("Surrogate-Key"),
		},
	})
}

func (s *dashboardServer) assetUploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	store := s.assetStorage()
	maxBytes := s.maxUploadBytes
	if maxBytes <= 0 {
		maxBytes = 100 * 1024 * 1024
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBytes+1024*1024)
	if err := r.ParseMultipartForm(maxBytes + 1024); err != nil {
		http.Error(w, "invalid multipart upload or upload too large", http.StatusBadRequest)
		return
	}

	folder, err := safeAssetFolder(r.FormValue("folder"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename, err := safeAssetFilename(header.Filename)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	assetPath := "/assets/" + path.Join(folder, filename)
	edgePath := "/edge" + assetPath
	written, err := store.Save(r.Context(), strings.TrimPrefix(assetPath, "/assets/"), file, maxBytes, contentTypeForAsset(assetPath))
	if err != nil {
		writeAssetStoreError(w, "failed to save upload", err)
		return
	}
	purgeStatus := "skipped"
	purgeEnabled := strings.ToLower(strings.TrimSpace(firstNonEmpty(r.FormValue("purge"), r.URL.Query().Get("purge")))) != "false"
	if purgeEnabled && s.controlBaseURL != nil {
		if err := s.purgeAsset(r.Context(), firstNonEmpty(r.FormValue("host"), r.URL.Query().Get("host")), edgePath); err != nil {
			purgeStatus = "failed"
			writeJSONValue(w, http.StatusCreated, map[string]any{
				"status":       "uploaded",
				"filename":     filename,
				"asset_path":   assetPath,
				"edge_path":    edgePath,
				"public_url":   s.publicAssetURL(edgePath),
				"bytes":        written,
				"purge_status": purgeStatus,
				"purge_error":  err.Error(),
			})
			return
		}
		purgeStatus = "accepted"
	}

	writeJSONValue(w, http.StatusCreated, map[string]any{
		"status":       "uploaded",
		"filename":     filename,
		"asset_path":   assetPath,
		"edge_path":    edgePath,
		"public_url":   s.publicAssetURL(edgePath),
		"bytes":        written,
		"purge_status": purgeStatus,
	})
}

type assetListItem struct {
	Name        string `json:"name"`
	Folder      string `json:"folder"`
	AssetPath   string `json:"asset_path"`
	EdgePath    string `json:"edge_path"`
	PublicURL   string `json:"public_url"`
	Bytes       int64  `json:"bytes"`
	ModifiedAt  string `json:"modified_at"`
	ContentType string `json:"content_type,omitempty"`
}

func (s *dashboardServer) assetHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.assetListHandler(w, r)
	case http.MethodDelete:
		s.assetDeleteHandler(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *dashboardServer) assetStorageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSONValue(w, http.StatusOK, s.assetStorageStatus())
}

func (s *dashboardServer) assetStorageStatus() map[string]any {
	status := map[string]any{
		"mode":                "local",
		"backend":             "local",
		"configured":          true,
		"max_upload_bytes":    s.maxUploadBytes,
		"public_cdn_base_url": "",
	}
	if s != nil && s.publicCDNBaseURL != nil {
		status["public_cdn_base_url"] = s.publicCDNBaseURL.String()
	}
	switch store := s.assetStorage().(type) {
	case localDashboardAssetStore:
		status["mode"] = "local"
		status["backend"] = "local"
		status["asset_dir"] = store.dir
		status["configured"] = store.dir != ""
	case s3DashboardAssetStore:
		status["mode"] = "s3"
		status["backend"] = "s3"
		status["endpoint"] = store.endpoint
		status["bucket"] = store.bucket
		status["region"] = firstNonEmpty(store.region, "us-east-1")
		status["prefix"] = store.prefix
		status["force_path_style"] = store.forcePathStyle
		status["configured"] = store.endpoint != "" && store.bucket != ""
	}
	return status
}

func (s *dashboardServer) assetListHandler(w http.ResponseWriter, r *http.Request) {
	folder, err := safeAssetListFolder(r.URL.Query().Get("folder"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	limit := parsePositiveInt(r.URL.Query().Get("limit"), 200)
	if limit > 1000 {
		limit = 1000
	}

	objects, err := s.assetStorage().List(r.Context(), folder, limit)
	if err != nil {
		writeAssetStoreError(w, "failed to list assets", err)
		return
	}
	items := make([]assetListItem, 0, len(objects))
	for _, object := range objects {
		rel := strings.Trim(strings.ReplaceAll(object.Rel, "\\", "/"), "/")
		if rel == "" || strings.HasPrefix(path.Base(rel), ".") {
			continue
		}
		assetPath := "/assets/" + rel
		edgePath := "/edge" + assetPath
		folderName := path.Dir(rel)
		if folderName == "." {
			folderName = ""
		}
		modifiedAt := ""
		if !object.ModifiedAt.IsZero() {
			modifiedAt = object.ModifiedAt.UTC().Format(time.RFC3339)
		}
		contentType := object.ContentType
		if contentType == "" {
			contentType = contentTypeForAsset(rel)
		}
		items = append(items, assetListItem{
			Name:        path.Base(rel),
			Folder:      folderName,
			AssetPath:   assetPath,
			EdgePath:    edgePath,
			PublicURL:   s.publicAssetURL(edgePath),
			Bytes:       object.Size,
			ModifiedAt:  modifiedAt,
			ContentType: contentType,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].ModifiedAt == items[j].ModifiedAt {
			return items[i].AssetPath < items[j].AssetPath
		}
		return items[i].ModifiedAt > items[j].ModifiedAt
	})
	if len(items) > limit {
		items = items[:limit]
	}

	writeJSONValue(w, http.StatusOK, map[string]any{
		"assets": items,
		"count":  len(items),
		"folder": folder,
	})
}

func (s *dashboardServer) assetDeleteHandler(w http.ResponseWriter, r *http.Request) {
	rel, assetPath, edgePath, err := safeAssetDeletePath(r.URL.Query().Get("asset_path"), r.URL.Query().Get("edge_path"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.assetStorage().Delete(r.Context(), rel); err != nil {
		writeAssetStoreError(w, "failed to delete asset", err)
		return
	}

	purgeStatus := "skipped"
	purgeEnabled := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("purge"))) != "false"
	if purgeEnabled {
		if err := s.purgeAsset(r.Context(), strings.TrimSpace(r.URL.Query().Get("host")), edgePath); err != nil {
			purgeStatus = "failed"
			writeJSONValue(w, http.StatusAccepted, map[string]any{
				"status":       "deleted",
				"asset_path":   assetPath,
				"edge_path":    edgePath,
				"public_url":   s.publicAssetURL(edgePath),
				"purge_status": purgeStatus,
				"purge_error":  err.Error(),
			})
			return
		}
		purgeStatus = "accepted"
	}

	writeJSONValue(w, http.StatusOK, map[string]any{
		"status":       "deleted",
		"asset_path":   assetPath,
		"edge_path":    edgePath,
		"public_url":   s.publicAssetURL(edgePath),
		"purge_status": purgeStatus,
	})
}

func (s *dashboardServer) assetPurgeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rel, assetPath, edgePath, err := safeAssetDeletePath(r.URL.Query().Get("asset_path"), r.URL.Query().Get("edge_path"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.assetStorage().Exists(r.Context(), rel); err != nil {
		writeAssetStoreError(w, "failed to inspect asset", err)
		return
	}
	if err := s.purgeAsset(r.Context(), strings.TrimSpace(r.URL.Query().Get("host")), edgePath); err != nil {
		writeJSONValue(w, http.StatusAccepted, map[string]any{
			"status":       "purge_failed",
			"asset_path":   assetPath,
			"edge_path":    edgePath,
			"public_url":   s.publicAssetURL(edgePath),
			"purge_status": "failed",
			"purge_error":  err.Error(),
		})
		return
	}
	writeJSONValue(w, http.StatusAccepted, map[string]any{
		"status":       "purged",
		"asset_path":   assetPath,
		"edge_path":    edgePath,
		"public_url":   s.publicAssetURL(edgePath),
		"purge_status": "accepted",
	})
}

func (s *dashboardServer) assetStorage() dashboardAssetStore {
	if s != nil && s.assetStore != nil {
		return s.assetStore
	}
	if s != nil {
		return localDashboardAssetStore{dir: s.assetDir}
	}
	return localDashboardAssetStore{}
}

type dashboardAssetStore interface {
	Save(ctx context.Context, rel string, src io.Reader, maxBytes int64, contentType string) (int64, error)
	List(ctx context.Context, folder string, limit int) ([]dashboardAssetObject, error)
	Delete(ctx context.Context, rel string) error
	Exists(ctx context.Context, rel string) error
}

type dashboardAssetObject struct {
	Rel         string
	Size        int64
	ModifiedAt  time.Time
	ContentType string
}

type localDashboardAssetStore struct {
	dir string
}

func newDashboardAssetStoreFromEnv() dashboardAssetStore {
	mode := strings.ToLower(strings.TrimSpace(env("DASHBOARD_STORAGE_MODE", env("ORIGIN_STORAGE_MODE", "local"))))
	if mode == "s3" {
		return s3DashboardAssetStore{
			endpoint:        strings.TrimRight(env("DASHBOARD_S3_ENDPOINT", env("ORIGIN_S3_ENDPOINT", "")), "/"),
			bucket:          env("DASHBOARD_S3_BUCKET", env("ORIGIN_S3_BUCKET", "")),
			region:          env("DASHBOARD_S3_REGION", env("ORIGIN_S3_REGION", "us-east-1")),
			accessKeyID:     env("DASHBOARD_S3_ACCESS_KEY_ID", env("ORIGIN_S3_ACCESS_KEY_ID", "")),
			secretAccessKey: env("DASHBOARD_S3_SECRET_ACCESS_KEY", env("ORIGIN_S3_SECRET_ACCESS_KEY", "")),
			sessionToken:    env("DASHBOARD_S3_SESSION_TOKEN", env("ORIGIN_S3_SESSION_TOKEN", "")),
			prefix:          strings.Trim(strings.TrimSpace(env("DASHBOARD_S3_PREFIX", env("ORIGIN_S3_PREFIX", ""))), "/"),
			forcePathStyle:  envBool("DASHBOARD_S3_FORCE_PATH_STYLE", envBool("ORIGIN_S3_FORCE_PATH_STYLE", true)),
			client: &http.Client{
				Timeout: envDuration("DASHBOARD_S3_TIMEOUT", envDuration("ORIGIN_S3_TIMEOUT", 30*time.Second)),
			},
		}
	}
	return localDashboardAssetStore{dir: env("DASHBOARD_ASSET_DIR", "data/origin")}
}

func (s localDashboardAssetStore) Save(_ context.Context, rel string, src io.Reader, maxBytes int64, _ string) (int64, error) {
	if s.dir == "" {
		return 0, errAssetStoreNotConfigured
	}
	targetPath := filepath.Join(s.dir, filepath.FromSlash(rel))
	if err := ensurePathInside(s.dir, targetPath); err != nil {
		return 0, errAssetPathInvalid
	}
	targetDir := filepath.Dir(targetPath)
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		log.Printf("dashboard asset mkdir failed dir=%s err=%v", targetDir, err)
		return 0, errAssetStoreFailed
	}
	temp, err := os.CreateTemp(targetDir, "."+path.Base(rel)+".tmp-*")
	if err != nil {
		log.Printf("dashboard asset temp create failed dir=%s err=%v", targetDir, err)
		return 0, errAssetStoreFailed
	}
	tempName := temp.Name()
	defer func() {
		_ = os.Remove(tempName)
	}()

	written, err := copyUpload(temp, src, maxBytes)
	closeErr := temp.Close()
	if err != nil {
		return written, err
	}
	if closeErr != nil {
		log.Printf("dashboard asset temp close failed path=%s err=%v", tempName, closeErr)
		return written, errAssetStoreFailed
	}
	if err := os.Rename(tempName, targetPath); err != nil {
		log.Printf("dashboard asset rename failed src=%s dst=%s err=%v", tempName, targetPath, err)
		return written, errAssetStoreFailed
	}
	return written, nil
}

func (s localDashboardAssetStore) List(_ context.Context, folder string, limit int) ([]dashboardAssetObject, error) {
	if s.dir == "" {
		return nil, errAssetStoreNotConfigured
	}
	root := filepath.Join(s.dir, filepath.FromSlash(folder))
	if err := ensurePathInside(s.dir, root); err != nil {
		return nil, errAssetPathInvalid
	}
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return []dashboardAssetObject{}, nil
	} else if err != nil {
		log.Printf("dashboard asset list stat failed dir=%s err=%v", root, err)
		return nil, errAssetInspectFailed
	}

	objects := make([]dashboardAssetObject, 0)
	walkErr := filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(s.dir, filePath)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(path.Base(rel), ".") {
			return nil
		}
		objects = append(objects, dashboardAssetObject{
			Rel:         rel,
			Size:        info.Size(),
			ModifiedAt:  info.ModTime(),
			ContentType: contentTypeForAsset(rel),
		})
		return nil
	})
	if walkErr != nil {
		log.Printf("dashboard asset list failed dir=%s err=%v", root, walkErr)
		return nil, errAssetInspectFailed
	}
	if len(objects) > limit {
		objects = objects[:limit]
	}
	return objects, nil
}

func (s localDashboardAssetStore) Delete(_ context.Context, rel string) error {
	targetPath, info, err := s.localAssetFile(rel)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return errAssetPathInvalid
	}
	if err := os.Remove(targetPath); err != nil {
		log.Printf("dashboard asset delete failed path=%s err=%v", targetPath, err)
		return errAssetStoreFailed
	}
	removeEmptyAssetParents(s.dir, filepath.Dir(targetPath))
	return nil
}

func (s localDashboardAssetStore) Exists(_ context.Context, rel string) error {
	_, info, err := s.localAssetFile(rel)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return errAssetPathInvalid
	}
	return nil
}

func (s localDashboardAssetStore) localAssetFile(rel string) (string, os.FileInfo, error) {
	if s.dir == "" {
		return "", nil, errAssetStoreNotConfigured
	}
	targetPath := filepath.Join(s.dir, filepath.FromSlash(rel))
	if err := ensurePathInside(s.dir, targetPath); err != nil {
		return "", nil, errAssetPathInvalid
	}
	info, err := os.Stat(targetPath)
	if os.IsNotExist(err) {
		return targetPath, nil, errAssetNotFound
	}
	if err != nil {
		log.Printf("dashboard asset stat failed path=%s err=%v", targetPath, err)
		return targetPath, nil, errAssetInspectFailed
	}
	return targetPath, info, nil
}

type s3DashboardAssetStore struct {
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

func (s s3DashboardAssetStore) Save(ctx context.Context, rel string, src io.Reader, maxBytes int64, contentType string) (int64, error) {
	if s.endpoint == "" || s.bucket == "" {
		return 0, errAssetStoreNotConfigured
	}
	var body bytes.Buffer
	written, err := copyUploadToWriter(&body, src, maxBytes)
	if err != nil {
		return written, err
	}
	target, err := s.objectURL(rel, nil)
	if err != nil {
		return 0, errAssetPathInvalid
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(body.Bytes()))
	if err != nil {
		return 0, errAssetStoreFailed
	}
	req.ContentLength = int64(body.Len())
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Cache-Control", fmt.Sprintf("public, max-age=%d", envInt64("ORIGIN_CACHE_MAX_AGE", 60)))
	s.sign(req, time.Now().UTC())
	resp, err := s.httpClient().Do(req)
	if err != nil {
		log.Printf("dashboard s3 upload failed bucket=%s key=%s err=%v", s.bucket, s.objectKey(rel), err)
		return written, errAssetStoreFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		log.Printf("dashboard s3 upload failed status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
		return written, errAssetStoreFailed
	}
	return written, nil
}

func (s s3DashboardAssetStore) List(ctx context.Context, folder string, limit int) ([]dashboardAssetObject, error) {
	if s.endpoint == "" || s.bucket == "" {
		return nil, errAssetStoreNotConfigured
	}
	query := url.Values{}
	query.Set("list-type", "2")
	query.Set("prefix", s.listPrefix(folder))
	query.Set("max-keys", strconv.Itoa(limit))
	target, err := s.bucketURL(query)
	if err != nil {
		return nil, errAssetPathInvalid
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, errAssetStoreFailed
	}
	s.sign(req, time.Now().UTC())
	resp, err := s.httpClient().Do(req)
	if err != nil {
		log.Printf("dashboard s3 list failed bucket=%s prefix=%s err=%v", s.bucket, s.listPrefix(folder), err)
		return nil, errAssetStoreFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		log.Printf("dashboard s3 list failed status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
		return nil, errAssetStoreFailed
	}
	var listed s3ListBucketResult
	if err := xml.NewDecoder(resp.Body).Decode(&listed); err != nil {
		log.Printf("dashboard s3 list decode failed err=%v", err)
		return nil, errAssetStoreFailed
	}
	objects := make([]dashboardAssetObject, 0, len(listed.Contents))
	for _, object := range listed.Contents {
		rel := s.relFromObjectKey(object.Key)
		if rel == "" || strings.HasSuffix(rel, "/") {
			continue
		}
		modifiedAt, _ := time.Parse(time.RFC3339, object.LastModified)
		objects = append(objects, dashboardAssetObject{
			Rel:         rel,
			Size:        object.Size,
			ModifiedAt:  modifiedAt,
			ContentType: contentTypeForAsset(rel),
		})
	}
	return objects, nil
}

func (s s3DashboardAssetStore) Delete(ctx context.Context, rel string) error {
	if err := s.Exists(ctx, rel); err != nil {
		return err
	}
	target, err := s.objectURL(rel, nil)
	if err != nil {
		return errAssetPathInvalid
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, target, nil)
	if err != nil {
		return errAssetStoreFailed
	}
	s.sign(req, time.Now().UTC())
	resp, err := s.httpClient().Do(req)
	if err != nil {
		log.Printf("dashboard s3 delete failed bucket=%s key=%s err=%v", s.bucket, s.objectKey(rel), err)
		return errAssetStoreFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errAssetNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errAssetStoreFailed
	}
	return nil
}

func (s s3DashboardAssetStore) Exists(ctx context.Context, rel string) error {
	if s.endpoint == "" || s.bucket == "" {
		return errAssetStoreNotConfigured
	}
	target, err := s.objectURL(rel, nil)
	if err != nil {
		return errAssetPathInvalid
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	if err != nil {
		return errAssetStoreFailed
	}
	s.sign(req, time.Now().UTC())
	resp, err := s.httpClient().Do(req)
	if err != nil {
		log.Printf("dashboard s3 head failed bucket=%s key=%s err=%v", s.bucket, s.objectKey(rel), err)
		return errAssetStoreFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
		return errAssetNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errAssetInspectFailed
	}
	return nil
}

func (s s3DashboardAssetStore) httpClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return http.DefaultClient
}

func (s s3DashboardAssetStore) bucketURL(query url.Values) (string, error) {
	base, err := url.Parse(s.endpoint)
	if err != nil {
		return "", err
	}
	if s.forcePathStyle {
		base.Path = joinURLPath(base.Path, s.bucket)
	} else {
		base.Host = s.bucket + "." + base.Host
	}
	base.RawQuery = query.Encode()
	return base.String(), nil
}

func (s s3DashboardAssetStore) objectURL(rel string, query url.Values) (string, error) {
	base, err := url.Parse(s.endpoint)
	if err != nil {
		return "", err
	}
	key := s.objectKey(rel)
	if s.forcePathStyle {
		base.Path = joinURLPath(joinURLPath(base.Path, s.bucket), key)
	} else {
		base.Host = s.bucket + "." + base.Host
		base.Path = joinURLPath(base.Path, key)
	}
	if query != nil {
		base.RawQuery = query.Encode()
	}
	return base.String(), nil
}

func (s s3DashboardAssetStore) objectKey(rel string) string {
	rel = strings.Trim(strings.ReplaceAll(rel, "\\", "/"), "/")
	if s.prefix == "" {
		return rel
	}
	if rel == "" {
		return strings.Trim(s.prefix, "/")
	}
	return strings.Trim(s.prefix, "/") + "/" + rel
}

func (s s3DashboardAssetStore) listPrefix(folder string) string {
	prefix := s.objectKey(folder)
	if folder != "" && prefix != "" && !strings.HasSuffix(prefix, "/") {
		return prefix + "/"
	}
	return prefix
}

func (s s3DashboardAssetStore) relFromObjectKey(key string) string {
	key = strings.Trim(strings.ReplaceAll(key, "\\", "/"), "/")
	prefix := strings.Trim(s.prefix, "/")
	if prefix == "" {
		return key
	}
	if key == prefix {
		return ""
	}
	return strings.TrimPrefix(strings.TrimPrefix(key, prefix), "/")
}

func (s s3DashboardAssetStore) sign(req *http.Request, now time.Time) {
	if s.accessKeyID == "" || s.secretAccessKey == "" {
		return
	}
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
	region := s.region
	if region == "" {
		region = "us-east-1"
	}
	scope := dateStamp + "/" + region + "/s3/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex(canonicalRequest),
	}, "\n")
	signature := hex.EncodeToString(hmacSHA256(signingKey(s.secretAccessKey, dateStamp, region), stringToSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.accessKeyID+"/"+scope+", SignedHeaders="+strings.Join(signedHeaders, ";")+", Signature="+signature)
}

type s3ListBucketResult struct {
	Contents []struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
		Size         int64  `xml:"Size"`
	} `xml:"Contents"`
}

var (
	errAssetPathInvalid        = errors.New("invalid asset path")
	errAssetNotFound           = errors.New("asset not found")
	errAssetInspectFailed      = errors.New("failed to inspect asset")
	errAssetStoreFailed        = errors.New("asset store operation failed")
	errAssetStoreNotConfigured = errors.New("asset store is not configured")
)

func writeAssetStoreError(w http.ResponseWriter, fallback string, err error) {
	switch {
	case errors.Is(err, errAssetPathInvalid):
		http.Error(w, "invalid asset path", http.StatusBadRequest)
	case errors.Is(err, errAssetNotFound):
		http.Error(w, "asset not found", http.StatusNotFound)
	case errors.Is(err, errAssetStoreNotConfigured):
		http.Error(w, "asset storage is not configured", http.StatusInternalServerError)
	case errors.Is(err, errAssetStoreFailed):
		http.Error(w, fallback, http.StatusInternalServerError)
	case strings.Contains(err.Error(), "upload too large"):
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
	default:
		http.Error(w, fallback, http.StatusInternalServerError)
	}
}

func (s *dashboardServer) publicAssetURL(edgePath string) string {
	if s == nil || s.publicCDNBaseURL == nil || edgePath == "" {
		return ""
	}
	u := *s.publicCDNBaseURL
	u.Path = joinURLPath(s.publicCDNBaseURL.Path, edgePath)
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func (s *dashboardServer) purgeAsset(ctx context.Context, host, edgePath string) error {
	if s.controlBaseURL == nil {
		return errors.New("control upstream is not configured")
	}
	payload := map[string]any{
		"keys":         []string{edgePath},
		"requested_by": "dashboard",
	}
	if host != "" {
		if !validCDNFetchHost(host) {
			return errors.New("invalid purge host")
		}
		payload["host"] = host
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	target := *s.controlBaseURL
	target.Path = joinURLPath(s.controlBaseURL.Path, "/v1/cache/invalidate")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return errors.New("control purge failed: " + strings.TrimSpace(string(responseBody)))
	}
	return nil
}

func safeAssetFolder(raw string) (string, error) {
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	if raw == "" {
		raw = "uploads"
	}
	if strings.HasPrefix(raw, "/") {
		return "", errors.New("folder must be relative")
	}
	cleaned := path.Clean(raw)
	if cleaned == "." {
		cleaned = "uploads"
	}
	segments := strings.Split(cleaned, "/")
	safe := make([]string, 0, len(segments))
	for _, segment := range segments {
		if segment == "" || segment == "." {
			continue
		}
		if segment == ".." {
			return "", errors.New("folder must not contain path traversal")
		}
		safe = append(safe, sanitizeAssetSegment(segment))
	}
	if len(safe) == 0 {
		return "uploads", nil
	}
	return path.Join(safe...), nil
}

func safeAssetListFolder(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	return safeAssetFolder(raw)
}

func safeAssetDeletePath(assetPathRaw, edgePathRaw string) (string, string, string, error) {
	raw := strings.TrimSpace(assetPathRaw)
	if raw == "" {
		raw = strings.TrimSpace(edgePathRaw)
	}
	if raw == "" {
		return "", "", "", errors.New("asset_path or edge_path is required")
	}
	if strings.HasPrefix(raw, "/edge/assets/") {
		raw = strings.TrimPrefix(raw, "/edge")
	}
	if !strings.HasPrefix(raw, "/assets/") {
		return "", "", "", errors.New("asset path must start with /assets/")
	}
	rel := strings.ReplaceAll(strings.TrimPrefix(raw, "/assets/"), "\\", "/")
	if rel == "" || strings.HasSuffix(rel, "/") {
		return "", "", "", errors.New("asset path must reference a file")
	}
	for _, segment := range strings.Split(rel, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", "", "", errors.New("asset path must not contain path traversal")
		}
	}
	cleaned := path.Clean("/" + rel)
	rel = strings.TrimPrefix(cleaned, "/")
	if strings.HasPrefix(rel, "../") || rel == ".." || path.Base(rel) == "." || path.Base(rel) == ".." {
		return "", "", "", errors.New("asset path is invalid")
	}
	assetPath := "/assets/" + rel
	return rel, assetPath, "/edge" + assetPath, nil
}

func safeAssetFilename(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("filename is required")
	}
	if strings.ContainsAny(raw, `/\`) || raw == "." || raw == ".." {
		return "", errors.New("filename must not contain path separators")
	}
	name := sanitizeAssetSegment(raw)
	if name == "" || name == "." || name == ".." {
		return "", errors.New("filename is invalid")
	}
	return name, nil
}

func sanitizeAssetSegment(segment string) string {
	segment = strings.TrimSpace(segment)
	var b strings.Builder
	b.Grow(len(segment))
	lastDash := false
	for _, r := range segment {
		ok := r >= 'a' && r <= 'z' ||
			r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' ||
			r == '.' || r == '_' || r == '-'
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), ".-")
}

func contentTypeForAsset(assetPath string) string {
	if contentType := mime.TypeByExtension(path.Ext(assetPath)); contentType != "" {
		return contentType
	}
	return "application/octet-stream"
}

func removeEmptyAssetParents(root, start string) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return
	}
	current, err := filepath.Abs(start)
	if err != nil {
		return
	}
	for {
		if current == rootAbs {
			return
		}
		rel, err := filepath.Rel(rootAbs, current)
		if err != nil || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
			return
		}
		if err := os.Remove(current); err != nil {
			return
		}
		current = filepath.Dir(current)
	}
}

func ensurePathInside(root, candidate string) error {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(rootAbs, candidateAbs)
	if err != nil {
		return err
	}
	if rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." && !filepath.IsAbs(rel)) {
		return nil
	}
	return errors.New("path escapes root")
}

func copyUpload(dst *os.File, src io.Reader, maxBytes int64) (int64, error) {
	written, err := copyUploadToWriter(dst, src, maxBytes)
	if err != nil {
		return written, err
	}
	if err := dst.Sync(); err != nil {
		return written, errors.New("failed to flush upload")
	}
	return written, nil
}

func copyUploadToWriter(dst io.Writer, src io.Reader, maxBytes int64) (int64, error) {
	limited := io.LimitReader(src, maxBytes+1)
	written, err := io.Copy(dst, limited)
	if err != nil {
		return written, errors.New("failed to write upload")
	}
	if written > maxBytes {
		return written, errors.New("upload too large")
	}
	return written, nil
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

func validCDNFetchHost(host string) bool {
	if host == "" || strings.ContainsAny(host, "/?#") {
		return false
	}
	return true
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func copyProxyHeaders(dst, src http.Header) {
	for key, values := range src {
		if hopByHopHeader(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func hopByHopHeader(key string) bool {
	switch strings.ToLower(key) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func joinURLPath(basePath, requestPath string) string {
	basePath = strings.TrimRight(basePath, "/")
	requestPath = "/" + strings.TrimLeft(requestPath, "/")
	if basePath == "" {
		return requestPath
	}
	return basePath + requestPath
}

func mustParseBaseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		log.Fatalf("invalid dashboard upstream URL %q", raw)
	}
	return u
}

func writeJSON(w http.ResponseWriter, status int, payload string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(payload))
}

func writeJSONValue(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("dashboard json encode failed: %v", err)
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

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
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
	if err != nil || value < 0 {
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

func parsePositiveInt(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
