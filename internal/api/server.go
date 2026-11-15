// Package api implements the REST HTTP API layer.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/nfchecker/internal/cookiefetch"
	"github.com/nfchecker/internal/models"
	"github.com/nfchecker/internal/proxy"
	"github.com/nfchecker/internal/worker"
)

// Server is the main API server.
type Server struct {
	router    *mux.Router
	jobs      sync.Map // jobID -> *jobRecord
	proxyPool *proxy.Pool

	// default worker settings (can be overridden per request)
	defaultConcurrency   int
	defaultRatePerMinute int
}

type jobRecord struct {
	status *models.JobStatus
	hits   []*models.CheckResult
	hitsMu sync.Mutex
	cancel context.CancelFunc
}

// NewServer creates a configured API server.
func NewServer(concurrency, ratePerMinute int) *Server {
	s := &Server{
		proxyPool:            proxy.NewPool(3),
		defaultConcurrency:   concurrency,
		defaultRatePerMinute: ratePerMinute,
	}
	s.router = mux.NewRouter()
	s.registerRoutes()
	s.startJanitor()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) registerRoutes() {
	r := s.router

	// Middlewares
	r.Use(recoveryMiddleware)
	r.Use(corsAndLoggingMiddleware)

	// API v1 routes
	v1 := r.PathPrefix("/api/v1").Subrouter()
	v1.HandleFunc("/jobs", s.handleSubmitJob).Methods("POST")
	v1.HandleFunc("/jobs", s.handleListJobs).Methods("GET")
	v1.HandleFunc("/jobs/{id}", s.handleGetJob).Methods("GET")
	v1.HandleFunc("/jobs/{id}/hits", s.handleGetHits).Methods("GET")
	v1.HandleFunc("/jobs/{id}/export", s.handleExportHits).Methods("GET")
	v1.HandleFunc("/jobs/{id}/cancel", s.handleCancelJob).Methods("POST")
	v1.HandleFunc("/proxies", s.handleUpdateProxies).Methods("POST")
	v1.HandleFunc("/proxies/status", s.handleProxyStatus).Methods("GET")
	v1.HandleFunc("/stats", s.handleStats).Methods("GET")

	// Prometheus Metrics
	r.HandleFunc("/metrics", s.handleMetrics).Methods("GET")

	// Health Checks & Root
	r.HandleFunc("/", s.handleRoot).Methods("GET")
	r.HandleFunc("/health", s.handleHealth).Methods("GET")
	r.HandleFunc("/health/live", s.handleHealth).Methods("GET")
	r.HandleFunc("/health/ready", s.handleHealthReady).Methods("GET")
}

// -----------------------------------------------------------------
// POST /api/v1/jobs
// Accepts:
//   multipart/form-data with:
//     - file: .txt / .json / .zip / .rar cookie file (required)
//     - concurrency: int (optional, overrides default)
//     - rate_per_minute: int (optional, 0 = unlimited)
//     - retry_on_proxy: bool (optional)
//   OR application/json body:
//     { "cookies": [...CookieSet...], "concurrency": N, ... }
// -----------------------------------------------------------------

func (s *Server) handleSubmitJob(w http.ResponseWriter, r *http.Request) {
	ct := r.Header.Get("Content-Type")

	var cookies []*models.CookieSet
	concurrency := s.defaultConcurrency
	ratePerMin := s.defaultRatePerMinute
	retryProxy := true

	switch {
	case isMultipart(ct):
		if err := r.ParseMultipartForm(256 << 20); err != nil { // 256MB max
			writeError(w, 400, "multipart parse error: "+err.Error())
			return
		}

		concurrency = queryInt(r, "concurrency", concurrency)
		ratePerMin = queryInt(r, "rate_per_minute", ratePerMin)
		retryProxy = queryBool(r, "retry_on_proxy", retryProxy)

		fh, _, err := r.FormFile("file")
		if err != nil {
			writeError(w, 400, "file field required: "+err.Error())
			return
		}
		defer fh.Close()

		data, fname, err := readFormFile(fh, r)
		if err != nil {
			writeError(w, 400, "file read error: "+err.Error())
			return
		}
		cookies, err = cookiefetch.ExtractFromReader(fname, data)
		if err != nil {
			writeError(w, 400, "cookie extract error: "+err.Error())
			return
		}

	default:
		var req struct {
			Cookies       []*models.CookieSet `json:"cookies"`
			Concurrency   int                 `json:"concurrency"`
			RatePerMinute int                 `json:"rate_per_minute"`
			RetryProxy    bool                `json:"retry_on_proxy"`
		}
		req.RetryProxy = true
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, 400, "JSON decode error: "+err.Error())
			return
		}
		cookies = req.Cookies
		if req.Concurrency > 0 {
			concurrency = req.Concurrency
		}
		if req.RatePerMinute != 0 {
			ratePerMin = req.RatePerMinute
		}
		retryProxy = req.RetryProxy
	}

	if len(cookies) == 0 {
		writeError(w, 400, "no valid cookies found in input")
		return
	}

	// Boundary safeguards
	if concurrency > 1000 {
		concurrency = 1000
	}
	if concurrency < 1 {
		concurrency = 1
	}

	jobID := uuid.New().String()
	status := &models.JobStatus{
		ID:        jobID,
		Total:     len(cookies),
		StartedAt: time.Now(),
	}
	status.Status = "running"
	status.WorkerCount = concurrency

	ctx, cancel := context.WithCancel(context.Background())
	rec := &jobRecord{status: status, cancel: cancel}
	s.jobs.Store(jobID, rec)

	cfg := worker.Config{
		Concurrency:   concurrency,
		RatePerMinute: ratePerMin,
		RetryOnProxy:  retryProxy,
		ProxyPool:     s.proxyPool,
	}
	p := worker.NewPool(cfg)
	resultChan := p.Run(ctx, cookies, status)

	// Async collector with safety cap (max 50,000 hits in memory)
	go func() {
		for res := range resultChan {
			if res.Status == "hit" {
				rec.hitsMu.Lock()
				if len(rec.hits) < 50000 {
					rec.hits = append(rec.hits, res)
				}
				rec.hitsMu.Unlock()
			}
		}
	}()

	slog.Info("Job submitted", "job_id", jobID, "total_cookies", len(cookies), "concurrency", concurrency, "rpm", ratePerMin)

	writeJSON(w, 201, map[string]interface{}{
		"job_id":  jobID,
		"status":  "running",
		"total":   len(cookies),
		"message": "batch submitted successfully",
	})
}

// -----------------------------------------------------------------
// GET /api/v1/jobs
// -----------------------------------------------------------------

func (s *Server) handleListJobs(w http.ResponseWriter, _ *http.Request) {
	var snapshots []models.JobStatusSnapshot
	s.jobs.Range(func(_, v interface{}) bool {
		rec := v.(*jobRecord)
		snapshots = append(snapshots, rec.status.Snapshot())
		return true
	})

	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].StartedAt > snapshots[j].StartedAt
	})

	writeJSON(w, 200, map[string]interface{}{
		"count": len(snapshots),
		"jobs":  snapshots,
	})
}

// -----------------------------------------------------------------
// GET /api/v1/jobs/:id
// -----------------------------------------------------------------

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.loadJob(w, r)
	if !ok {
		return
	}
	writeJSON(w, 200, rec.status.Snapshot())
}

// -----------------------------------------------------------------
// GET /api/v1/jobs/:id/hits
// Parameters:
//   - page: int (default 1)
//   - page_size: int (default 100, max 1000)
//   - plan: string (optional filter)
//   - hold: bool (optional filter)
// -----------------------------------------------------------------

func (s *Server) handleGetHits(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.loadJob(w, r)
	if !ok {
		return
	}

	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 100)
	if pageSize > 1000 {
		pageSize = 1000
	}
	if pageSize < 1 {
		pageSize = 100
	}

	planFilter := strings.ToLower(r.URL.Query().Get("plan"))
	holdFilter := strings.ToLower(r.URL.Query().Get("hold"))

	rec.hitsMu.Lock()
	var filtered []*models.CheckResult
	for _, h := range rec.hits {
		if planFilter != "" {
			if h.Account == nil || (!strings.Contains(strings.ToLower(h.Account.Plan), planFilter) && !strings.Contains(strings.ToLower(h.Account.PlanType), planFilter)) {
				continue
			}
		}
		if holdFilter != "" {
			isHold := holdFilter == "true" || holdFilter == "yes" || holdFilter == "1"
			if h.Account == nil || (h.Account.IsOnHold != isHold) {
				continue
			}
		}
		filtered = append(filtered, h)
	}
	rec.hitsMu.Unlock()

	totalHits := len(filtered)
	totalPages := (totalHits + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}

	start := (page - 1) * pageSize
	end := start + pageSize
	if start > totalHits {
		start = totalHits
	}
	if end > totalHits {
		end = totalHits
	}

	hitsPage := filtered[start:end]
	writeJSON(w, 200, map[string]interface{}{
		"job_id":      mux.Vars(r)["id"],
		"total_hits":  totalHits,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": totalPages,
		"hits":        hitsPage,
	})
}

// -----------------------------------------------------------------
// GET /api/v1/jobs/:id/export
// -----------------------------------------------------------------

func (s *Server) handleExportHits(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.loadJob(w, r)
	if !ok {
		return
	}

	format := r.URL.Query().Get("format")
	rec.hitsMu.Lock()
	hits := make([]*models.CheckResult, len(rec.hits))
	copy(hits, rec.hits)
	rec.hitsMu.Unlock()

	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"hits_%s.json\"", mux.Vars(r)["id"]))
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(hits)
		return
	}

	var buf strings.Builder
	for _, h := range hits {
		acc := h.Account
		if acc == nil {
			acc = &models.AccountInfo{}
		}
		nft := h.NfToken
		if nft == nil {
			nft = &models.NfToken{}
		}

		buf.WriteString("==================================================\n")
		buf.WriteString("✅ NETFLIX HIT\n")
		buf.WriteString(fmt.Sprintf("Name: %s\n", acc.Name))
		buf.WriteString(fmt.Sprintf("Email: %s\n", acc.Email))
		buf.WriteString(fmt.Sprintf("Country: %s %s\n", acc.Country, acc.CountryFlag))
		buf.WriteString(fmt.Sprintf("Plan: %s (Type: %s, Streams: %d, Quality: %s)\n", acc.Plan, acc.PlanType, acc.Streams, acc.VideoQuality))
		buf.WriteString(fmt.Sprintf("Price: %s | Payment: %s | Card: %s\n", acc.Price, acc.Payment, acc.Card))
		buf.WriteString(fmt.Sprintf("Hold Status: %s | Extra Member: %s\n", acc.HoldStatus, acc.ExtraMember))
		buf.WriteString(fmt.Sprintf("Valid Till: %s\n", acc.ValidTillUTC))
		if nft.Token != "" {
			buf.WriteString(fmt.Sprintf("📱 Phone: %s\n", nft.PhoneLink))
			buf.WriteString(fmt.Sprintf("💻 PC:    %s\n", nft.PCLink))
			buf.WriteString(fmt.Sprintf("📺 TV:    %s\n", nft.TVLink))
		}
		buf.WriteString("\n")
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"hits_%s.txt\"", mux.Vars(r)["id"]))
	w.Write([]byte(buf.String()))
}

// -----------------------------------------------------------------
// POST /api/v1/jobs/:id/cancel
// -----------------------------------------------------------------

func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.loadJob(w, r)
	if !ok {
		return
	}
	rec.cancel()
	rec.status.SetCancelled()
	slog.Info("Job cancelled", "job_id", mux.Vars(r)["id"])
	writeJSON(w, 200, map[string]string{"status": "cancelled"})
}

// -----------------------------------------------------------------
// POST /api/v1/proxies
// -----------------------------------------------------------------

func (s *Server) handleUpdateProxies(w http.ResponseWriter, r *http.Request) {
	var raw string
	ct := r.Header.Get("Content-Type")

	switch {
	case isMultipart(ct):
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			writeError(w, 400, "multipart parse error: "+err.Error())
			return
		}
		fh, _, err := r.FormFile("file")
		if err != nil {
			writeError(w, 400, "file field required: "+err.Error())
			return
		}
		defer fh.Close()
		data, _, _ := readFormFile(fh, r)
		raw = string(data)

	case ct == "text/plain":
		b, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
		if err != nil {
			writeError(w, 400, "read error: "+err.Error())
			return
		}
		raw = string(b)

	default:
		var req struct {
			Proxies string `json:"proxies"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, 400, "JSON decode error: "+err.Error())
			return
		}
		raw = req.Proxies
	}

	n := s.proxyPool.LoadFromString(raw)
	slog.Info("Proxies updated", "loaded", n, "alive", s.proxyPool.Alive())
	writeJSON(w, 200, map[string]interface{}{
		"loaded": n,
		"alive":  s.proxyPool.Alive(),
	})
}

// GET /api/v1/proxies/status
func (s *Server) handleProxyStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]interface{}{
		"total": s.proxyPool.Total(),
		"alive": s.proxyPool.Alive(),
	})
}

// -----------------------------------------------------------------
// GET /api/v1/stats
// -----------------------------------------------------------------

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	activeJobs := 0
	totalJobs := 0
	s.jobs.Range(func(_, v interface{}) bool {
		totalJobs++
		rec := v.(*jobRecord)
		snap := rec.status.Snapshot()
		if snap.Status == "running" {
			activeJobs++
		}
		return true
	})

	writeJSON(w, 200, map[string]interface{}{
		"goroutines":    runtime.NumGoroutine(),
		"active_jobs":   activeJobs,
		"total_jobs":    totalJobs,
		"proxy_total":   s.proxyPool.Total(),
		"proxy_alive":   s.proxyPool.Alive(),
		"heap_alloc_mb": float64(ms.HeapAlloc) / 1024 / 1024,
		"sys_mb":        float64(ms.Sys) / 1024 / 1024,
		"gc_cycles":     ms.NumGC,
	})
}

// -----------------------------------------------------------------
// GET /metrics (Prometheus plaintext format)
// -----------------------------------------------------------------

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	activeJobs := 0
	totalJobs := 0
	var totalHits int64
	var totalChecked int64

	s.jobs.Range(func(_, v interface{}) bool {
		totalJobs++
		rec := v.(*jobRecord)
		snap := rec.status.Snapshot()
		if snap.Status == "running" {
			activeJobs++
		}
		totalHits += snap.Hits
		totalChecked += snap.Checked
		return true
	})

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP nfcheck_goroutines Active Go goroutines\n# TYPE nfcheck_goroutines gauge\nnfcheck_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(w, "# HELP nfcheck_heap_alloc_bytes Bytes allocated on heap\n# TYPE nfcheck_heap_alloc_bytes gauge\nnfcheck_heap_alloc_bytes %d\n", ms.HeapAlloc)
	fmt.Fprintf(w, "# HELP nfcheck_heap_sys_bytes Bytes obtained from system\n# TYPE nfcheck_heap_sys_bytes gauge\nnfcheck_heap_sys_bytes %d\n", ms.HeapSys)
	fmt.Fprintf(w, "# HELP nfcheck_gc_cycles_total Total GC cycles completed\n# TYPE nfcheck_gc_cycles_total counter\nnfcheck_gc_cycles_total %d\n", ms.NumGC)
	fmt.Fprintf(w, "# HELP nfcheck_jobs_active Active checking jobs\n# TYPE nfcheck_jobs_active gauge\nnfcheck_jobs_active %d\n", activeJobs)
	fmt.Fprintf(w, "# HELP nfcheck_jobs_total Total checking jobs submitted\n# TYPE nfcheck_jobs_total counter\nnfcheck_jobs_total %d\n", totalJobs)
	fmt.Fprintf(w, "# HELP nfcheck_checked_total Total cookies checked across all jobs\n# TYPE nfcheck_checked_total counter\nnfcheck_checked_total %d\n", totalChecked)
	fmt.Fprintf(w, "# HELP nfcheck_hits_total Total hits found across all jobs\n# TYPE nfcheck_hits_total counter\nnfcheck_hits_total %d\n", totalHits)
	fmt.Fprintf(w, "# HELP nfcheck_proxies_total Total proxies configured\n# TYPE nfcheck_proxies_total gauge\nnfcheck_proxies_total %d\n", s.proxyPool.Total())
	fmt.Fprintf(w, "# HELP nfcheck_proxies_alive Total live proxies in pool\n# TYPE nfcheck_proxies_alive gauge\nnfcheck_proxies_alive %d\n", s.proxyPool.Alive())
}

// -----------------------------------------------------------------
// Health Endpoints
// -----------------------------------------------------------------

func (s *Server) handleRoot(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"service": "nfcheck",
		"version": "2.0.0",
		"status":  "ok",
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok", "service": "nfcheck"})
}

func (s *Server) handleHealthReady(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]interface{}{
		"status":      "ready",
		"proxy_alive": s.proxyPool.Alive(),
	})
}

// -----------------------------------------------------------------
// Background Janitor — cleans jobs older than 24h
// -----------------------------------------------------------------

func (s *Server) startJanitor() {
	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cutoff := time.Now().Add(-24 * time.Hour)
			s.jobs.Range(func(k, v interface{}) bool {
				rec := v.(*jobRecord)
				snap := rec.status.Snapshot()
				if (snap.Status == "done" || snap.Status == "cancelled" || snap.Status == "failed") && rec.status.StartedAt.Before(cutoff) {
					s.jobs.Delete(k)
					slog.Info("Janitor cleaned up expired job", "job_id", k)
				}
				return true
			})
		}
	}()
}

// -----------------------------------------------------------------
// Middlewares
// -----------------------------------------------------------------

func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("PANIC RECOVERED in HTTP handler", "error", rec)
				writeError(w, 500, "Internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func corsAndLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = uuid.New().String()
		}
		w.Header().Set("X-Request-ID", reqID)

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE, PUT")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// -----------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------

func (s *Server) loadJob(w http.ResponseWriter, r *http.Request) (*jobRecord, bool) {
	id := mux.Vars(r)["id"]
	v, ok := s.jobs.Load(id)
	if !ok {
		writeError(w, 404, fmt.Sprintf("job %s not found", id))
		return nil, false
	}
	return v.(*jobRecord), true
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func isMultipart(ct string) bool {
	return len(ct) >= 20 && ct[:20] == "multipart/form-data;"
}

func readFormFile(fh multipart.File, r *http.Request) ([]byte, string, error) {
	fname := ""
	for _, fhs := range r.MultipartForm.File {
		if len(fhs) > 0 {
			fname = fhs[0].Filename
			break
		}
	}
	data, err := io.ReadAll(io.LimitReader(fh, 512<<20)) // 512MB max
	return data, fname, err
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.FormValue(key)
	if v == "" {
		v = r.URL.Query().Get(key)
	}
	if v == "" {
		return def
	}
	var i int
	fmt.Sscanf(v, "%d", &i)
	if i < 0 {
		return def
	}
	return i
}

func queryBool(r *http.Request, key string, def bool) bool {
	v := r.FormValue(key)
	if v == "" {
		v = r.URL.Query().Get(key)
	}
	if v == "" {
		return def
	}
	return v == "true" || v == "1" || v == "yes"
}
