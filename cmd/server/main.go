package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/nfchecker/internal/api"
)

// Built-in defaults: no environment is required to run the server. It
// starts with 300 workers, no rate limit and JSON logs. Every value can
// still be overridden by a flag or the matching environment variable.
const (
	defaultWorkersCount = 300
	defaultRatePerMin   = 0
	defaultJSONLog      = true
)

var (
	version   = "2.0.0"
	buildTime = "2026-11-15"
)

func main() {
	defaultListen := defaultAddr()
	defaultWorkersCount := defaultWorkers()

	addr := flag.String("addr", defaultListen, "Listen address (env: PORT or ADDR, default 0.0.0.0:8080)")
	workers := flag.Int("workers", defaultWorkersCount, "Worker goroutines (env: WORKERS or CONCURRENCY, default 300)")
	concurrency := flag.Int("concurrency", defaultWorkersCount, "Legacy alias for -workers (env: CONCURRENCY)")
	ratePerMin := flag.Int("rpm", envInt("RATE_PER_MIN", defaultRatePerMin), "Checks per minute, 0=unlimited (env: RATE_PER_MIN, default 0)")
	readTimeout := flag.Duration("read-timeout", 30*time.Second, "HTTP read timeout")
	writeTimeout := flag.Duration("write-timeout", 120*time.Second, "HTTP write timeout")
	maxGOMAXPROCS := flag.Int("gomaxprocs", 0, "Override GOMAXPROCS (0 = use all CPUs)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	jsonLog := flag.Bool("json-log", envBool("JSON_LOG", defaultJSONLog), "Output structured JSON logs (default on)")
	proxiesFile := flag.String("proxies-file", os.Getenv("PROXIES_FILE"), "Load proxies from this file at startup (env: PROXIES_FILE)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("nfchecker v%s (built %s)\n", version, buildTime)
		os.Exit(0)
	}

	// Resolve worker count prioritizing explicitly set CLI flags
	workerCount := *workers
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "concurrency" {
			workerCount = *concurrency
		} else if f.Name == "workers" {
			workerCount = *workers
		}
	})

	// Configure structured logger
	var logHandler slog.Handler
	if *jsonLog {
		logHandler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	} else {
		logHandler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	slog.SetDefault(slog.New(logHandler))

	if *maxGOMAXPROCS > 0 {
		runtime.GOMAXPROCS(*maxGOMAXPROCS)
	}

	srv := api.NewServer(workerCount, *ratePerMin)

	// Dead proxies come back every 5 minutes so a transient failure cannot
	// permanently shrink the pool to zero.
	srv.StartProxyReviver(5*time.Minute, 10*time.Minute)

	if path := strings.TrimSpace(*proxiesFile); path != "" {
		report, err := srv.LoadProxiesFromFile(path)
		if err != nil {
			slog.Error("Proxy file could not be loaded", "path", path, "error", err)
		} else {
			slog.Info("Proxies preloaded",
				"path", path,
				"loaded", report.Loaded,
				"rejected_lines", report.Rejected,
			)
		}
	}

	httpSrv := &http.Server{
		Addr:         *addr,
		Handler:      srv,
		ReadTimeout:  *readTimeout,
		WriteTimeout: *writeTimeout,
		IdleTimeout:  120 * time.Second,
	}

	// Channel for graceful shutdown signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("NFCheck Server starting",
			"version", version,
			"addr", *addr,
			"workers", workerCount,
			"rpm", *ratePerMin,
			"cpus", runtime.NumCPU(),
		)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Server fatal error", "error", err)
			os.Exit(1)
		}
	}()

	<-stop
	slog.Info("Shutdown signal received, draining active connections...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
	} else {
		slog.Info("NFCheck Server exited gracefully")
	}
}

// defaultAddr determines the default listening address.
// It prioritizes Render's PORT environment variable, then ADDR, and falls back to 0.0.0.0:8080.
func defaultAddr() string {
	if port := os.Getenv("PORT"); port != "" {
		port = strings.TrimSpace(port)
		if strings.HasPrefix(port, ":") {
			return "0.0.0.0" + port
		}
		return "0.0.0.0:" + port
	}
	if addr := os.Getenv("ADDR"); addr != "" {
		addr = strings.TrimSpace(addr)
		if strings.HasPrefix(addr, ":") {
			return "0.0.0.0" + addr
		}
		return addr
	}
	return "0.0.0.0:8080"
}

// defaultWorkers determines the default worker count.
// It prioritizes WORKERS, falls back to CONCURRENCY, and defaults to 300.
func defaultWorkers() int {
	if w := envInt("WORKERS", 0); w > 0 {
		return w
	}
	if c := envInt("CONCURRENCY", 0); c > 0 {
		return c
	}
	return defaultWorkersCount
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var i int
	fmt.Sscanf(v, "%d", &i)
	if i <= 0 {
		return def
	}
	return i
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v == "true" || v == "1" || v == "yes"
}
