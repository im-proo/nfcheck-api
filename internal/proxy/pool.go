// Package proxy manages the rotating proxy pool.
// Supports formats: ip:port, user:pass@ip:port, http://ip:port,
// http://user:pass@ip:port, socks5://user:pass@ip:port and the bare
// datacenter forms ip:port:user:pass / user:pass:ip:port
package proxy

import (
	"bufio"
	"crypto/tls"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Proxy — a single proxy entry with latency and success/failure tracking
// ---------------------------------------------------------------------------

// Proxy is a single proxy entry.
type Proxy struct {
	Raw    string
	URL    *url.URL
	Scheme string
	Host   string
	Port   string
	User   string
	Pass   string
	Dead   uint32 // atomic: 1 = dead
	Fails  int32  // atomic fail counter

	LastUsed int64 // unix nano (atomic)

	// --- Latency tracking (exponential moving average) ---
	// AvgLatencyNs stores the EMA in nanoseconds as an atomic int64.
	AvgLatencyNs int64 // atomic

	// --- Success / failure counters ---
	SuccessCount int64 // atomic
	FailCount    int64 // atomic

	// --- Timestamps ---
	LastSuccess int64 // atomic: unix nano of last successful use
	LastFail    int64 // atomic: unix nano of last failure

	// deadSince stores the unix-nano timestamp of when this proxy was marked
	// dead. 0 means it has never been marked dead (or has been revived).
	deadSince int64 // atomic

	// removed is set to 1 when permanently removed via Pool.Remove.
	removed uint32 // atomic
}

func (p *Proxy) MarkDead() {
	if atomic.CompareAndSwapUint32(&p.Dead, 0, 1) {
		atomic.StoreInt64(&p.deadSince, time.Now().UnixNano())
	}
}

func (p *Proxy) IsAlive() bool {
	return atomic.LoadUint32(&p.Dead) == 0 && atomic.LoadUint32(&p.removed) == 0
}

func (p *Proxy) IncrFail() int32 { return atomic.AddInt32(&p.Fails, 1) }
func (p *Proxy) ResetFails()     { atomic.StoreInt32(&p.Fails, 0) }
func (p *Proxy) isRemoved() bool { return atomic.LoadUint32(&p.removed) == 1 }

// AvgLatencyMs returns the exponential moving average latency in milliseconds.
func (p *Proxy) AvgLatencyMs() float64 {
	ns := atomic.LoadInt64(&p.AvgLatencyNs)
	if ns <= 0 {
		return 0
	}
	return float64(ns) / float64(time.Millisecond)
}

// recordLatency updates the EMA with alpha ≈ 0.3 (lock-free CAS loop).
// Alpha of 0.3 gives ~70% weight to history, 30% to the new sample,
// making it responsive to recent changes without being too noisy.
func (p *Proxy) recordLatency(d time.Duration) {
	newNs := d.Nanoseconds()
	if newNs <= 0 {
		return
	}
	const alphaNum, alphaDen = 3, 10 // alpha = 0.3
	for {
		old := atomic.LoadInt64(&p.AvgLatencyNs)
		var updated int64
		if old <= 0 {
			// First sample — seed the average.
			updated = newNs
		} else {
			// EMA: new = old*(1-alpha) + sample*alpha
			updated = old*(alphaDen-alphaNum)/alphaDen + newNs*alphaNum/alphaDen
		}
		if atomic.CompareAndSwapInt64(&p.AvgLatencyNs, old, updated) {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// PoolStats — returned by Pool.Stats()
// ---------------------------------------------------------------------------

// ProxyStats holds per-proxy statistics.
type ProxyStats struct {
	Raw          string  `json:"raw"`
	Alive        bool    `json:"alive"`
	Removed      bool    `json:"removed"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
	SuccessCount int64   `json:"success_count"`
	FailCount    int64   `json:"fail_count"`
	ConsecFails  int32   `json:"consecutive_fails"`
	LastSuccess  string  `json:"last_success,omitempty"` // RFC3339Nano or ""
	LastFail     string  `json:"last_fail,omitempty"`    // RFC3339Nano or ""
}

// PoolStats holds aggregate pool statistics.
type PoolStats struct {
	Total      int          `json:"total"`
	Alive      int          `json:"alive"`
	Dead       int          `json:"dead"`
	Removed    int          `json:"removed"`
	AvgLatency float64      `json:"avg_latency_ms"` // across alive proxies
	Proxies    []ProxyStats `json:"proxies"`
}

// ---------------------------------------------------------------------------
// Pool — thread-safe rotating proxy pool
// ---------------------------------------------------------------------------

// slicePool is used by Random() to avoid allocating temporary slices.
var slicePool = sync.Pool{
	New: func() any {
		s := make([]*Proxy, 0, 64)
		return &s
	},
}

// Pool manages a thread-safe rotating list of proxies.
type Pool struct {
	mu      sync.RWMutex
	proxies []*Proxy
	cursor  uint64
	maxFail int32

	// aliveCount is an atomic counter maintained by MarkDead / revive
	// operations so that Alive() is O(1).
	aliveCount int64
}

// NewPool creates an empty pool. maxFailsBeforeDead: how many consecutive
// failures before a proxy is marked dead.
func NewPool(maxFailsBeforeDead int) *Pool {
	if maxFailsBeforeDead <= 0 {
		maxFailsBeforeDead = 3
	}
	return &Pool{maxFail: int32(maxFailsBeforeDead)}
}

// LoadReport describes what LoadFromString accepted.
type LoadReport struct {
	Loaded int
	// Rejected holds the 1-based line numbers that could not be parsed.
	// Line numbers (not the lines themselves) are reported so proxy
	// credentials never travel back out in an API response or a log line.
	Rejected []int
}

// LoadFromString parses a newline-separated proxy list. It replaces the
// whole pool, so an empty list clears it. Blank lines and '#' comments are
// ignored; unparsable lines are counted in the report instead of silently
// disappearing.
func (p *Pool) LoadFromString(raw string) LoadReport {
	var proxies []*Proxy
	var rejected []int
	sc := bufio.NewScanner(strings.NewReader(raw))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if px := parseProxy(line); px != nil {
			proxies = append(proxies, px)
		} else {
			rejected = append(rejected, lineNo)
		}
	}
	if len(rejected) > 25 {
		rejected = rejected[:25]
	}
	p.mu.Lock()
	p.proxies = proxies
	p.mu.Unlock()
	atomic.StoreInt64(&p.aliveCount, int64(len(proxies)))
	return LoadReport{Loaded: len(proxies), Rejected: rejected}
}

// Alive returns the number of alive (non-dead, non-removed) proxies.
// This is O(1) because the count is maintained atomically.
func (p *Pool) Alive() int {
	n := atomic.LoadInt64(&p.aliveCount)
	if n < 0 {
		return 0
	}
	return int(n)
}

// Total returns total proxy count (including removed).
func (p *Pool) Total() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.proxies)
}

// Next returns the next alive proxy in round-robin fashion.
// Returns nil if no alive proxies are available.
func (p *Pool) Next() *Proxy {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := len(p.proxies)
	if n == 0 {
		return nil
	}
	start := atomic.AddUint64(&p.cursor, 1)
	for i := 0; i < n; i++ {
		idx := (int(start) + i) % n
		px := p.proxies[idx]
		if px.IsAlive() {
			atomic.StoreInt64(&px.LastUsed, time.Now().UnixNano())
			return px
		}
	}
	return nil
}

// Random returns a random alive proxy (useful for load distribution).
// Uses sync.Pool for the temporary alive-list slice to reduce GC pressure.
func (p *Pool) Random() *Proxy {
	// Borrow a slice from the pool.
	sp := slicePool.Get().(*[]*Proxy)
	alive := (*sp)[:0]

	p.mu.RLock()
	for _, px := range p.proxies {
		if px.IsAlive() {
			alive = append(alive, px)
		}
	}
	p.mu.RUnlock()

	var result *Proxy
	if len(alive) > 0 {
		result = alive[rand.IntN(len(alive))]
	}

	// Clear references before returning to pool (help GC).
	for i := range alive {
		alive[i] = nil
	}
	*sp = alive[:0]
	slicePool.Put(sp)
	return result
}

// SmartNext picks the best proxy among a random sample of alive proxies
// using the "power of two choices" approach extended to 3 candidates.
// Among 3 randomly-sampled alive proxies, it returns the one with the
// lowest average latency. This gives near-optimal load balancing without
// the overhead of sorting the entire proxy list.
// Returns nil if no alive proxies are available.
func (p *Pool) SmartNext() *Proxy {
	const sampleSize = 3

	sp := slicePool.Get().(*[]*Proxy)
	alive := (*sp)[:0]

	p.mu.RLock()
	for _, px := range p.proxies {
		if px.IsAlive() {
			alive = append(alive, px)
		}
	}
	p.mu.RUnlock()

	var result *Proxy
	n := len(alive)
	switch {
	case n == 0:
		// no alive proxies
	case n <= sampleSize:
		// Pool is tiny — just pick the lowest latency among all.
		result = alive[0]
		best := atomic.LoadInt64(&result.AvgLatencyNs)
		for _, px := range alive[1:] {
			lat := atomic.LoadInt64(&px.AvgLatencyNs)
			// Treat 0 (no data) as better than any known latency so new
			// proxies get a chance to be tested.
			if best != 0 && (lat == 0 || lat < best) {
				best = lat
				result = px
			}
		}
	default:
		// Sample `sampleSize` distinct random proxies.
		indices := [sampleSize]int{}
		indices[0] = rand.IntN(n)
		for i := 1; i < sampleSize; i++ {
			for {
				idx := rand.IntN(n)
				unique := true
				for j := 0; j < i; j++ {
					if indices[j] == idx {
						unique = false
						break
					}
				}
				if unique {
					indices[i] = idx
					break
				}
			}
		}
		result = alive[indices[0]]
		best := atomic.LoadInt64(&result.AvgLatencyNs)
		for _, idx := range indices[1:] {
			px := alive[idx]
			lat := atomic.LoadInt64(&px.AvgLatencyNs)
			if best != 0 && (lat == 0 || lat < best) {
				best = lat
				result = px
			}
		}
	}

	if result != nil {
		atomic.StoreInt64(&result.LastUsed, time.Now().UnixNano())
	}

	// Return slice to pool.
	for i := range alive {
		alive[i] = nil
	}
	*sp = alive[:0]
	slicePool.Put(sp)
	return result
}

// ReportFail notifies the pool that a proxy had a failure.
// After maxFail consecutive failures the proxy is marked dead.
// Also records the failure timestamp and updates latency EMA.
func (p *Pool) ReportFail(px *Proxy) {
	atomic.AddInt64(&px.FailCount, 1)
	atomic.StoreInt64(&px.LastFail, time.Now().UnixNano())
	fails := px.IncrFail()
	if fails >= p.maxFail {
		wasAlive := px.IsAlive()
		px.MarkDead()
		if wasAlive && !px.IsAlive() {
			atomic.AddInt64(&p.aliveCount, -1)
		}
	}
}

// ReportSuccess resets fail counter for a proxy and records success
// timestamp and latency. `d` is the duration of the request that used
// this proxy.
func (p *Pool) ReportSuccess(px *Proxy) {
	px.ResetFails()
	atomic.AddInt64(&px.SuccessCount, 1)
	atomic.StoreInt64(&px.LastSuccess, time.Now().UnixNano())
}

// ReportLatency records a latency observation for the proxy.
// Call this in addition to ReportSuccess/ReportFail to track latency.
func (p *Pool) ReportLatency(px *Proxy, d time.Duration) {
	px.recordLatency(d)
}

// ReviveAll resets all dead proxies (call periodically to allow re-testing).
// Permanently removed proxies are NOT revived.
func (p *Pool) ReviveAll() {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, px := range p.proxies {
		if px.isRemoved() {
			continue
		}
		if atomic.CompareAndSwapUint32(&px.Dead, 1, 0) {
			atomic.StoreInt64(&px.deadSince, 0)
			atomic.StoreInt32(&px.Fails, 0)
			atomic.AddInt64(&p.aliveCount, 1)
		}
	}
}

// ReviveDead revives only proxies that have been dead for longer than maxAge.
// Permanently removed proxies are NOT revived. This is less aggressive than
// ReviveAll and is suitable for periodic recovery of proxies that may have
// had transient failures.
func (p *Pool) ReviveDead(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge).UnixNano()
	revived := 0

	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, px := range p.proxies {
		if px.isRemoved() {
			continue
		}
		if atomic.LoadUint32(&px.Dead) == 0 {
			continue // already alive
		}
		ds := atomic.LoadInt64(&px.deadSince)
		if ds > 0 && ds <= cutoff {
			if atomic.CompareAndSwapUint32(&px.Dead, 1, 0) {
				atomic.StoreInt64(&px.deadSince, 0)
				atomic.StoreInt32(&px.Fails, 0)
				atomic.AddInt64(&p.aliveCount, 1)
				revived++
			}
		}
	}
	return revived
}

// Remove permanently removes a proxy identified by its raw string.
// The proxy is marked as removed and will not be revived by ReviveAll
// or ReviveDead. Returns true if the proxy was found and removed.
func (p *Pool) Remove(raw string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, px := range p.proxies {
		if px.Raw == raw && !px.isRemoved() {
			wasAlive := px.IsAlive()
			atomic.StoreUint32(&px.removed, 1)
			atomic.StoreUint32(&px.Dead, 1)
			if wasAlive {
				atomic.AddInt64(&p.aliveCount, -1)
			}
			return true
		}
	}
	return false
}

// Stats returns aggregate and per-proxy statistics for the pool.
func (p *Pool) Stats() PoolStats {
	p.mu.RLock()
	proxies := make([]*Proxy, len(p.proxies))
	copy(proxies, p.proxies)
	p.mu.RUnlock()

	stats := PoolStats{
		Total:   len(proxies),
		Proxies: make([]ProxyStats, 0, len(proxies)),
	}

	var latencySum float64
	var latencyCount int

	for _, px := range proxies {
		isRemoved := px.isRemoved()
		isAlive := px.IsAlive()

		ps := ProxyStats{
			Raw:          px.Raw,
			Alive:        isAlive,
			Removed:      isRemoved,
			AvgLatencyMs: px.AvgLatencyMs(),
			SuccessCount: atomic.LoadInt64(&px.SuccessCount),
			FailCount:    atomic.LoadInt64(&px.FailCount),
			ConsecFails:  atomic.LoadInt32(&px.Fails),
		}

		if ls := atomic.LoadInt64(&px.LastSuccess); ls > 0 {
			ps.LastSuccess = time.Unix(0, ls).UTC().Format(time.RFC3339Nano)
		}
		if lf := atomic.LoadInt64(&px.LastFail); lf > 0 {
			ps.LastFail = time.Unix(0, lf).UTC().Format(time.RFC3339Nano)
		}

		if isAlive {
			stats.Alive++
			if ps.AvgLatencyMs > 0 {
				latencySum += ps.AvgLatencyMs
				latencyCount++
			}
		} else if isRemoved {
			stats.Removed++
			stats.Dead++ // removed proxies are also dead
		} else {
			stats.Dead++
		}

		stats.Proxies = append(stats.Proxies, ps)
	}

	if latencyCount > 0 {
		stats.AvgLatency = latencySum / float64(latencyCount)
	}

	return stats
}

// ProxyTransport returns a pre-configured *http.Transport that uses the
// given proxy. The transport is set up with sensible connection pooling
// parameters for high-throughput checking. The caller should reuse the
// transport across requests to the same proxy to benefit from connection
// reuse and keep-alive.
//
// Returns nil if px is nil.
func ProxyTransport(px *Proxy) *http.Transport {
	if px == nil {
		return nil
	}
	tr := &http.Transport{
		Proxy: http.ProxyURL(px.URL),
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       0, // unlimited
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
		DisableCompression:    false,
		DisableKeepAlives:     false,
	}
	return tr
}

// -----------------------------------------------------------------
// Proxy string parser – handles all common formats
// -----------------------------------------------------------------

func parseProxy(raw string) *Proxy {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	// Bare "ip:port:user:pass" (and "user:pass:ip:port") is the usual
	// datacenter list format: no scheme, no '@', so url.Parse cannot read
	// it. Handle it before the generic path.
	if !strings.Contains(raw, "://") && !strings.Contains(raw, "[") {
		if px := parseBareColon(raw); px != nil {
			return px
		}
	}

	px := &Proxy{Raw: raw}

	s := raw
	// Inject scheme if missing
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}

	u, err := url.Parse(s)
	if err != nil {
		return nil
	}

	px.Scheme = strings.ToLower(u.Scheme)
	if px.Scheme == "" {
		px.Scheme = "http"
	}
	px.Host = u.Hostname()
	px.Port = u.Port()
	if u.User != nil {
		px.User = u.User.Username()
		px.Pass, _ = u.User.Password()
	}

	if px.Host == "" || px.Port == "" {
		return nil
	}

	// Build the dialable URL structurally instead of re-parsing a string, so
	// passwords containing ':', '@', '%' or spaces survive byte for byte.
	finalURL := &url.URL{
		Scheme: px.Scheme,
		Host:   net.JoinHostPort(px.Host, px.Port),
	}
	if px.User != "" {
		finalURL.User = url.UserPassword(px.User, px.Pass)
	}
	px.URL = finalURL
	return px
}

// parseBareColon understands the colon-separated proxy list formats:
//
//	ip:port:user:pass        (password may itself contain ':')
//	user:pass:ip:port
func parseBareColon(raw string) *Proxy {
	parts := strings.Split(raw, ":")
	if len(parts) < 4 {
		return nil
	}

	// ip:port:user:pass
	if isPortToken(parts[1]) && looksLikeHost(parts[0]) {
		user := parts[2]
		pass := strings.Join(parts[3:], ":")
		if user == "" {
			return nil
		}
		return buildBareProxy(raw, parts[0], parts[1], user, pass)
	}

	// user:pass:ip:port
	if len(parts) == 4 && isPortToken(parts[3]) && looksLikeHost(parts[2]) {
		if parts[0] == "" || parts[1] == "" {
			return nil
		}
		return buildBareProxy(raw, parts[2], parts[3], parts[0], parts[1])
	}

	return nil
}

func buildBareProxy(raw, host, port, user, pass string) *Proxy {
	px := &Proxy{
		Raw:    raw,
		Scheme: "http",
		Host:   host,
		Port:   port,
		User:   user,
		Pass:   pass,
	}
	px.URL = &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(host, port),
		User:   url.UserPassword(user, pass),
	}
	return px
}

// isPortToken reports whether s is a plain numeric TCP port.
func isPortToken(s string) bool {
	if s == "" || len(s) > 5 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// looksLikeHost reports whether s can be the address part of a proxy entry.
// Hostnames and IPv4 addresses contain a '.', so a user name or a password
// in the same position is not mistaken for one.
func looksLikeHost(s string) bool {
	if s == "" {
		return false
	}
	// A user name or password segment can contain a '.' too; only accept a
	// token that could really be an address.
	if strings.ContainsAny(s, "@/? \t") {
		return false
	}
	return s == "localhost" || strings.Contains(s, ".")
}
