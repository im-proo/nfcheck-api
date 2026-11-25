// Package proxyscan decides which harvested proxies are worth using.
//
// Free proxy lists are mostly dead, slow or already blocked by Netflix, so
// every candidate is dialled and forced through a real TLS request to a
// Netflix page. Only proxies that answer quickly with a usable status survive.
package proxyscan

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nfchecker/internal/proxy"
)

// DefaultTarget is probed through each proxy. A real Netflix page is used on
// purpose: a proxy that reaches the open internet but is blocked by Netflix
// must be rejected here, not in the middle of a check.
const DefaultTarget = "https://www.netflix.com/"

// Options tunes a scan. Zero values fall back to the defaults below.
type Options struct {
	Concurrency  int
	DialTimeout  time.Duration
	ProbeTimeout time.Duration
	MaxLatency   time.Duration
	Target       string
}

func (o *Options) defaults() {
	if o.Concurrency <= 0 {
		o.Concurrency = 300
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = 4 * time.Second
	}
	if o.ProbeTimeout <= 0 {
		o.ProbeTimeout = 8 * time.Second
	}
	if o.MaxLatency <= 0 {
		o.MaxLatency = 1500 * time.Millisecond
	}
	if o.Target == "" {
		o.Target = DefaultTarget
	}
}

// Hit is a proxy that passed the probe.
type Hit struct {
	Proxy   *proxy.Proxy
	Latency time.Duration
}

// Report is the outcome of one scan.
type Report struct {
	Tested   int
	Alive    []Hit
	Rejected map[string]int
	Duration time.Duration
}

var probeUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
}

// Scan probes every candidate concurrently and returns the survivors sorted
// by latency (fastest first).
func Scan(ctx context.Context, candidates []*proxy.Proxy, opt Options) Report {
	opt.defaults()
	start := time.Now()
	rep := Report{Rejected: map[string]int{}}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, opt.Concurrency)
	var tested int64
	var uaCounter uint64

loop:
	for _, px := range candidates {
		select {
		case <-ctx.Done():
			break loop
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(px *proxy.Proxy) {
			defer wg.Done()
			defer func() { <-sem }()

			atomic.AddInt64(&tested, 1)
			ua := probeUAs[atomic.AddUint64(&uaCounter, 1)%uint64(len(probeUAs))]
			lat, reason := probe(ctx, px, opt, ua)

			mu.Lock()
			defer mu.Unlock()
			if reason != "" {
				rep.Rejected[reason]++
				return
			}
			rep.Alive = append(rep.Alive, Hit{Proxy: px, Latency: lat})
		}(px)
	}
	wg.Wait()

	rep.Tested = int(tested)
	sort.Slice(rep.Alive, func(i, j int) bool {
		return rep.Alive[i].Latency < rep.Alive[j].Latency
	})
	rep.Duration = time.Since(start)
	return rep
}

// probe returns the measured latency and an empty reason on success.
func probe(ctx context.Context, px *proxy.Proxy, opt Options, ua string) (time.Duration, string) {
	if px == nil || px.URL == nil {
		return 0, "unparsable"
	}

	dialer := &net.Dialer{Timeout: opt.DialTimeout}
	tr := &http.Transport{
		Proxy:                 http.ProxyURL(px.URL),
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		TLSHandshakeTimeout:   opt.DialTimeout,
		ResponseHeaderTimeout: opt.ProbeTimeout,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		Timeout:   opt.ProbeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", opt.Target, nil)
	if err != nil {
		return 0, "request"
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip")

	begin := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, errorReason(err)
	}
	defer resp.Body.Close()

	// Pull a little actual page data: a proxy that returns headers and then
	// stalls mid-body is useless for a check, so it must not pass on headers.
	if _, err := io.CopyN(io.Discard, resp.Body, 2048); err != nil && err != io.EOF {
		return 0, "body"
	}

	lat := time.Since(begin)
	switch resp.StatusCode {
	case 200, 301, 302, 303, 307, 308:
		// Netflix answered through the proxy.
	case 407:
		return 0, "auth"
	case 403:
		return 0, "blocked"
	case 429:
		return 0, "throttled"
	default:
		return 0, "status"
	}
	if lat > opt.MaxLatency {
		return 0, "slow"
	}
	return lat, ""
}

func errorReason(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "proxyconnect") || strings.Contains(msg, "407") || strings.Contains(msg, "proxy authentication"):
		return "auth"
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline"):
		return "timeout"
	case strings.Contains(msg, "refused"):
		return "refused"
	case strings.Contains(msg, "certificate") || strings.Contains(msg, "tls"):
		return "tls"
	case strings.Contains(msg, "no such host"):
		return "dns"
	case strings.Contains(msg, "reset") || strings.Contains(msg, "eof"):
		return "reset"
	}
	return "dial"
}
