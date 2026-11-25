package proxyscan

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nfchecker/internal/proxy"
)

// startConnectProxy runs a minimal HTTP CONNECT proxy that forwards to the
// host the client asked for, so a scan can be tested without the internet.
func startConnectProxy(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		up, err := net.DialTimeout("tcp", r.Host, 3*time.Second)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer up.Close()
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		client, _, err := hj.Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(up, client); done <- struct{}{} }()
		go func() { _, _ = io.Copy(client, up); done <- struct{}{} }()
		<-done
	}))
}

func TestScanKeepsOnlyWorkingProxiesFastestFirst(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(strings.Repeat("<html>netflix</html>", 500)))
	}))
	defer target.Close()

	good := startConnectProxy(t)
	defer good.Close()

	goodRaw := "http://" + strings.TrimPrefix(good.URL, "http://")
	deadRaw := "http://127.0.0.1:1"
	notAProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer notAProxy.Close()

	candidates := []*proxy.Proxy{
		proxy.Parse(goodRaw),
		proxy.Parse(deadRaw),
		proxy.Parse(notAProxy.URL),
		nil,
	}

	rep := Scan(context.Background(), candidates, Options{
		Concurrency:  4,
		DialTimeout:  time.Second,
		ProbeTimeout: 3 * time.Second,
		MaxLatency:   5 * time.Second,
		Target:       target.URL,
	})

	if len(rep.Alive) != 1 {
		t.Fatalf("expected exactly 1 alive proxy, got %d (rejected=%v)", len(rep.Alive), rep.Rejected)
	}
	if rep.Alive[0].Proxy.Raw != goodRaw {
		t.Fatalf("wrong survivor: %s", rep.Alive[0].Proxy.Raw)
	}
	if rep.Alive[0].Latency <= 0 {
		t.Fatal("latency not measured")
	}
	if rep.Tested != 4 {
		t.Fatalf("tested=%d want 4", rep.Tested)
	}
	if rep.Rejected["unparsable"] != 1 {
		t.Fatalf("nil proxy should be rejected as unparsable: %v", rep.Rejected)
	}
}

func TestScanRejectsSlowProxies(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(150 * time.Millisecond)
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	good := startConnectProxy(t)
	defer good.Close()

	rep := Scan(context.Background(), []*proxy.Proxy{proxy.Parse("http://" + strings.TrimPrefix(good.URL, "http://"))}, Options{
		Concurrency:  1,
		DialTimeout:  time.Second,
		ProbeTimeout: 3 * time.Second,
		MaxLatency:   50 * time.Millisecond,
		Target:       target.URL,
	})
	if len(rep.Alive) != 0 || rep.Rejected["slow"] != 1 {
		t.Fatalf("slow proxy should be rejected: alive=%d rejected=%v", len(rep.Alive), rep.Rejected)
	}
}
