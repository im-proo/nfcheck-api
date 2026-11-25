// Package proxysrc harvests proxy candidates from public proxy lists.
//
// Nothing here is trusted. A list entry is only a hint that is handed to
// proxyscan, which decides whether the proxy is reachable, fast and accepted
// by Netflix before it ever enters the pool.
package proxysrc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nfchecker/internal/proxy"
)

// Kind is how a source body is parsed.
type Kind int

const (
	// KindText is one proxy per line, with or without a scheme:
	// 1.2.3.4:8080, 1.2.3.4:8080:user:pass, http://1.2.3.4:8080.
	KindText Kind = iota
	// KindHTML is a page that lists ip:port pairs in its markup.
	KindHTML
	// KindGeonode is geonode's JSON proxy API.
	KindGeonode
)

// Source is one public list.
type Source struct {
	Name string
	URL  string
	Kind Kind
}

// DefaultSources is the set harvested when the caller names none. GitHub raw
// lists rotate fastest, the APIs behind them refresh hourly, and the HTML
// pages cover the "free proxy list" sites that publish no feed.
func DefaultSources() []Source {
	return []Source{
		{"thespeedx-http", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", KindText},
		{"thespeedx-socks5", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", KindText},
		{"monosans-http", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", KindText},
		{"monosans-socks5", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", KindText},
		{"proxifly-all", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt", KindText},
		{"clarketm-http", "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt", KindText},
		{"mmpx12-http", "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt", KindText},
		{"mmpx12-socks5", "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt", KindText},
		{"roosterkid-https", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt", KindText},
		{"hookzof-socks5", "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt", KindText},
		{"proxyscrape-http", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all", KindText},
		{"proxyscrape-socks5", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all", KindText},
		{"proxylist-download-http", "https://www.proxy-list.download/api/v1/get?type=http", KindText},
		{"proxylist-download-socks5", "https://www.proxy-list.download/api/v1/get?type=socks5", KindText},
		{"geonode", "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc", KindGeonode},
		{"hidemy-name", "https://hidemy.name/en/proxy-list/", KindHTML},
		{"hide-me", "https://hide.me/en/proxy", KindHTML},
	}
}

// Options configures one harvest.
type Options struct {
	Timeout      time.Duration
	MaxPerSource int
	Sources      []Source
}

// SourceStat is what one source contributed.
type SourceStat struct {
	Name    string `json:"name"`
	Fetched int    `json:"fetched"`
	Kept    int    `json:"kept"`
	Err     string `json:"error,omitempty"`
}

// Result is the harvest output.
type Result struct {
	Candidates []*proxy.Proxy
	Stats      []SourceStat
}

var (
	ipPortRe   = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}`)
	urlRe      = regexp.MustCompile(`(?i)\b(?:https?|socks4|socks5)://[^\s"'<>,]+`)
	cellPairRe = regexp.MustCompile(`(?is)>\s*((?:\d{1,3}\.){3}\d{1,3})\s*<\s*/t[dh]\s*>\s*<t[dh][^>]*>\s*(\d{2,5})\s*<`)
)

// Harvest fetches every source concurrently and returns deduplicated
// candidates. A failing source is reported in Stats and never aborts the run.
func Harvest(ctx context.Context, opt Options) Result {
	if opt.Timeout <= 0 {
		opt.Timeout = 12 * time.Second
	}
	if opt.MaxPerSource <= 0 {
		opt.MaxPerSource = 2000
	}
	sources := opt.Sources
	if len(sources) == 0 {
		sources = DefaultSources()
	}

	client := &http.Client{Timeout: opt.Timeout}
	stats := make([]SourceStat, len(sources))
	lists := make([][]*proxy.Proxy, len(sources))

	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, src := range sources {
		wg.Add(1)
		go func(i int, src Source) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				stats[i] = SourceStat{Name: src.Name, Err: "cancelled"}
				return
			}
			stats[i], lists[i] = fetchOne(ctx, client, src, opt.MaxPerSource)
		}(i, src)
	}
	wg.Wait()

	seen := make(map[string]struct{}, 8192)
	out := make([]*proxy.Proxy, 0, 8192)
	for i := range lists {
		for _, px := range lists[i] {
			key := proxyKey(px)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, px)
		}
	}
	return Result{Candidates: out, Stats: stats}
}

func fetchOne(ctx context.Context, client *http.Client, src Source, max int) (SourceStat, []*proxy.Proxy) {
	stat := SourceStat{Name: src.Name}

	req, err := http.NewRequestWithContext(ctx, "GET", src.URL, nil)
	if err != nil {
		stat.Err = shortErr(err)
		return stat, nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/plain,text/html,application/json;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		stat.Err = shortErr(err)
		return stat, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		stat.Err = fmt.Sprintf("status %d", resp.StatusCode)
		return stat, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		stat.Err = shortErr(err)
		return stat, nil
	}

	var raws []string
	switch src.Kind {
	case KindHTML:
		raws = ParseHTML(string(body))
	case KindGeonode:
		raws = ParseGeonode(body)
	default:
		raws = ParseText(string(body))
	}
	stat.Fetched = len(raws)

	list := make([]*proxy.Proxy, 0, len(raws))
	local := make(map[string]struct{}, len(raws))
	for _, raw := range raws {
		if len(list) >= max {
			break
		}
		px := proxy.Parse(raw)
		if px == nil || !Usable(px) {
			continue
		}
		key := proxyKey(px)
		if _, dup := local[key]; dup {
			continue
		}
		local[key] = struct{}{}
		list = append(list, px)
	}
	stat.Kept = len(list)
	return stat, list
}

// ParseText reads a plain list. A line that is a single token is taken whole,
// so credential forms (ip:port:user:pass) survive; anything else is scanned
// for a usable ip:port.
func ParseText(body string) []string {
	lines := strings.Split(body, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		line = strings.Trim(line, `",;`)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if m := urlRe.FindString(line); m != "" {
			out = append(out, m)
			continue
		}
		if !strings.ContainsAny(line, " \t,;\"'<>") {
			out = append(out, line)
			continue
		}
		if m := ipPortRe.FindString(line); m != "" {
			out = append(out, m)
		}
	}
	return out
}

// ParseHTML pulls ip:port pairs out of a list page, including the common
// separate-cell layout (<td>1.2.3.4</td><td>8080</td>).
func ParseHTML(body string) []string {
	out := ipPortRe.FindAllString(body, -1)
	for _, m := range cellPairRe.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1]+":"+m[2])
	}
	return out
}

type flexibleString string

func (f *flexibleString) UnmarshalJSON(b []byte) error {
	*f = flexibleString(strings.Trim(string(b), `"`))
	return nil
}

// ParseGeonode reads geonode's {"data":[{"ip":..,"port":..,"protocols":[..]}]}.
func ParseGeonode(body []byte) []string {
	var payload struct {
		Data []struct {
			IP        string         `json:"ip"`
			Port      flexibleString `json:"port"`
			Protocols []string       `json:"protocols"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil
	}
	out := make([]string, 0, len(payload.Data))
	for _, row := range payload.Data {
		if row.IP == "" || row.Port == "" {
			continue
		}
		scheme := "http"
		for _, p := range row.Protocols {
			p = strings.ToLower(strings.TrimSpace(p))
			if p == "socks4" || p == "socks5" || p == "http" {
				scheme = p
				break
			}
		}
		out = append(out, fmt.Sprintf("%s://%s:%s", scheme, row.IP, row.Port))
	}
	return out
}

// Usable rejects entries that can never be used: private, loopback and
// reserved addresses ("0.0.0.0:8080" and "127.0.0.1:8080" show up in bad
// lists) and impossible ports.
func Usable(px *proxy.Proxy) bool {
	if px == nil || px.Host == "" || px.Port == "" {
		return false
	}
	var port int
	if _, err := fmt.Sscanf(px.Port, "%d", &port); err != nil || port < 1 || port > 65535 {
		return false
	}
	if ip := net.ParseIP(px.Host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
			ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
			return false
		}
	}
	if strings.HasPrefix(px.Host, "0.") || strings.HasPrefix(px.Host, "255.") {
		return false
	}
	return true
}

func proxyKey(px *proxy.Proxy) string {
	if px == nil {
		return ""
	}
	return px.Scheme + "|" + px.Host + "|" + px.Port + "|" + px.User
}

func shortErr(err error) string {
	msg := strings.Join(strings.Fields(err.Error()), " ")
	if len(msg) > 120 {
		msg = msg[:120]
	}
	return msg
}
