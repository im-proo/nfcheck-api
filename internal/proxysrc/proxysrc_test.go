package proxysrc

import (
	"context"
	"strings"
	"testing"

	"github.com/nfchecker/internal/proxy"
)

func TestParseTextKeepsCredentials(t *testing.T) {
	body := strings.Join([]string{
		"# free list",
		"1.2.3.4:8080",
		"5.6.7.8:3128:alice:s3cret",
		"9.9.9.9:1080 bob 12%",  // comment column: bare ip:port survives
		"http://10.0.0.1:8000/", // private, must be filtered later
		"",
	}, "\n")

	got := ParseText(body)
	want := []string{"1.2.3.4:8080", "5.6.7.8:3128:alice:s3cret", "9.9.9.9:1080", "http://10.0.0.1:8000/"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d: got %q want %q", i, got[i], want[i])
		}
	}

	if px := proxy.Parse(got[1]); px == nil || px.User != "alice" || px.Pass != "s3cret" {
		t.Fatalf("credentials lost: %+v", px)
	}
}

func TestParseHTMLAndGeonode(t *testing.T) {
	html := `<table><tr><td>1.2.3.4</td><td>8080</td></tr>
<tr><td>5.6.7.8:3128</td><td>HTTPS</td></tr></table>`
	// Order is irrelevant (candidates are deduplicated later); both layouts
	// must be found.
	found := map[string]bool{}
	for _, raw := range ParseHTML(html) {
		found[raw] = true
	}
	if !found["1.2.3.4:8080"] || !found["5.6.7.8:3128"] {
		t.Fatalf("html parse missed a layout: %v", found)
	}

	js := []byte(`{"data":[{"ip":"1.1.1.1","port":"8080","protocols":["socks5"]},{"ip":"2.2.2.2","port":3128,"protocols":["http"]}]}`)
	got := ParseGeonode(js)
	want := []string{"socks5://1.1.1.1:8080", "http://2.2.2.2:3128"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("geonode parse: %v", got)
	}
}

func TestUsableRejectsJunk(t *testing.T) {
	bad := []string{"127.0.0.1:8080", "0.0.0.0:80", "192.168.1.5:3128", "10.1.2.3:9000", "1.2.3.4:0", "1.2.3.4:99999"}
	for _, raw := range bad {
		if px := proxy.Parse(raw); px != nil && Usable(px) {
			t.Fatalf("%s should not be usable", raw)
		}
	}
	if px := proxy.Parse("8.8.8.8:8080"); px == nil || !Usable(px) {
		t.Fatal("public proxy should be usable")
	}
}

func TestHarvestReportsFailingSource(t *testing.T) {
	res := Harvest(context.Background(), Options{
		Timeout: 1500_000_000, // 1.5s
		Sources: []Source{{Name: "dead", URL: "http://127.0.0.1:1/list.txt", Kind: KindText}},
	})
	if len(res.Candidates) != 0 {
		t.Fatalf("expected no candidates, got %d", len(res.Candidates))
	}
	if len(res.Stats) != 1 || res.Stats[0].Err == "" {
		t.Fatalf("expected a reported error, got %+v", res.Stats)
	}
}
