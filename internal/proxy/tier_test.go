package proxy

import "testing"

func TestConfiguredProxiesBeatScrapedOnes(t *testing.T) {
	p := NewPool(1) // one failure marks dead, to make the switch quick
	p.LoadFromString("http://1.2.3.4:8080")

	scraped := Parse("http://5.6.7.8:3128")
	if scraped == nil {
		t.Fatal("parse failed")
	}
	if replaced := p.ReplaceSource(SourceScrape, []*Proxy{scraped}); replaced != 0 {
		t.Fatalf("nothing to replace yet, got %d", replaced)
	}
	if p.Total() != 2 || p.Alive() != 2 {
		t.Fatalf("total=%d alive=%d", p.Total(), p.Alive())
	}

	for i := 0; i < 3; i++ {
		px := p.Next()
		if px == nil || px.Host != "1.2.3.4" {
			t.Fatalf("configured proxy must be used first, got %+v", px)
		}
	}

	// Kill the configured proxy: the scraped tier becomes usable.
	p.ReportFail(p.Next())
	if got := p.Next(); got == nil || got.Host != "5.6.7.8" {
		t.Fatalf("expected scraped fallback, got %+v", got)
	}
	if got := p.CountSource(SourceScrape, true); got != 1 {
		t.Fatalf("scrape alive count = %d", got)
	}

	// A fresh harvest replaces the scrape tier without touching the rest.
	fresh := Parse("http://9.9.9.9:1080")
	if replaced := p.ReplaceSource(SourceScrape, []*Proxy{fresh}); replaced != 1 {
		t.Fatalf("replaced = %d, want 1", replaced)
	}
	if p.CountSource(SourceScrape, false) != 1 {
		t.Fatalf("scrape tier should hold exactly one proxy")
	}
	if got := p.Stats().Total; got != 2 {
		t.Fatalf("manual proxy must survive a scrape refresh, total=%d", got)
	}
}

func TestScrapedProxyIsNotRevived(t *testing.T) {
	p := NewPool(1)
	scraped := Parse("http://5.6.7.8:3128")
	p.ReplaceSource(SourceScrape, []*Proxy{scraped})
	p.ReportFail(p.Next())
	if p.Alive() != 0 {
		t.Fatalf("alive = %d, want 0", p.Alive())
	}
	if revived := p.ReviveDead(0); revived != 0 {
		t.Fatalf("scraped proxy must not be revived, revived=%d", revived)
	}
}

func TestSetLatencySeedsAverage(t *testing.T) {
	px := Parse("http://1.2.3.4:8080")
	px.SetLatency(120_000_000) // 120ms
	if got := px.AvgLatencyMs(); got < 119 || got > 121 {
		t.Fatalf("avg latency = %v", got)
	}
}
