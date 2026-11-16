// Package models defines the core data types for the Netflix cookie checker.
package models

import (
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Cookie & Account types
// ---------------------------------------------------------------------------

// CookieSet holds a parsed Netflix session cookie.
type CookieSet struct {
	NetflixId       string `json:"netflix_id"`
	SecureNetflixId string `json:"secure_netflix_id"`
	NfvdId          string `json:"nfvdid"`
	OptanonConsent  string `json:"optanon_consent"`
	CookieExpires   int64  `json:"cookie_expires"`
	Raw             string `json:"raw,omitempty"`
	Fingerprint     string `json:"fingerprint"`
}

// AccountInfo is the fully-extracted Netflix account data.
type AccountInfo struct {
	Name             string   `json:"name"`
	Email            string   `json:"email"`
	Country          string   `json:"country"`
	CountryFlag      string   `json:"country_flag"`
	Plan             string   `json:"plan"`
	MemberSince      string   `json:"member_since"`
	NextBilling      string   `json:"next_billing"`
	Payment          string   `json:"payment"`
	Card             string   `json:"card"`
	Phone            string   `json:"phone"`
	VideoQuality     string   `json:"video_quality"`
	Streams          int      `json:"streams"`
	Price            string   `json:"price"`
	HoldStatus       string   `json:"hold_status"`
	ExtraMember      string   `json:"extra_member"`
	EmailVerified    string   `json:"email_verified"`
	MembershipStatus string   `json:"membership_status"`
	Profiles         []string `json:"profiles"`
	UserGUID         string   `json:"user_guid"`
	ValidTillUTC     string   `json:"valid_till_utc"`
	RemainingHours   int      `json:"remaining_hours"`
	RemainingMinutes int      `json:"remaining_minutes"`

	// Plan classification fields (accuracy improvements)
	IsOnHold           bool   `json:"is_on_hold"`
	PlanType           string `json:"plan_type"`           // "premium"/"standard"/"standard_with_ads"/"basic"/"basic_with_ads"/"unknown"
	IsAdsTier          bool   `json:"is_ads_tier"`         // true if plan contains "ads"
	MembershipCategory string `json:"membership_category"` // derived from PlanType
}

// NfToken holds the generated auto-login token.
type NfToken struct {
	Token     string `json:"token"`
	Expires   int64  `json:"expires"`
	PhoneLink string `json:"phone_link"`
	PCLink    string `json:"pc_link"`
	TVLink    string `json:"tv_link"`
}

// ---------------------------------------------------------------------------
// CheckResult + sync.Pool
// ---------------------------------------------------------------------------

// CheckResult is the final result for a single cookie check.
type CheckResult struct {
	Status     string       `json:"status"` // "hit", "expired", "error", "duplicate"
	Cookie     *CookieSet   `json:"cookie"`
	Account    *AccountInfo `json:"account,omitempty"`
	NfToken    *NfToken     `json:"nf_token,omitempty"`
	Error      string       `json:"error,omitempty"`
	ProxyUsed  string       `json:"proxy_used,omitempty"`
	CheckedAt  time.Time    `json:"checked_at"`
	DurationMs int64        `json:"duration_ms"`
}

// checkResultPool reduces GC pressure by reusing CheckResult allocations.
var checkResultPool = sync.Pool{
	New: func() any {
		return &CheckResult{}
	},
}

// AcquireCheckResult retrieves a zeroed CheckResult from the pool.
func AcquireCheckResult() *CheckResult {
	r := checkResultPool.Get().(*CheckResult)
	*r = CheckResult{}
	return r
}

// ReleaseCheckResult returns a CheckResult to the pool for reuse.
func ReleaseCheckResult(r *CheckResult) {
	if r == nil {
		return
	}
	r.Cookie = nil
	r.Account = nil
	r.NfToken = nil
	checkResultPool.Put(r)
}

// ---------------------------------------------------------------------------
// BatchResult — paginated hit list
// ---------------------------------------------------------------------------

// BatchResult carries a page of hits for the paginated hits endpoint.
type BatchResult struct {
	Hits      []*CheckResult `json:"hits"`
	Page      int            `json:"page"`
	PageSize  int            `json:"page_size"`
	TotalHits int            `json:"total_hits"`
}

// ---------------------------------------------------------------------------
// JobStatus — production-grade, lock-free counters + mutex-guarded fields
// ---------------------------------------------------------------------------

// JobStatus represents a submitted checking job.
type JobStatus struct {
	ID        string    `json:"id"`
	Total     int       `json:"total"`
	StartedAt time.Time `json:"started_at"`

	// --- atomic counters (no mutex required) ---
	Checked    atomic.Int64 `json:"-"`
	Hits       atomic.Int64 `json:"-"`
	Expired    atomic.Int64 `json:"-"`
	Errors     atomic.Int64 `json:"-"`
	Duplicates atomic.Int64 `json:"-"`

	// --- mutex-guarded fields ---
	Mu          sync.Mutex `json:"-"`
	Status      string     `json:"-"` // "pending","running","done","failed","cancelled"
	CompletedAt time.Time  `json:"-"`
	CurrentRPM  float64    `json:"-"`
	PeakRPM     float64    `json:"-"`

	// --- progress / diagnostics ---
	ETA             time.Duration `json:"-"`
	AvgCheckMs      int64         `json:"-"`
	MemoryUsedBytes int64         `json:"-"`
	WorkerCount     int           `json:"-"`
}

// ---------------------------------------------------------------------------
// Atomic increment helpers
// ---------------------------------------------------------------------------

func (j *JobStatus) IncrChecked()    { j.Checked.Add(1) }
func (j *JobStatus) IncrHits()       { j.Hits.Add(1) }
func (j *JobStatus) IncrExpired()    { j.Expired.Add(1) }
func (j *JobStatus) IncrErrors()     { j.Errors.Add(1) }
func (j *JobStatus) IncrDuplicates() { j.Duplicates.Add(1) }

// ---------------------------------------------------------------------------
// Mutex-guarded setters
// ---------------------------------------------------------------------------

func (j *JobStatus) SetRPM(rpm float64) {
	j.Mu.Lock()
	defer j.Mu.Unlock()
	j.CurrentRPM = rpm
	if rpm > j.PeakRPM {
		j.PeakRPM = rpm
	}
}

func (j *JobStatus) SetDone() {
	j.Mu.Lock()
	defer j.Mu.Unlock()
	j.Status = "done"
	j.CompletedAt = time.Now()
	j.CurrentRPM = 0 // a finished job has no live speed to report
}

// RecordCheckDuration folds one check into the published average.
func (j *JobStatus) RecordCheckDuration(ms int64) {
	if ms <= 0 {
		return
	}
	j.Mu.Lock()
	if j.AvgCheckMs == 0 {
		j.AvgCheckMs = ms
	} else {
		j.AvgCheckMs = (j.AvgCheckMs*7 + ms) / 8
	}
	j.Mu.Unlock()
}

func (j *JobStatus) SetCancelled() {
	j.Mu.Lock()
	defer j.Mu.Unlock()
	j.Status = "cancelled"
	j.CompletedAt = time.Now()
	j.CurrentRPM = 0
}

func (j *JobStatus) SetFailed() {
	j.Mu.Lock()
	defer j.Mu.Unlock()
	j.Status = "failed"
	j.CompletedAt = time.Now()
}

// ---------------------------------------------------------------------------
// Progress / ETA helpers
// ---------------------------------------------------------------------------

func (j *JobStatus) Progress() float64 {
	total := j.Total
	if total <= 0 {
		return 0
	}
	checked := j.Checked.Load()
	pct := float64(checked) / float64(total) * 100
	if pct > 100 {
		pct = 100
	}
	return pct
}

func (j *JobStatus) ElapsedMs() int64 {
	return time.Since(j.StartedAt).Milliseconds()
}

// ---------------------------------------------------------------------------
// Snapshot — safe, JSON-serialisable copy
// ---------------------------------------------------------------------------

type JobStatusSnapshot struct {
	ID              string  `json:"id"`
	Status          string  `json:"status"`
	Total           int     `json:"total"`
	Checked         int64   `json:"checked"`
	Hits            int64   `json:"hits"`
	Expired         int64   `json:"expired"`
	Errors          int64   `json:"errors"`
	Duplicates      int64   `json:"duplicates"`
	CurrentRPM      float64 `json:"current_rpm"`
	PeakRPM         float64 `json:"peak_rpm"`
	Progress        float64 `json:"progress"`
	ETA             string  `json:"eta"`
	ElapsedMs       int64   `json:"elapsed_ms"`
	AvgCheckMs      int64   `json:"avg_check_ms"`
	MemoryUsedBytes int64   `json:"memory_used_bytes"`
	WorkerCount     int     `json:"worker_count"`
	StartedAt       string  `json:"started_at"`
	CompletedAt     string  `json:"completed_at,omitempty"`
}

// Snapshot returns a consistent, JSON-safe copy of the job status.
func (j *JobStatus) Snapshot() JobStatusSnapshot {
	checked := j.Checked.Load()
	hits := j.Hits.Load()
	expired := j.Expired.Load()
	errors := j.Errors.Load()
	duplicates := j.Duplicates.Load()

	j.Mu.Lock()
	status := j.Status
	completedAt := j.CompletedAt
	currentRPM := j.CurrentRPM
	peakRPM := j.PeakRPM
	eta := j.ETA
	avgCheckMs := j.AvgCheckMs
	memUsed := j.MemoryUsedBytes
	workerCount := j.WorkerCount
	j.Mu.Unlock()

	var completedStr string
	if !completedAt.IsZero() {
		completedStr = completedAt.Format(time.RFC3339Nano)
	}

	var etaStr string
	if eta > 0 {
		etaStr = eta.String()
	}

	var progress float64
	if j.Total > 0 {
		progress = float64(checked) / float64(j.Total) * 100
		if progress > 100 {
			progress = 100
		}
	}

	return JobStatusSnapshot{
		ID:              j.ID,
		Status:          status,
		Total:           j.Total,
		Checked:         checked,
		Hits:            hits,
		Expired:         expired,
		Errors:          errors,
		Duplicates:      duplicates,
		CurrentRPM:      currentRPM,
		PeakRPM:         peakRPM,
		Progress:        progress,
		ETA:             etaStr,
		ElapsedMs:       time.Since(j.StartedAt).Milliseconds(),
		AvgCheckMs:      avgCheckMs,
		MemoryUsedBytes: memUsed,
		WorkerCount:     workerCount,
		StartedAt:       j.StartedAt.Format(time.RFC3339Nano),
		CompletedAt:     completedStr,
	}
}
