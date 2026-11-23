package checker

import (
	"testing"

	"github.com/nfchecker/internal/models"
)

// A market whose plan wording is localised must still classify, and its price
// and currency must both be extracted.
func TestExtractAccountInfoLocalizedPlanAndCurrency(t *testing.T) {
	page := `{"currentPlan":{"localizedPlanName":{"value":"Özel","fieldType":"String"}},` +
		`"planCode":"PREMIUM","priceAmount":"149,99","currencyCode":"TRY"}`
	info := ExtractAccountInfo(page, &models.CookieSet{})
	if info.Plan != "Özel" {
		t.Fatalf("plan = %q, want Özel", info.Plan)
	}
	if info.PlanType != "premium" {
		t.Fatalf("plan_type = %q, want premium", info.PlanType)
	}
	if info.Price != "149,99" {
		t.Fatalf("price = %q, want 149,99", info.Price)
	}
	if info.Currency != "TRY" {
		t.Fatalf("currency = %q, want TRY", info.Currency)
	}
}

// An unfamiliar display name is classified from the locale-independent plan
// code instead of falling through to "unknown".
func TestExtractAccountInfoFallsBackToPlanCode(t *testing.T) {
	page := `{"planName":"Paket Süper","planCode":"PREMIUM"}`
	info := ExtractAccountInfo(page, &models.CookieSet{})
	if info.PlanType != "premium" {
		t.Fatalf("plan_type = %q, want premium", info.PlanType)
	}
	if info.PlanCode != "PREMIUM" {
		t.Fatalf("plan_code = %q, want PREMIUM", info.PlanCode)
	}
}

func TestExtractAccountInfoAdsCode(t *testing.T) {
	page := `{"planName":"Unbekannt","planCode":"STANDARD_WITH_ADS"}`
	info := ExtractAccountInfo(page, &models.CookieSet{})
	if info.PlanType != "standard_with_ads" || !info.IsAdsTier {
		t.Fatalf("plan_type = %q ads = %v, want standard_with_ads", info.PlanType, info.IsAdsTier)
	}
}
