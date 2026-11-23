package checker

import (
	"strings"
	"testing"
)

func TestNormalizePlanNameLocalized(t *testing.T) {
	cases := []struct {
		plan      string
		family    string
		wantsAds  bool
	}{
		{"Premium", "premium", false},
		{"Padrão com anúncios", "standard", true},
		{"Padrão", "standard", false},
		{"Básico", "basic", false},
		{"Básico com anúncios", "basic", true},
		{"Estándar con anuncios", "standard", true},
		{"Estándar", "standard", false},
		{"Standard with ads", "standard", true},
		// Premium is localised too; an unrecognised name would be reported as
		// a free account by the bot.
		{"Prémium", "premium", false},
		{"Преміум", "premium", false},
		{"Премијум", "premium", false},
		{"Özel", "premium", false},
		{"Cao cấp", "premium", false},
		{"प्रीमियम", "premium", false},
		{"พรีเมียม", "premium", false},
	}
	for _, tc := range cases {
		got := normalizePlanName(tc.plan)
		if !strings.Contains(got, tc.family) {
			t.Fatalf("%q normalised to %q, want family %q", tc.plan, got, tc.family)
		}
		if tc.wantsAds && !strings.Contains(got, "ads") {
			t.Fatalf("%q normalised to %q, want ads token", tc.plan, got)
		}
		if !tc.wantsAds && strings.Contains(got, "ads") {
			t.Fatalf("%q normalised to %q, unexpected ads token", tc.plan, got)
		}
	}
}
