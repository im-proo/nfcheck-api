package models

import "testing"

func TestAccountInfoHasIdentity(t *testing.T) {
	cases := []struct {
		name string
		info *AccountInfo
		want bool
	}{
		{"nil", nil, false},
		{"empty", &AccountInfo{}, false},
		{"all unknown", &AccountInfo{
			Name: "Unknown", Email: "Unknown", Plan: "Unknown",
			PlanCode: "Unknown", MembershipStatus: "Unknown",
		}, false},
		{"plan only", &AccountInfo{Plan: "Premium"}, true},
		{"membership only", &AccountInfo{MembershipStatus: "MEMBER"}, true},
		{"email only", &AccountInfo{Email: "a@b.c"}, true},
	}
	for _, tc := range cases {
		if got := tc.info.HasIdentity(); got != tc.want {
			t.Errorf("%s: HasIdentity() = %v, want %v", tc.name, got, tc.want)
		}
	}
}
