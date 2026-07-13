package application

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

func TestInternetCapabilityConditionsClassifyOperationalStates(t *testing.T) {
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	link := domain.LinkIdentity{Index: 7, Name: "proxy-test"}
	fresh := domain.InternetFamilyCapability{Initialized: true, Available: true, ObservedAt: now.Add(-time.Second), ValidUntil: now.Add(time.Minute)}
	tests := []struct {
		name     string
		snapshot domain.InternetCapabilitySnapshot
		want     []domain.ReconcileCondition
	}{
		{
			name:     "initial",
			snapshot: domain.InternetCapabilitySnapshot{ProxyLink: link},
			want: []domain.ReconcileCondition{
				{Kind: domain.ConditionInternetCapabilityInitializing, Family: domain.IPv4},
				{Kind: domain.ConditionInternetCapabilityInitializing, Family: domain.IPv6},
			},
		},
		{
			name: "unavailable",
			snapshot: domain.InternetCapabilitySnapshot{
				ProxyLink: link, IPv4: fresh,
				IPv6: domain.InternetFamilyCapability{Initialized: true, ObservedAt: now},
			},
			want: []domain.ReconcileCondition{{Kind: domain.ConditionInternetCapabilityUnavailable, Family: domain.IPv6}},
		},
		{
			name: "stale",
			snapshot: domain.InternetCapabilitySnapshot{
				ProxyLink: link, IPv4: fresh,
				IPv6: domain.InternetFamilyCapability{Initialized: true, Available: true, ObservedAt: now.Add(-time.Minute), ValidUntil: now.Add(-time.Second)},
			},
			want: []domain.ReconcileCondition{{Kind: domain.ConditionInternetCapabilityStale, Family: domain.IPv6}},
		},
		{
			name: "link mismatch",
			snapshot: domain.InternetCapabilitySnapshot{
				ProxyLink: domain.LinkIdentity{Index: 8, Name: "proxy-other"}, IPv4: fresh, IPv6: fresh,
			},
			want: []domain.ReconcileCondition{{Kind: domain.ConditionInternetCapabilityLinkMismatch}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := internetCapabilityConditions(test.snapshot, link, now)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, test.want) {
				t.Fatalf("conditions = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestExactExitPreferenceReductionRejectsAnyNonExitDifference(t *testing.T) {
	subnet := netip.MustParsePrefix("10.0.8.0/24")
	desired := domain.NewTailnetPreferences([]netip.Prefix{subnet}, false)
	if !isExactExitPreferenceReduction(domain.NewTailnetPreferences([]netip.Prefix{subnet}, true), desired) {
		t.Fatal("exact dual-default reduction was rejected")
	}
	for _, current := range []domain.TailnetPreferences{
		domain.NewTailnetPreferences(nil, true),
		domain.NewTailnetPreferences([]netip.Prefix{subnet}, false),
		domain.NewTailnetPreferences([]netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")}, true),
	} {
		if isExactExitPreferenceReduction(current, desired) {
			t.Fatalf("non-exact reduction was accepted: %#v", current)
		}
	}
}
