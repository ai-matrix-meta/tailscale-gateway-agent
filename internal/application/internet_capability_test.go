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
		name             string
		snapshot         domain.InternetCapabilitySnapshot
		wantExitDefaults domain.ExitDefaultRouteSet
		wantConditions   []domain.ReconcileCondition
	}{
		{
			name:     "initial",
			snapshot: domain.InternetCapabilitySnapshot{ProxyLink: link},
			wantConditions: []domain.ReconcileCondition{
				{Kind: domain.ConditionInternetCapabilityInitializing, Family: domain.IPv4},
				{Kind: domain.ConditionInternetCapabilityInitializing, Family: domain.IPv6},
			},
		},
		{
			name: "ipv6 unavailable keeps ipv4 publishable",
			snapshot: domain.InternetCapabilitySnapshot{
				ProxyLink: link, IPv4: fresh,
				IPv6: domain.InternetFamilyCapability{Initialized: true, ObservedAt: now},
			},
			wantExitDefaults: domain.ExitDefaultRouteSet{IPv4: true},
			wantConditions:   []domain.ReconcileCondition{{Kind: domain.ConditionInternetCapabilityUnavailable, Family: domain.IPv6}},
		},
		{
			name: "ipv4 unavailable keeps ipv6 publishable",
			snapshot: domain.InternetCapabilitySnapshot{
				ProxyLink: link, IPv4: domain.InternetFamilyCapability{Initialized: true, ObservedAt: now},
				IPv6: fresh,
			},
			wantExitDefaults: domain.ExitDefaultRouteSet{IPv6: true},
			wantConditions:   []domain.ReconcileCondition{{Kind: domain.ConditionInternetCapabilityUnavailable, Family: domain.IPv4}},
		},
		{
			name: "stale family is not publishable",
			snapshot: domain.InternetCapabilitySnapshot{
				ProxyLink: link, IPv4: fresh,
				IPv6: domain.InternetFamilyCapability{Initialized: true, Available: true, ObservedAt: now.Add(-time.Minute), ValidUntil: now.Add(-time.Second)},
			},
			wantExitDefaults: domain.ExitDefaultRouteSet{IPv4: true},
			wantConditions:   []domain.ReconcileCondition{{Kind: domain.ConditionInternetCapabilityStale, Family: domain.IPv6}},
		},
		{
			name: "link mismatch",
			snapshot: domain.InternetCapabilitySnapshot{
				ProxyLink: domain.LinkIdentity{Index: 8, Name: "proxy-other"}, IPv4: fresh, IPv6: fresh,
			},
			wantConditions: []domain.ReconcileCondition{{Kind: domain.ConditionInternetCapabilityLinkMismatch}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := evaluateInternetCapability(test.snapshot, link, now)
			if err != nil {
				t.Fatal(err)
			}
			if !got.exitDefaults.Equal(test.wantExitDefaults) {
				t.Fatalf("exit defaults = %#v, want %#v", got.exitDefaults, test.wantExitDefaults)
			}
			if !slices.Equal(got.conditions, test.wantConditions) {
				t.Fatalf("conditions = %#v, want %#v", got.conditions, test.wantConditions)
			}
		})
	}
}

func TestClassifyExitDefaultAdvertisementTransitionRejectsNonExitDifferences(t *testing.T) {
	subnet := netip.MustParsePrefix("10.0.8.0/24")
	current := domain.NewTailnetPreferences([]netip.Prefix{subnet}, domain.AllExitDefaultRoutes())
	target := domain.NewTailnetPreferences([]netip.Prefix{subnet}, domain.ExitDefaultRouteSet{IPv4: true})
	transition, ok := classifyExitDefaultAdvertisementTransition(current, target)
	if !ok || !transition.advertisementsToWithdraw.Equal(domain.ExitDefaultRouteSet{IPv6: true}) || !transition.advertisementsToPublish.Empty() {
		t.Fatalf("single-family withdrawal was misclassified: transition=%#v ok=%v", transition, ok)
	}
	transition, ok = classifyExitDefaultAdvertisementTransition(
		domain.NewTailnetPreferences([]netip.Prefix{subnet}, domain.ExitDefaultRouteSet{IPv4: true}),
		domain.NewTailnetPreferences([]netip.Prefix{subnet}, domain.AllExitDefaultRoutes()),
	)
	if !ok || !transition.advertisementsToPublish.Equal(domain.ExitDefaultRouteSet{IPv6: true}) || !transition.advertisementsToWithdraw.Empty() {
		t.Fatalf("single-family publication was misclassified: transition=%#v ok=%v", transition, ok)
	}
	for _, pair := range []struct {
		current domain.TailnetPreferences
		target  domain.TailnetPreferences
	}{
		{
			current: domain.NewTailnetPreferences(nil, domain.AllExitDefaultRoutes()),
			target:  domain.NewTailnetPreferences([]netip.Prefix{subnet}, domain.ExitDefaultRouteSet{}),
		},
		{
			current: domain.NewTailnetPreferences([]netip.Prefix{subnet}, domain.ExitDefaultRouteSet{}),
			target:  domain.NewTailnetPreferences([]netip.Prefix{subnet}, domain.ExitDefaultRouteSet{}),
		},
		{
			current: domain.NewTailnetPreferences([]netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")}, domain.AllExitDefaultRoutes()),
			target:  domain.NewTailnetPreferences([]netip.Prefix{subnet}, domain.ExitDefaultRouteSet{}),
		},
	} {
		if _, ok := classifyExitDefaultAdvertisementTransition(pair.current, pair.target); ok {
			t.Fatalf("non-isolated transition was accepted: current=%#v target=%#v", pair.current, pair.target)
		}
	}
}

func TestRoutingChangesMatchOnlyTheClassifiedExitDefaultTransition(t *testing.T) {
	network := domain.DefaultConfiguration().Network
	transition := exitDefaultAdvertisementTransition{
		advertisementsToPublish:  domain.ExitDefaultRouteSet{IPv6: true},
		advertisementsToWithdraw: domain.ExitDefaultRouteSet{IPv4: true},
	}
	if !routingChangesMatchExitDefaultTransition(domain.RoutingChanges{
		UpsertRoutes: []domain.Route{{
			Family: domain.IPv6, Disposition: domain.RouteUnicast, Table: network.ExitRouteTable,
			Prefix: domain.DefaultPrefix(domain.IPv6), Metric: network.ActiveRouteMetric,
		}},
		DeleteRoutes: []domain.Route{{
			Family: domain.IPv4, Disposition: domain.RouteUnicast, Table: network.ExitRouteTable,
			Prefix: domain.DefaultPrefix(domain.IPv4), Metric: network.ActiveRouteMetric,
		}},
	}, network, transition) {
		t.Fatal("isolated cross-family Exit default transition was rejected")
	}
	for _, changes := range []domain.RoutingChanges{
		{AddRules: []domain.Rule{{Family: domain.IPv6, Priority: network.ExitRulePriority, Table: network.ExitRouteTable, IncomingInterface: "tailscale0"}}},
		{UpsertRoutes: []domain.Route{{Family: domain.IPv4, Disposition: domain.RouteUnicast, Table: network.ExitRouteTable, Prefix: domain.DefaultPrefix(domain.IPv4), Metric: network.ActiveRouteMetric}}},
		{DeleteRoutes: []domain.Route{{Family: domain.IPv6, Disposition: domain.RouteUnicast, Table: network.ExitRouteTable, Prefix: domain.DefaultPrefix(domain.IPv6), Metric: network.ActiveRouteMetric}}},
		{DeleteRoutes: []domain.Route{{Family: domain.IPv6, Disposition: domain.RouteUnicast, Table: network.ExitRouteTable, Prefix: netip.MustParsePrefix("10.0.8.0/24"), Metric: network.ActiveRouteMetric}}},
	} {
		if routingChangesMatchExitDefaultTransition(changes, network, transition) {
			t.Fatalf("unsafe routing change was accepted: %#v", changes)
		}
	}
}
