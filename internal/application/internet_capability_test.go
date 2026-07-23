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
		name                        string
		snapshot                    domain.InternetCapabilitySnapshot
		wantActiveExitDefaultRoutes domain.ExitDefaultRouteSet
		wantConditions              []domain.ReconcileCondition
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
			wantActiveExitDefaultRoutes: domain.ExitDefaultRouteSet{IPv4: true},
			wantConditions:              []domain.ReconcileCondition{{Kind: domain.ConditionInternetCapabilityUnavailable, Family: domain.IPv6}},
		},
		{
			name: "ipv4 unavailable keeps ipv6 publishable",
			snapshot: domain.InternetCapabilitySnapshot{
				ProxyLink: link, IPv4: domain.InternetFamilyCapability{Initialized: true, ObservedAt: now},
				IPv6: fresh,
			},
			wantActiveExitDefaultRoutes: domain.ExitDefaultRouteSet{IPv6: true},
			wantConditions:              []domain.ReconcileCondition{{Kind: domain.ConditionInternetCapabilityUnavailable, Family: domain.IPv4}},
		},
		{
			name: "stale family is not publishable",
			snapshot: domain.InternetCapabilitySnapshot{
				ProxyLink: link, IPv4: fresh,
				IPv6: domain.InternetFamilyCapability{Initialized: true, Available: true, ObservedAt: now.Add(-time.Minute), ValidUntil: now.Add(-time.Second)},
			},
			wantActiveExitDefaultRoutes: domain.ExitDefaultRouteSet{IPv4: true},
			wantConditions:              []domain.ReconcileCondition{{Kind: domain.ConditionInternetCapabilityStale, Family: domain.IPv6}},
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
			if !got.activeExitDefaultRoutes.Equal(test.wantActiveExitDefaultRoutes) {
				t.Fatalf("active Exit default routes = %#v, want %#v", got.activeExitDefaultRoutes, test.wantActiveExitDefaultRoutes)
			}
			if !slices.Equal(got.conditions, test.wantConditions) {
				t.Fatalf("conditions = %#v, want %#v", got.conditions, test.wantConditions)
			}
		})
	}
}

func TestClassifyExitDefaultRouteTransitionPartitionsDeactivationBeforeActivation(t *testing.T) {
	network := domain.DefaultConfiguration().Network
	changes := domain.RoutingChanges{
		UpsertRoutes: []domain.Route{{
			Family: domain.IPv6, Disposition: domain.RouteUnicast, Table: network.ExitRouteTable,
			Prefix: domain.DefaultPrefix(domain.IPv6), Metric: network.ActiveRouteMetric,
		}},
		DeleteRoutes: []domain.Route{{
			Family: domain.IPv4, Disposition: domain.RouteUnicast, Table: network.ExitRouteTable,
			Prefix: domain.DefaultPrefix(domain.IPv4), Metric: network.ActiveRouteMetric,
		}},
	}
	transition, ok := classifyExitDefaultRouteTransition(changes, network)
	if !ok ||
		!transition.activationChanges.Equal(domain.RoutingChanges{UpsertRoutes: changes.UpsertRoutes}) ||
		!transition.deactivationChanges.Equal(domain.RoutingChanges{DeleteRoutes: changes.DeleteRoutes}) {
		t.Fatalf("cross-family Exit route transition was misclassified: transition=%#v ok=%v", transition, ok)
	}
	for _, unsafeChanges := range []domain.RoutingChanges{
		{},
		{AddRules: []domain.Rule{{Family: domain.IPv6, Priority: network.ExitRulePriority, Table: network.ExitRouteTable, IncomingInterface: "tailscale0"}}},
		{UpsertRoutes: []domain.Route{{Family: domain.IPv4, Disposition: domain.RouteBlackhole, Table: network.ExitRouteTable, Prefix: domain.DefaultPrefix(domain.IPv4), Metric: network.FailClosedRouteMetric}}},
		{DeleteRoutes: []domain.Route{{Family: domain.IPv6, Disposition: domain.RouteUnicast, Table: network.ExitRouteTable, Prefix: netip.MustParsePrefix("10.0.8.0/24"), Metric: network.ActiveRouteMetric}}},
		{
			UpsertRoutes: []domain.Route{{Family: domain.IPv4, Disposition: domain.RouteUnicast, Table: network.ExitRouteTable, Prefix: domain.DefaultPrefix(domain.IPv4), Metric: network.ActiveRouteMetric}},
			DeleteRoutes: []domain.Route{{Family: domain.IPv4, Disposition: domain.RouteUnicast, Table: network.ExitRouteTable, Prefix: domain.DefaultPrefix(domain.IPv4), Metric: network.ActiveRouteMetric}},
		},
	} {
		if _, ok := classifyExitDefaultRouteTransition(unsafeChanges, network); ok {
			t.Fatalf("unsafe routing change was accepted: %#v", unsafeChanges)
		}
	}
}
