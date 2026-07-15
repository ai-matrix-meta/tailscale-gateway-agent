package domain

import (
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestTailnetPreferencesExposeAndRemoveExitDefaultsWithoutChangingOtherRoutes(t *testing.T) {
	routes := []netip.Prefix{
		netip.MustParsePrefix("10.0.8.0/24"),
		netip.MustParsePrefix("fd00:8::/64"),
	}
	preferences := NewTailnetPreferences(routes, AllExitDefaultRoutes())
	if got := preferences.ExitDefaultRoutes(); !got.Equal(AllExitDefaultRoutes()) {
		t.Fatalf("exit default routes = %#v, want both families", got)
	}
	if got := preferences.RoutesWithoutExitDefaults(); !slices.Equal(got, routes) {
		t.Fatalf("non-Exit routes = %v, want %v", got, routes)
	}

	retained := preferences.WithoutExitDefaults(ExitDefaultRouteSet{IPv6: true})
	want := NewTailnetPreferences(routes, ExitDefaultRouteSet{IPv4: true})
	if !retained.Equal(want) {
		t.Fatalf("removing IPv6 Exit default changed unrelated preferences: got %v, want %v", retained.AdvertiseRoutes, want.AdvertiseRoutes)
	}
}

func TestTailnetControlObservationAcceptsExplicitAvailableState(t *testing.T) {
	observation := TailnetControlObservation{
		SelfPresent: true, InNetworkMap: true, Online: true, AllowedIPsAvailable: true,
		ApprovedRoutes: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("10.0.8.0/24"),
			netip.MustParsePrefix("::/0"),
		},
		ObservedAt: time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC),
	}
	if err := observation.Validate(); err != nil {
		t.Fatalf("valid Tailnet control observation was rejected: %v", err)
	}
}

func TestTailnetControlObservationRejectsIncoherentState(t *testing.T) {
	now := time.Now()
	tests := []TailnetControlObservation{
		{},
		{InNetworkMap: true, ObservedAt: now},
		{Online: true, ObservedAt: now},
		{AllowedIPsAvailable: true, ObservedAt: now},
		{SelfPresent: true, ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.0.8.0/24")}, ObservedAt: now},
		{SelfPresent: true, AllowedIPsAvailable: true, ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.0.8.1/24")}, ObservedAt: now},
		{SelfPresent: true, AllowedIPsAvailable: true, ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.0.8.0/24"), netip.MustParsePrefix("10.0.8.0/24")}, ObservedAt: now},
	}
	for index, observation := range tests {
		if err := observation.Validate(); err == nil {
			t.Fatalf("invalid Tailnet control observation %d was accepted: %#v", index, observation)
		}
	}
}
