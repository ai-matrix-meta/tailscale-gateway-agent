package domain

import (
	"testing"
	"time"
)

func TestInternetCapabilitySnapshotDerivesAvailableExitDefaultsPerFreshFamilyOnTheObservedLink(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	link := LinkIdentity{Index: 7, Name: "proxy-test"}
	fresh := InternetFamilyCapability{
		Initialized: true, Available: true, ObservedAt: now.Add(-time.Minute), ValidUntil: now.Add(time.Minute),
	}
	snapshot := InternetCapabilitySnapshot{
		ProxyLink: link,
		IPv4:      fresh,
		IPv6:      fresh,
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("valid snapshot was rejected: %v", err)
	}
	if got := snapshot.AvailableExitDefaultRoutes(now, link); !got.Equal(AllExitDefaultRoutes()) {
		t.Fatalf("fresh dual-stack capability produced %#v", got)
	}
	if got := snapshot.AvailableExitDefaultRoutes(now, LinkIdentity{Index: 8, Name: "proxy-test"}); !got.Empty() {
		t.Fatal("capability observed on a different link was accepted")
	}
	snapshot.IPv6.ValidUntil = now.Add(-time.Nanosecond)
	if got := snapshot.AvailableExitDefaultRoutes(now, link); !got.Equal(ExitDefaultRouteSet{IPv4: true}) {
		t.Fatalf("stale IPv6 capability produced %#v", got)
	}
	snapshot.IPv4.ValidUntil = now.Add(-time.Nanosecond)
	snapshot.IPv6 = fresh
	if got := snapshot.AvailableExitDefaultRoutes(now, link); !got.Equal(ExitDefaultRouteSet{IPv6: true}) {
		t.Fatalf("stale IPv4 capability produced %#v", got)
	}
}

func TestInternetCapabilitySnapshotRejectsIncoherentStates(t *testing.T) {
	now := time.Now()
	tests := []InternetCapabilitySnapshot{
		{ProxyLink: LinkIdentity{Index: 1, Name: "proxy"}, IPv4: InternetFamilyCapability{Available: true}},
		{ProxyLink: LinkIdentity{Index: 1, Name: "proxy"}, IPv4: InternetFamilyCapability{Initialized: true}},
		{ProxyLink: LinkIdentity{Index: 1, Name: "proxy"}, IPv4: InternetFamilyCapability{Initialized: true, Available: true, ObservedAt: now, ValidUntil: now}},
		{IPv4: InternetFamilyCapability{Initialized: true, ObservedAt: now}},
		{ProxyLink: LinkIdentity{Index: -1, Name: "proxy"}},
	}
	for index, snapshot := range tests {
		if err := snapshot.Validate(); err == nil {
			t.Fatalf("invalid snapshot %d was accepted: %#v", index, snapshot)
		}
	}
}
