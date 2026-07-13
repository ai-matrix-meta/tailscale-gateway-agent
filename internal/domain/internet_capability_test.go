package domain

import (
	"testing"
	"time"
)

func TestInternetCapabilitySnapshotRequiresBothFreshFamiliesOnTheObservedLink(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	link := LinkIdentity{Index: 7, Name: "proxy-test"}
	snapshot := InternetCapabilitySnapshot{
		ProxyLink: link,
		IPv4: InternetFamilyCapability{
			Initialized: true, Available: true, ObservedAt: now.Add(-time.Minute), ValidUntil: now.Add(time.Minute),
		},
		IPv6: InternetFamilyCapability{
			Initialized: true, Available: true, ObservedAt: now.Add(-time.Minute), ValidUntil: now.Add(time.Minute),
		},
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("valid snapshot was rejected: %v", err)
	}
	if !snapshot.ExitAvailable(now, link) {
		t.Fatal("fresh dual-stack capability was not accepted")
	}
	if snapshot.ExitAvailable(now, LinkIdentity{Index: 8, Name: "proxy-test"}) {
		t.Fatal("capability observed on a different link was accepted")
	}
	snapshot.IPv6.ValidUntil = now.Add(-time.Nanosecond)
	if snapshot.ExitAvailable(now, link) {
		t.Fatal("stale IPv6 capability was accepted")
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
