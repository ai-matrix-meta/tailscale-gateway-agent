package tailscale

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/views"
)

func TestReadStateReturnsKernelTunnelIdentityAndPreferences(t *testing.T) {
	selfAddresses := []netip.Addr{netip.MustParseAddr("100.64.0.8"), netip.MustParseAddr("fd7a:115c:a1e0::8")}
	allowed := views.SliceOf([]netip.Prefix{
		netip.MustParsePrefix("100.64.0.8/32"), netip.MustParsePrefix("fd7a:115c:a1e0::8/128"),
		netip.MustParsePrefix("10.0.8.0/24"), netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
	})
	client := &fakeLocalAPI{
		status: &ipnstate.Status{
			BackendState: "Running",
			TUN:          true,
			TailscaleIPs: selfAddresses,
			Self:         &ipnstate.PeerStatus{InNetworkMap: true, Online: true, AllowedIPs: &allowed},
		},
		preferences: &ipn.Prefs{AdvertiseRoutes: []netip.Prefix{netip.MustParsePrefix("10.0.8.0/24")}},
	}
	observedAt := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	control := &Control{client: client, now: func() time.Time { return observedAt }}
	state, err := control.ReadState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !state.Running || !state.KernelTunnel || len(state.SelfAddresses) != 2 || len(state.Preferences.AdvertiseRoutes) != 1 {
		t.Fatalf("unexpected LocalAPI state: %#v", state)
	}
	if !state.Control.SelfPresent || !state.Control.InNetworkMap || !state.Control.Online || !state.Control.AllowedIPsAvailable || state.Control.ObservedAt != observedAt {
		t.Fatalf("control-plane availability was lost: %#v", state.Control)
	}
	wantApproved := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("10.0.8.0/24"), netip.MustParsePrefix("::/0")}
	if !slices.Equal(state.Control.ApprovedRoutes, wantApproved) {
		t.Fatalf("approved routes mismatch: got %v, want %v", state.Control.ApprovedRoutes, wantApproved)
	}
}

func TestReadStatePreservesUnavailableAllowedIPs(t *testing.T) {
	control := &Control{client: &fakeLocalAPI{
		status: &ipnstate.Status{
			BackendState: ipn.Running.String(), TUN: true,
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.8")},
			Self:         &ipnstate.PeerStatus{InNetworkMap: true, Online: true},
		},
		preferences: &ipn.Prefs{},
	}}
	state, err := control.ReadState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !state.Control.SelfPresent || state.Control.AllowedIPsAvailable || len(state.Control.ApprovedRoutes) != 0 {
		t.Fatalf("nil AllowedIPs was converted to an explicit approval set: %#v", state.Control)
	}
}

func TestReadStateRejectsInvalidApprovedRoutes(t *testing.T) {
	allowed := views.SliceOf([]netip.Prefix{netip.MustParsePrefix("10.0.8.0/24"), netip.MustParsePrefix("10.0.8.0/24")})
	control := &Control{client: &fakeLocalAPI{
		status: &ipnstate.Status{
			BackendState: ipn.Running.String(), TUN: true,
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.8")},
			Self:         &ipnstate.PeerStatus{InNetworkMap: true, Online: true, AllowedIPs: &allowed},
		},
		preferences: &ipn.Prefs{},
	}}
	if _, err := control.ReadState(context.Background()); err == nil {
		t.Fatal("duplicate approved route was accepted")
	}
}

func TestWritePreferencesMasksOnlyAdvertiseRoutes(t *testing.T) {
	client := &fakeLocalAPI{}
	control := &Control{client: client}
	preferences := domain.NewTailnetPreferences([]netip.Prefix{netip.MustParsePrefix("10.0.8.0/24")}, true)
	client.editResponse = &ipn.Prefs{AdvertiseRoutes: preferences.AdvertiseRoutes}

	if err := control.WritePreferences(context.Background(), preferences); err != nil {
		t.Fatal(err)
	}
	if client.mask == nil || !client.mask.AdvertiseRoutesSet {
		t.Fatal("AdvertiseRoutesSet was not set")
	}
	if client.mask.WantRunningSet || client.mask.HostnameSet || client.mask.NoSNATSet {
		t.Fatalf("unowned preference fields were included: %#v", client.mask)
	}
	if len(client.mask.AdvertiseRoutes) != 3 {
		t.Fatalf("unexpected advertised routes: %v", client.mask.AdvertiseRoutes)
	}
}

func TestWritePreferencesRejectsNonConvergedResponse(t *testing.T) {
	control := &Control{client: &fakeLocalAPI{editResponse: &ipn.Prefs{}}}
	preferences := domain.NewTailnetPreferences([]netip.Prefix{netip.MustParsePrefix("10.0.8.0/24")}, false)
	if err := control.WritePreferences(context.Background(), preferences); err == nil {
		t.Fatal("non-converged LocalAPI response was accepted")
	}
}

type fakeLocalAPI struct {
	status       *ipnstate.Status
	preferences  *ipn.Prefs
	mask         *ipn.MaskedPrefs
	editResponse *ipn.Prefs
}

func (fake *fakeLocalAPI) GetPrefs(context.Context) (*ipn.Prefs, error) {
	return fake.preferences, nil
}

func (fake *fakeLocalAPI) EditPrefs(_ context.Context, mask *ipn.MaskedPrefs) (*ipn.Prefs, error) {
	fake.mask = mask
	return fake.editResponse, nil
}

func (fake *fakeLocalAPI) StatusWithoutPeers(context.Context) (*ipnstate.Status, error) {
	return fake.status, nil
}
