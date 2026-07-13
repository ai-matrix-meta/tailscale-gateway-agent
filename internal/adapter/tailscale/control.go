package tailscale

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
)

type localAPI interface {
	GetPrefs(context.Context) (*ipn.Prefs, error)
	EditPrefs(context.Context, *ipn.MaskedPrefs) (*ipn.Prefs, error)
	StatusWithoutPeers(context.Context) (*ipnstate.Status, error)
}

type Control struct {
	client      localAPI
	watchIPNBus watchIPNBusFunc
	now         func() time.Time
}

func NewControl(socketPath string) *Control {
	client := &local.Client{Socket: socketPath, UseSocketOnly: true}
	return &Control{
		client: client,
		watchIPNBus: func(ctx context.Context, mask ipn.NotifyWatchOpt) (ipnBusWatcher, error) {
			return client.WatchIPNBus(ctx, mask)
		},
		now: time.Now,
	}
}

func (control *Control) ReadState(ctx context.Context) (domain.TailnetState, error) {
	status, err := control.client.StatusWithoutPeers(ctx)
	if err != nil {
		return domain.TailnetState{}, fmt.Errorf("read LocalAPI status: %w", err)
	}
	if status == nil {
		return domain.TailnetState{}, errors.New("LocalAPI returned a nil status")
	}
	preferences, err := control.client.GetPrefs(ctx)
	if err != nil {
		return domain.TailnetState{}, fmt.Errorf("read LocalAPI preferences: %w", err)
	}
	if preferences == nil {
		return domain.TailnetState{}, errors.New("LocalAPI returned nil preferences")
	}
	rawPreferences := domain.TailnetPreferences{AdvertiseRoutes: slices.Clone(preferences.AdvertiseRoutes)}
	if err := rawPreferences.Validate(); err != nil {
		return domain.TailnetState{}, fmt.Errorf("validate LocalAPI preferences: %w", err)
	}
	controlObservation := domain.TailnetControlObservation{ObservedAt: control.observedAt()}
	if status.Self != nil {
		controlObservation.SelfPresent = true
		controlObservation.InNetworkMap = status.Self.InNetworkMap
		controlObservation.Online = status.Self.Online
		controlObservation.AllowedIPsAvailable = status.Self.AllowedIPs != nil && !status.Self.AllowedIPs.IsNil()
		if controlObservation.AllowedIPsAvailable {
			approved, approvalErr := approvedRoutes(status.Self.AllowedIPs.AsSlice(), status.TailscaleIPs)
			if approvalErr != nil {
				return domain.TailnetState{}, fmt.Errorf("normalize LocalAPI approved routes: %w", approvalErr)
			}
			controlObservation.ApprovedRoutes = approved
		}
	}
	if err := controlObservation.Validate(); err != nil {
		return domain.TailnetState{}, fmt.Errorf("validate LocalAPI control observation: %w", err)
	}
	return domain.TailnetState{
		Running:       status.BackendState == ipn.Running.String(),
		KernelTunnel:  status.TUN,
		SelfAddresses: slices.Clone(status.TailscaleIPs),
		Preferences:   domain.NewTailnetPreferences(preferences.AdvertiseRoutes, false),
		Control:       controlObservation,
	}, nil
}

func (control *Control) observedAt() time.Time {
	if control.now == nil {
		return time.Now()
	}
	return control.now()
}

func approvedRoutes(allowed []netip.Prefix, selfAddresses []netip.Addr) ([]netip.Prefix, error) {
	raw := domain.TailnetPreferences{AdvertiseRoutes: slices.Clone(allowed)}
	if err := raw.Validate(); err != nil {
		return nil, err
	}
	selfPrefixes := make(map[netip.Prefix]struct{}, len(selfAddresses))
	for _, address := range selfAddresses {
		address = address.Unmap()
		if !address.IsValid() || address.Zone() != "" {
			return nil, fmt.Errorf("self address %q is invalid", address)
		}
		selfPrefixes[netip.PrefixFrom(address, address.BitLen())] = struct{}{}
	}
	approved := make([]netip.Prefix, 0, len(allowed))
	for _, prefix := range allowed {
		prefix = prefix.Masked()
		if _, self := selfPrefixes[prefix]; !self {
			approved = append(approved, prefix)
		}
	}
	return domain.NewTailnetPreferences(approved, false).AdvertiseRoutes, nil
}

func (control *Control) WritePreferences(ctx context.Context, preferences domain.TailnetPreferences) error {
	if err := preferences.Validate(); err != nil {
		return fmt.Errorf("validate desired LocalAPI preferences: %w", err)
	}
	updated, err := control.client.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			AdvertiseRoutes: slices.Clone(preferences.AdvertiseRoutes),
		},
		AdvertiseRoutesSet: true,
	})
	if err != nil {
		return fmt.Errorf("edit LocalAPI preferences: %w", err)
	}
	if updated == nil {
		return errors.New("LocalAPI returned nil preferences after edit")
	}
	observed := domain.TailnetPreferences{AdvertiseRoutes: slices.Clone(updated.AdvertiseRoutes)}
	if err := observed.Validate(); err != nil {
		return fmt.Errorf("validate LocalAPI edit response: %w", err)
	}
	observed = domain.NewTailnetPreferences(observed.AdvertiseRoutes, false)
	if !observed.Equal(preferences) {
		return fmt.Errorf("LocalAPI edit response did not converge: got %v, want %v", observed.AdvertiseRoutes, preferences.AdvertiseRoutes)
	}
	return nil
}
