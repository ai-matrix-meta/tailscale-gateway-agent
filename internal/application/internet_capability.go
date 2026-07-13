package application

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

type InternetCapabilityObserver interface {
	Observe(context.Context, domain.LinkIdentity) (domain.InternetCapabilitySnapshot, error)
}

func internetCapabilityConditions(snapshot domain.InternetCapabilitySnapshot, proxyLink domain.LinkIdentity, now time.Time) ([]domain.ReconcileCondition, error) {
	if err := snapshot.Validate(); err != nil {
		return nil, fmt.Errorf("validate Internet capability observation: %w", err)
	}
	if snapshot.ProxyLink != proxyLink {
		return []domain.ReconcileCondition{{Kind: domain.ConditionInternetCapabilityLinkMismatch}}, nil
	}
	conditions := make([]domain.ReconcileCondition, 0, 2)
	for _, item := range []struct {
		family     domain.AddressFamily
		capability domain.InternetFamilyCapability
	}{
		{family: domain.IPv4, capability: snapshot.IPv4},
		{family: domain.IPv6, capability: snapshot.IPv6},
	} {
		kind := domain.ReconcileConditionKind("")
		switch {
		case !item.capability.Initialized:
			kind = domain.ConditionInternetCapabilityInitializing
		case !item.capability.Available:
			kind = domain.ConditionInternetCapabilityUnavailable
		case !item.capability.Fresh(now):
			kind = domain.ConditionInternetCapabilityStale
		}
		if kind != "" {
			conditions = append(conditions, domain.ReconcileCondition{Kind: kind, Family: item.family})
		}
	}
	return conditions, nil
}

func isExactExitPreferenceReduction(current, desired domain.TailnetPreferences) bool {
	if len(current.AdvertiseRoutes) != len(desired.AdvertiseRoutes)+2 {
		return false
	}
	currentRoutes := make(map[netip.Prefix]struct{}, len(current.AdvertiseRoutes))
	for _, prefix := range current.AdvertiseRoutes {
		currentRoutes[prefix] = struct{}{}
	}
	for _, prefix := range desired.AdvertiseRoutes {
		if _, exists := currentRoutes[prefix]; !exists {
			return false
		}
		delete(currentRoutes, prefix)
	}
	if len(currentRoutes) != 2 {
		return false
	}
	_, hasIPv4Default := currentRoutes[domain.DefaultPrefix(domain.IPv4)]
	_, hasIPv6Default := currentRoutes[domain.DefaultPrefix(domain.IPv6)]
	return hasIPv4Default && hasIPv6Default
}
