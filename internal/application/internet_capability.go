package application

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

type InternetCapabilityObserver interface {
	Observe(context.Context, domain.LinkIdentity) (domain.InternetCapabilitySnapshot, error)
}

type internetCapabilityEvaluation struct {
	exitDefaults domain.ExitDefaultRouteSet
	conditions   []domain.ReconcileCondition
}

type exitDefaultAdvertisementTransition struct {
	advertisementsToPublish  domain.ExitDefaultRouteSet
	advertisementsToWithdraw domain.ExitDefaultRouteSet
}

func (transition exitDefaultAdvertisementTransition) Empty() bool {
	return transition.advertisementsToPublish.Empty() && transition.advertisementsToWithdraw.Empty()
}

func evaluateInternetCapability(snapshot domain.InternetCapabilitySnapshot, proxyLink domain.LinkIdentity, now time.Time) (internetCapabilityEvaluation, error) {
	if err := snapshot.Validate(); err != nil {
		return internetCapabilityEvaluation{}, fmt.Errorf("validate Internet capability observation: %w", err)
	}
	if snapshot.ProxyLink != proxyLink {
		return internetCapabilityEvaluation{
			conditions: []domain.ReconcileCondition{{Kind: domain.ConditionInternetCapabilityLinkMismatch}},
		}, nil
	}
	evaluation := internetCapabilityEvaluation{
		exitDefaults: snapshot.AvailableExitDefaultRoutes(now, proxyLink),
		conditions:   make([]domain.ReconcileCondition, 0, 2),
	}
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
			evaluation.conditions = append(evaluation.conditions, domain.ReconcileCondition{Kind: kind, Family: item.family})
		}
	}
	return evaluation, nil
}

func classifyExitDefaultAdvertisementTransition(currentPreferences, targetPreferences domain.TailnetPreferences) (exitDefaultAdvertisementTransition, bool) {
	if !slices.Equal(currentPreferences.RoutesWithoutExitDefaults(), targetPreferences.RoutesWithoutExitDefaults()) {
		return exitDefaultAdvertisementTransition{}, false
	}
	currentExitDefaults := currentPreferences.ExitDefaultRoutes()
	targetExitDefaults := targetPreferences.ExitDefaultRoutes()
	transition := exitDefaultAdvertisementTransition{
		advertisementsToPublish:  targetExitDefaults.Difference(currentExitDefaults),
		advertisementsToWithdraw: currentExitDefaults.Difference(targetExitDefaults),
	}
	if transition.Empty() {
		return exitDefaultAdvertisementTransition{}, false
	}
	return transition, true
}

func routingChangesMatchExitDefaultTransition(changes domain.RoutingChanges, network domain.NetworkConfiguration, transition exitDefaultAdvertisementTransition) bool {
	if transition.Empty() || len(changes.AddRules) != 0 || len(changes.DeleteRules) != 0 {
		return false
	}
	for _, route := range changes.UpsertRoutes {
		if !isExitDefaultRouteForPublication(route, network, transition.advertisementsToPublish) &&
			!isRestoredExitDefaultBlackhole(route, network, transition.advertisementsToWithdraw) {
			return false
		}
	}
	for _, route := range changes.DeleteRoutes {
		if !isWithdrawnExitDefaultRoute(route, network, transition.advertisementsToWithdraw) {
			return false
		}
	}
	return len(changes.UpsertRoutes) != 0 || len(changes.DeleteRoutes) != 0
}

func isExitDefaultRouteForPublication(route domain.Route, network domain.NetworkConfiguration, advertisements domain.ExitDefaultRouteSet) bool {
	return route.Table == network.ExitRouteTable &&
		route.Disposition == domain.RouteUnicast &&
		route.Metric == network.ActiveRouteMetric &&
		advertisements.Contains(route.Family) &&
		route.Prefix == domain.DefaultPrefix(route.Family)
}

func isRestoredExitDefaultBlackhole(route domain.Route, network domain.NetworkConfiguration, withdrawals domain.ExitDefaultRouteSet) bool {
	return route.Table == network.ExitRouteTable &&
		route.Disposition == domain.RouteBlackhole &&
		route.Metric == network.FailClosedRouteMetric &&
		withdrawals.Contains(route.Family) &&
		route.Prefix == domain.DefaultPrefix(route.Family)
}

func isWithdrawnExitDefaultRoute(route domain.Route, network domain.NetworkConfiguration, withdrawals domain.ExitDefaultRouteSet) bool {
	return route.Table == network.ExitRouteTable &&
		route.Disposition == domain.RouteUnicast &&
		route.Metric == network.ActiveRouteMetric &&
		withdrawals.Contains(route.Family) &&
		route.Prefix == domain.DefaultPrefix(route.Family)
}
