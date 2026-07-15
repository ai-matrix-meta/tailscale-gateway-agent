package application

import (
	"context"
	"fmt"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

type InternetCapabilityObserver interface {
	Observe(context.Context, domain.LinkIdentity) (domain.InternetCapabilitySnapshot, error)
}

type internetCapabilityEvaluation struct {
	activeExitDefaultRoutes domain.ExitDefaultRouteSet
	conditions              []domain.ReconcileCondition
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
		activeExitDefaultRoutes: snapshot.AvailableExitDefaultRoutes(now, proxyLink),
		conditions:              make([]domain.ReconcileCondition, 0, 2),
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
