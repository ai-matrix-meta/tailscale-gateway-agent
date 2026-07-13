package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

type TailnetPreferences struct {
	AdvertiseRoutes []netip.Prefix
}

func NewTailnetPreferences(routes []netip.Prefix, advertiseExitNode bool) TailnetPreferences {
	result := slices.Clone(routes)
	if advertiseExitNode {
		result = append(result, DefaultPrefix(IPv4), DefaultPrefix(IPv6))
	}
	for index := range result {
		result[index] = result[index].Masked()
	}
	slices.SortFunc(result, func(left, right netip.Prefix) int {
		if comparison := left.Addr().Compare(right.Addr()); comparison != 0 {
			return comparison
		}
		return left.Bits() - right.Bits()
	})
	return TailnetPreferences{AdvertiseRoutes: slices.Compact(result)}
}

func (preferences TailnetPreferences) Equal(other TailnetPreferences) bool {
	return slices.Equal(preferences.AdvertiseRoutes, other.AdvertiseRoutes)
}

func (preferences TailnetPreferences) Validate() error {
	var validationErrors []error
	seen := make(map[netip.Prefix]struct{}, len(preferences.AdvertiseRoutes))
	for _, prefix := range preferences.AdvertiseRoutes {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			validationErrors = append(validationErrors, fmt.Errorf("advertised preference route %q is invalid", prefix))
			continue
		}
		if _, duplicate := seen[prefix]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("advertised preference route %s is duplicated", prefix))
		}
		seen[prefix] = struct{}{}
	}
	return errors.Join(validationErrors...)
}

type TailnetState struct {
	Running       bool
	KernelTunnel  bool
	SelfAddresses []netip.Addr
	Preferences   TailnetPreferences
	Control       TailnetControlObservation
}

type TailnetEventKind string

const (
	TailnetEventStateChanged TailnetEventKind = "state_changed"
	TailnetEventNetworkMap   TailnetEventKind = "network_map_changed"
	TailnetEventSelfNode     TailnetEventKind = "self_node_changed"
)

type TailnetEvent struct {
	Kind TailnetEventKind
}

func (event TailnetEvent) Validate() error {
	switch event.Kind {
	case TailnetEventStateChanged, TailnetEventNetworkMap, TailnetEventSelfNode:
		return nil
	default:
		return fmt.Errorf("tailnet event kind %q is unsupported", event.Kind)
	}
}

type TailnetControlObservation struct {
	SelfPresent         bool
	InNetworkMap        bool
	Online              bool
	AllowedIPsAvailable bool
	ApprovedRoutes      []netip.Prefix
	ObservedAt          time.Time
}

func (observation TailnetControlObservation) Validate() error {
	var validationErrors []error
	if observation.ObservedAt.IsZero() {
		validationErrors = append(validationErrors, errors.New("tailnet control observation time is required"))
	}
	if !observation.SelfPresent && (observation.InNetworkMap || observation.Online || observation.AllowedIPsAvailable || len(observation.ApprovedRoutes) != 0) {
		validationErrors = append(validationErrors, errors.New("missing Tailnet self status carries control-plane state"))
	}
	if !observation.AllowedIPsAvailable && len(observation.ApprovedRoutes) != 0 {
		validationErrors = append(validationErrors, errors.New("unavailable Tailnet AllowedIPs carries approved routes"))
	}
	seen := make(map[netip.Prefix]struct{}, len(observation.ApprovedRoutes))
	for _, prefix := range observation.ApprovedRoutes {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			validationErrors = append(validationErrors, fmt.Errorf("approved Tailnet route %q is invalid", prefix))
			continue
		}
		if _, duplicate := seen[prefix]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("approved Tailnet route %s is duplicated", prefix))
		}
		seen[prefix] = struct{}{}
	}
	return errors.Join(validationErrors...)
}
