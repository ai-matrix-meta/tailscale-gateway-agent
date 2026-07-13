package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

type ResolvedAddresses struct {
	IPv4 []netip.Addr
	IPv6 []netip.Addr
}

func NewResolvedAddresses(addresses []netip.Addr) ResolvedAddresses {
	var result ResolvedAddresses
	for _, address := range addresses {
		address = address.Unmap()
		switch {
		case address.Is4():
			result.IPv4 = append(result.IPv4, address)
		case address.Is6() && address.Zone() == "":
			result.IPv6 = append(result.IPv6, address)
		}
	}
	result.IPv4 = sortedAddresses(result.IPv4)
	result.IPv6 = sortedAddresses(result.IPv6)
	return result
}

func (addresses ResolvedAddresses) Empty() bool {
	return len(addresses.IPv4) == 0 && len(addresses.IPv6) == 0
}

func (addresses ResolvedAddresses) All() []netip.Addr {
	result := make([]netip.Addr, 0, len(addresses.IPv4)+len(addresses.IPv6))
	result = append(result, addresses.IPv4...)
	result = append(result, addresses.IPv6...)
	return result
}

type NetworkEventKind string

type NetworkEventAction string

const (
	NetworkEventLink    NetworkEventKind = "link"
	NetworkEventAddress NetworkEventKind = "address"
	NetworkEventRoute   NetworkEventKind = "route"

	NetworkEventUpsert NetworkEventAction = "upsert"
	NetworkEventDelete NetworkEventAction = "delete"
)

type NetworkEvent struct {
	Kind      NetworkEventKind
	Action    NetworkEventAction
	Family    AddressFamily
	Table     int
	Protocol  uint8
	RouteType int
	Prefix    netip.Prefix
	Metric    int
}

type ReconcileReport struct {
	Changed            bool
	RoutingWrites      int
	PacketFilterWrites int
	TailnetWrites      int
	Conditions         []ReconcileCondition
	ApprovalObserved   bool
	RouteApprovals     []RouteApproval
}

type ReconcileConditionKind string

const (
	ConditionRouteNotApproved               ReconcileConditionKind = "route_not_approved"
	ConditionInternetCapabilityInitializing ReconcileConditionKind = "internet_capability_initializing"
	ConditionInternetCapabilityUnavailable  ReconcileConditionKind = "internet_capability_unavailable"
	ConditionInternetCapabilityStale        ReconcileConditionKind = "internet_capability_stale"
	ConditionInternetCapabilityLinkMismatch ReconcileConditionKind = "internet_capability_link_mismatch"
)

type ReconcileCondition struct {
	Kind   ReconcileConditionKind
	Family AddressFamily
	Prefix netip.Prefix
}

func (condition ReconcileCondition) Validate() error {
	switch condition.Kind {
	case ConditionRouteNotApproved:
		if !condition.Prefix.IsValid() || condition.Prefix != condition.Prefix.Masked() {
			return fmt.Errorf("route approval condition has invalid prefix %q", condition.Prefix)
		}
		if condition.Family != FamilyOfPrefix(condition.Prefix) {
			return errors.New("route approval condition family does not match its prefix")
		}
	case ConditionInternetCapabilityInitializing, ConditionInternetCapabilityUnavailable, ConditionInternetCapabilityStale:
		if condition.Family != IPv4 && condition.Family != IPv6 {
			return fmt.Errorf("internet capability condition has invalid family %d", condition.Family)
		}
		if condition.Prefix.IsValid() {
			return errors.New("internet capability condition must not carry a prefix")
		}
	case ConditionInternetCapabilityLinkMismatch:
		if condition.Family != 0 || condition.Prefix.IsValid() {
			return errors.New("internet capability link condition must not carry a family or prefix")
		}
	default:
		return fmt.Errorf("reconciliation condition kind %q is unsupported", condition.Kind)
	}
	return nil
}

type RouteApproval struct {
	Prefix   netip.Prefix
	Approved bool
}

func (approval RouteApproval) Validate() error {
	if !approval.Prefix.IsValid() || approval.Prefix != approval.Prefix.Masked() {
		return fmt.Errorf("route approval prefix %q is invalid", approval.Prefix)
	}
	return nil
}

func (report ReconcileReport) Validate() error {
	var validationErrors []error
	seenConditions := make(map[ReconcileCondition]struct{}, len(report.Conditions))
	for _, condition := range report.Conditions {
		if err := condition.Validate(); err != nil {
			validationErrors = append(validationErrors, err)
		}
		if _, duplicate := seenConditions[condition]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("reconciliation condition %#v is duplicated", condition))
		}
		seenConditions[condition] = struct{}{}
	}
	if !report.ApprovalObserved && len(report.RouteApprovals) != 0 {
		validationErrors = append(validationErrors, errors.New("route approvals require a complete approval observation"))
	}
	seenApprovals := make(map[netip.Prefix]struct{}, len(report.RouteApprovals))
	for _, approval := range report.RouteApprovals {
		if err := approval.Validate(); err != nil {
			validationErrors = append(validationErrors, err)
		}
		if _, duplicate := seenApprovals[approval.Prefix]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("route approval prefix %s is duplicated", approval.Prefix))
		}
		seenApprovals[approval.Prefix] = struct{}{}
	}
	return errors.Join(validationErrors...)
}

type RuntimePhase string

const (
	RuntimeStarting    RuntimePhase = "starting"
	RuntimeQuarantined RuntimePhase = "quarantined"
	RuntimeReconciling RuntimePhase = "reconciling"
	RuntimeReady       RuntimePhase = "ready"
	RuntimeDegraded    RuntimePhase = "degraded"
	RuntimeStopping    RuntimePhase = "stopping"
)

type HealthSnapshot struct {
	Live              bool
	Ready             bool
	Phase             RuntimePhase
	LastAttempt       time.Time
	LastSuccess       time.Time
	LastError         string
	SuccessfulRuns    uint64
	FailedRuns        uint64
	ConsecutiveErrors uint64
	Conditions        []ReconcileCondition
}

type ProcessSpec struct {
	Executable  string
	Arguments   []string
	Environment []string
}

func NewProcessSpec(executable string, arguments, environment []string) ProcessSpec {
	return ProcessSpec{Executable: executable, Arguments: slices.Clone(arguments), Environment: slices.Clone(environment)}
}
