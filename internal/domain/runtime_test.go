package domain

import (
	"net/netip"
	"strings"
	"testing"
)

func TestReconcileReportRequiresAConditionWhenTheDataPlaneIsUnavailable(t *testing.T) {
	report := ReconcileReport{ApprovalObserved: true}
	if err := report.Validate(); err == nil || !strings.Contains(err.Error(), "unavailable data plane requires an operational condition") {
		t.Fatalf("unexplained data-plane unavailability was accepted: %v", err)
	}

	report.Conditions = []ReconcileCondition{{
		Kind: ConditionInternetCapabilityUnavailable, Family: IPv4,
	}}
	if err := report.Validate(); err != nil {
		t.Fatalf("conditioned data-plane unavailability was rejected: %v", err)
	}

	report = ReconcileReport{
		DataPlaneAvailable: true,
		ApprovalObserved:   true,
		Conditions: []ReconcileCondition{{
			Kind: ConditionRouteNotApproved, Family: IPv4, Prefix: netip.MustParsePrefix("10.0.8.0/24"),
		}},
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("available degraded data plane was rejected: %v", err)
	}
}

func TestReconcileReportRequiresCompleteApprovalObservation(t *testing.T) {
	report := ReconcileReport{DataPlaneAvailable: true}
	if err := report.Validate(); err == nil || !strings.Contains(err.Error(), "successful reconciliation requires a complete route approval observation") {
		t.Fatalf("successful report without approval observation was accepted: %v", err)
	}
}
