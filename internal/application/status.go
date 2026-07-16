package application

import (
	"slices"
	"sync"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

type Status struct {
	mutex         sync.RWMutex
	maximumAge    time.Duration
	now           func() time.Time
	snapshot      domain.HealthSnapshot
	dirtyEpoch    uint64
	verifiedEpoch uint64
}

func NewStatus(maximumAge time.Duration) *Status {
	return &Status{
		maximumAge: maximumAge,
		now:        time.Now,
		snapshot: domain.HealthSnapshot{
			Live:  true,
			Phase: domain.RuntimeStarting,
		},
	}
}

func (status *Status) MarkQuarantined() {
	status.setUnavailablePhase(domain.RuntimeQuarantined)
}

func (status *Status) MarkDirty() {
	status.mutex.Lock()
	defer status.mutex.Unlock()
	status.dirtyEpoch++
	status.snapshot.Phase = domain.RuntimeReconciling
	status.snapshot.DataPlaneAvailable = false
}

func (status *Status) MarkStopping() {
	status.setUnavailablePhase(domain.RuntimeStopping)
}

func (status *Status) BeginReconcile() uint64 {
	status.mutex.Lock()
	defer status.mutex.Unlock()
	status.snapshot.Phase = domain.RuntimeReconciling
	return status.dirtyEpoch
}

func (status *Status) isCurrent(observedEpoch uint64) bool {
	status.mutex.RLock()
	defer status.mutex.RUnlock()
	return status.dirtyEpoch == observedEpoch
}

func (status *Status) RecordSuccess(at time.Time, observedEpoch uint64, report domain.ReconcileReport) bool {
	status.mutex.Lock()
	defer status.mutex.Unlock()
	status.snapshot.LastAttempt = at
	status.snapshot.SuccessfulRuns++
	if status.dirtyEpoch != observedEpoch {
		status.snapshot.Phase = domain.RuntimeReconciling
		return false
	}
	status.snapshot.LastSuccess = at
	status.snapshot.LastError = ""
	status.snapshot.ConsecutiveErrors = 0
	status.snapshot.DataPlaneAvailable = report.DataPlaneAvailable
	status.snapshot.Conditions = slices.Clone(report.Conditions)
	status.verifiedEpoch = observedEpoch
	if len(report.Conditions) != 0 || !report.DataPlaneAvailable {
		status.snapshot.Phase = domain.RuntimeDegraded
	} else {
		status.snapshot.Phase = domain.RuntimeReady
	}
	return healthSnapshotReady(status.snapshot, status.verifiedEpoch == status.dirtyEpoch, 0, status.maximumAge)
}

func (status *Status) RecordFailure(at time.Time, err error) {
	status.mutex.Lock()
	defer status.mutex.Unlock()
	status.snapshot.Phase = domain.RuntimeDegraded
	status.snapshot.DataPlaneAvailable = false
	status.snapshot.LastAttempt = at
	status.snapshot.LastError = err.Error()
	status.snapshot.Conditions = nil
	status.snapshot.FailedRuns++
	status.snapshot.ConsecutiveErrors++
}

func (status *Status) HealthSnapshot() domain.HealthSnapshot {
	status.mutex.RLock()
	snapshot := status.snapshot
	snapshot.Conditions = slices.Clone(status.snapshot.Conditions)
	verifiedEpoch := status.verifiedEpoch
	dirtyEpoch := status.dirtyEpoch
	status.mutex.RUnlock()
	age := status.now().Sub(snapshot.LastSuccess)
	snapshot.Ready = healthSnapshotReady(snapshot, verifiedEpoch == dirtyEpoch, age, status.maximumAge)
	return snapshot
}

func healthSnapshotReady(snapshot domain.HealthSnapshot, verificationCurrent bool, age, maximumAge time.Duration) bool {
	return snapshot.Live && snapshot.DataPlaneAvailable && verificationCurrent && snapshot.LastError == "" &&
		!snapshot.LastSuccess.IsZero() && age >= 0 && age <= maximumAge && snapshot.Phase != domain.RuntimeStarting &&
		snapshot.Phase != domain.RuntimeQuarantined && snapshot.Phase != domain.RuntimeStopping
}

func (status *Status) setUnavailablePhase(phase domain.RuntimePhase) {
	status.mutex.Lock()
	defer status.mutex.Unlock()
	status.snapshot.Phase = phase
	status.snapshot.DataPlaneAvailable = false
}
