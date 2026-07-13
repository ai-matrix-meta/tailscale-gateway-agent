package application

import (
	"slices"
	"sync"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

type Status struct {
	mutex      sync.RWMutex
	maximumAge time.Duration
	now        func() time.Time
	snapshot   domain.HealthSnapshot
	dirtyEpoch uint64
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
	status.setPhase(domain.RuntimeQuarantined)
}

func (status *Status) MarkDirty() {
	status.mutex.Lock()
	defer status.mutex.Unlock()
	status.dirtyEpoch++
	status.snapshot.Phase = domain.RuntimeReconciling
}

func (status *Status) MarkStopping() {
	status.setPhase(domain.RuntimeStopping)
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

func (status *Status) RecordSuccess(at time.Time, observedEpoch uint64, conditions []domain.ReconcileCondition) bool {
	status.mutex.Lock()
	defer status.mutex.Unlock()
	status.snapshot.LastAttempt = at
	status.snapshot.LastSuccess = at
	status.snapshot.LastError = ""
	status.snapshot.SuccessfulRuns++
	status.snapshot.ConsecutiveErrors = 0
	status.snapshot.Conditions = slices.Clone(conditions)
	if status.dirtyEpoch != observedEpoch {
		status.snapshot.Phase = domain.RuntimeReconciling
		return false
	}
	if len(conditions) != 0 {
		status.snapshot.Phase = domain.RuntimeDegraded
		return false
	}
	status.snapshot.Phase = domain.RuntimeReady
	return true
}

func (status *Status) RecordFailure(at time.Time, err error) {
	status.mutex.Lock()
	defer status.mutex.Unlock()
	status.snapshot.Phase = domain.RuntimeDegraded
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
	status.mutex.RUnlock()
	age := status.now().Sub(snapshot.LastSuccess)
	snapshot.Ready = snapshot.Live && snapshot.Phase == domain.RuntimeReady && snapshot.LastError == "" && !snapshot.LastSuccess.IsZero() && age >= 0 && age <= status.maximumAge
	return snapshot
}

func (status *Status) setPhase(phase domain.RuntimePhase) {
	status.mutex.Lock()
	defer status.mutex.Unlock()
	status.snapshot.Phase = phase
}
