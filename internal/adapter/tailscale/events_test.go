package tailscale

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

func TestNormalizeTailnetEventsDropsThirdPartyPayloads(t *testing.T) {
	state := ipn.Running
	got := normalizeTailnetEvents(ipn.Notify{
		State:         &state,
		InitialStatus: &ipnstate.Status{},
		PeersChanged:  []*tailcfg.Node{{}},
		SelfChange:    &tailcfg.Node{},
	})
	want := []domain.TailnetEvent{
		{Kind: domain.TailnetEventStateChanged},
		{Kind: domain.TailnetEventNetworkMap},
		{Kind: domain.TailnetEventSelfNode},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("normalized events = %#v, want %#v", got, want)
	}
	if got := normalizeTailnetEvents(ipn.Notify{}); len(got) != 0 {
		t.Fatalf("empty notification produced events: %#v", got)
	}
}

func TestSubscribeUsesBoundedIPNBusHintsAndReportsStreamFailure(t *testing.T) {
	watcher := newFakeIPNBusWatcher()
	var observedMask ipn.NotifyWatchOpt
	control := &Control{watchIPNBus: func(_ context.Context, mask ipn.NotifyWatchOpt) (ipnBusWatcher, error) {
		observedMask = mask
		return watcher, nil
	}}

	events, eventErrors, err := control.Subscribe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	watcher.steps <- ipnBusStep{notification: ipn.Notify{SelfChange: &tailcfg.Node{}}}
	watcher.steps <- ipnBusStep{err: errors.New("watch stream stopped")}

	select {
	case event := <-events:
		if event != (domain.TailnetEvent{Kind: domain.TailnetEventSelfNode}) {
			t.Fatalf("unexpected Tailnet event: %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("normalized Tailnet event was not delivered")
	}
	select {
	case streamErr := <-eventErrors:
		if streamErr == nil || !strings.Contains(streamErr.Error(), "watch stream stopped") {
			t.Fatalf("unexpected stream error: %v", streamErr)
		}
	case <-time.After(time.Second):
		t.Fatal("tailnet stream failure was not delivered")
	}
	select {
	case <-watcher.closed:
	case <-time.After(time.Second):
		t.Fatal("ipn bus watcher was not closed")
	}
	if observedMask != tailnetWatchMask {
		t.Fatalf("watch mask = %d, want %d", observedMask, tailnetWatchMask)
	}
}

func TestSubscribeReturnsConnectionFailureWithoutStartingAStream(t *testing.T) {
	wantErr := errors.New("tailscale LocalAPI unavailable")
	control := &Control{watchIPNBus: func(context.Context, ipn.NotifyWatchOpt) (ipnBusWatcher, error) {
		return nil, wantErr
	}}
	events, eventErrors, err := control.Subscribe(context.Background())
	if !errors.Is(err, wantErr) || events != nil || eventErrors != nil {
		t.Fatalf("unexpected subscription result: events=%v errors=%v err=%v", events, eventErrors, err)
	}
}

func TestSubscribeCancellationClosesWatcherWithoutReportingFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	watcher := &cancelableIPNBusWatcher{ctx: ctx, closed: make(chan struct{})}
	control := &Control{watchIPNBus: func(context.Context, ipn.NotifyWatchOpt) (ipnBusWatcher, error) {
		return watcher, nil
	}}
	events, eventErrors, err := control.Subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case _, open := <-events:
		if open {
			t.Fatal("event channel remained open after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("event channel did not close after cancellation")
	}
	select {
	case eventErr, open := <-eventErrors:
		if open || eventErr != nil {
			t.Fatalf("cancellation was reported as a stream failure: open=%v err=%v", open, eventErr)
		}
	case <-time.After(time.Second):
		t.Fatal("event error channel did not close after cancellation")
	}
	select {
	case <-watcher.closed:
	case <-time.After(time.Second):
		t.Fatal("watcher was not closed after cancellation")
	}
}

type ipnBusStep struct {
	notification ipn.Notify
	err          error
}

type fakeIPNBusWatcher struct {
	steps     chan ipnBusStep
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeIPNBusWatcher() *fakeIPNBusWatcher {
	return &fakeIPNBusWatcher{steps: make(chan ipnBusStep, 4), closed: make(chan struct{})}
}

func (watcher *fakeIPNBusWatcher) Next() (ipn.Notify, error) {
	step := <-watcher.steps
	return step.notification, step.err
}

func (watcher *fakeIPNBusWatcher) Close() error {
	watcher.closeOnce.Do(func() { close(watcher.closed) })
	return nil
}

type cancelableIPNBusWatcher struct {
	ctx       context.Context
	closed    chan struct{}
	closeOnce sync.Once
}

func (watcher *cancelableIPNBusWatcher) Next() (ipn.Notify, error) {
	<-watcher.ctx.Done()
	return ipn.Notify{}, watcher.ctx.Err()
}

func (watcher *cancelableIPNBusWatcher) Close() error {
	watcher.closeOnce.Do(func() { close(watcher.closed) })
	return nil
}
