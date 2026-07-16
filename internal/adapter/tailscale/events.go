package tailscale

import (
	"context"
	"errors"
	"fmt"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"tailscale.com/ipn"
)

const tailnetWatchMask = ipn.NotifyInitialState |
	ipn.NotifyInitialStatus |
	ipn.NotifyPeerChanges |
	ipn.NotifyNoNetMap |
	ipn.NotifyRateLimit

type ipnBusWatcher interface {
	Next() (ipn.Notify, error)
	Close() error
}

type watchIPNBusFunc func(context.Context, ipn.NotifyWatchOpt) (ipnBusWatcher, error)

func (control *Control) Subscribe(ctx context.Context) (<-chan domain.TailnetEvent, <-chan error, error) {
	if ctx == nil {
		return nil, nil, errors.New("tailnet event subscription context is required")
	}
	if control.watchIPNBus == nil {
		return nil, nil, errors.New("tailnet event watcher is not configured")
	}
	watcher, err := control.watchIPNBus(ctx, tailnetWatchMask)
	if err != nil {
		return nil, nil, fmt.Errorf("open LocalAPI IPN bus watch: %w", err)
	}
	if watcher == nil {
		return nil, nil, errors.New("tailscale LocalAPI returned a nil IPN bus watcher")
	}

	events := make(chan domain.TailnetEvent, 1)
	eventErrors := make(chan error, 1)
	go forwardTailnetEvents(ctx, watcher, events, eventErrors)
	return events, eventErrors, nil
}

func forwardTailnetEvents(ctx context.Context, watcher ipnBusWatcher, events chan<- domain.TailnetEvent, eventErrors chan<- error) {
	defer close(events)
	defer close(eventErrors)
	defer watcher.Close()

	for {
		notification, err := watcher.Next()
		if err != nil {
			if ctx.Err() == nil {
				select {
				case eventErrors <- fmt.Errorf("read LocalAPI IPN bus: %w", err):
				case <-ctx.Done():
				}
			}
			return
		}
		for _, event := range normalizeTailnetEvents(notification) {
			select {
			case events <- event:
			case <-ctx.Done():
				return
			default:
				// A queued hint already forces a fresh authoritative LocalAPI read.
			}
		}
	}
}

func normalizeTailnetEvents(notification ipn.Notify) []domain.TailnetEvent {
	events := make([]domain.TailnetEvent, 0, 3)
	if notification.State != nil || notification.InitialStatus != nil {
		events = append(events, domain.TailnetEvent{Kind: domain.TailnetEventStateChanged})
	}
	if len(notification.PeersChanged) != 0 || len(notification.PeersRemoved) != 0 || len(notification.PeerChangedPatch) != 0 {
		events = append(events, domain.TailnetEvent{Kind: domain.TailnetEventNetworkMap})
	}
	if notification.SelfChange != nil {
		events = append(events, domain.TailnetEvent{Kind: domain.TailnetEventSelfNode})
	}
	return events
}
