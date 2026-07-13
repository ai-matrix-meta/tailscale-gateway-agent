//go:build linux

package netlink

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	vnetlink "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const maximumRouteNotificationDelay = 5 * time.Second

var errRouteEventSubscriptionClosed = errors.New("route event subscription closed before the kernel acknowledged a managed mutation")

type routeMutationKey struct {
	messageType uint16
	family      int
	table       int
	protocol    vnetlink.RouteProtocol
	routeType   int
	prefix      netip.Prefix
	metric      int
}

type routeMutationExpectation struct {
	key    routeMutationKey
	result chan error
}

type routeMutationTracker struct {
	mutex   sync.Mutex
	active  bool
	pending map[routeMutationKey][]*routeMutationExpectation
}

func (tracker *routeMutationTracker) activate() error {
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()
	if tracker.active {
		return errors.New("a route event subscription is already active")
	}
	if len(tracker.pending) != 0 {
		return errors.New("route mutation tracker contains stale expectations")
	}
	tracker.active = true
	tracker.pending = make(map[routeMutationKey][]*routeMutationExpectation)
	return nil
}

func (tracker *routeMutationTracker) deactivate(reason error) {
	if reason == nil {
		reason = errRouteEventSubscriptionClosed
	}
	tracker.mutex.Lock()
	if !tracker.active && len(tracker.pending) == 0 {
		tracker.mutex.Unlock()
		return
	}
	tracker.active = false
	pending := make([]*routeMutationExpectation, 0)
	for key, expectations := range tracker.pending {
		pending = append(pending, expectations...)
		delete(tracker.pending, key)
	}
	tracker.mutex.Unlock()
	for _, expectation := range pending {
		expectation.result <- reason
	}
}

func (tracker *routeMutationTracker) expect(messageType uint16, route *vnetlink.Route) (*routeMutationExpectation, error) {
	key, err := routeMutationIdentity(messageType, route)
	if err != nil {
		return nil, err
	}
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()
	if !tracker.active {
		return nil, nil
	}
	expectation := &routeMutationExpectation{key: key, result: make(chan error, 1)}
	tracker.pending[key] = append(tracker.pending[key], expectation)
	return expectation, nil
}

func (tracker *routeMutationTracker) acknowledge(update vnetlink.RouteUpdate) bool {
	key, err := routeMutationIdentity(update.Type, &update.Route)
	if err != nil {
		return false
	}
	tracker.mutex.Lock()
	expectations := tracker.pending[key]
	if len(expectations) == 0 {
		tracker.mutex.Unlock()
		return false
	}
	expectation := expectations[0]
	if len(expectations) == 1 {
		delete(tracker.pending, key)
	} else {
		tracker.pending[key] = expectations[1:]
	}
	tracker.mutex.Unlock()
	expectation.result <- nil
	return true
}

func (tracker *routeMutationTracker) cancel(expectation *routeMutationExpectation) bool {
	if expectation == nil {
		return false
	}
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()
	expectations := tracker.pending[expectation.key]
	for index, candidate := range expectations {
		if candidate != expectation {
			continue
		}
		expectations = append(expectations[:index], expectations[index+1:]...)
		if len(expectations) == 0 {
			delete(tracker.pending, expectation.key)
		} else {
			tracker.pending[expectation.key] = expectations
		}
		return true
	}
	return false
}

func (tracker *routeMutationTracker) wait(ctx context.Context, expectation *routeMutationExpectation) error {
	if expectation == nil {
		return nil
	}
	timer := time.NewTimer(maximumRouteNotificationDelay)
	defer timer.Stop()
	select {
	case err := <-expectation.result:
		return err
	case <-ctx.Done():
		if tracker.cancel(expectation) {
			return ctx.Err()
		}
		return <-expectation.result
	case <-timer.C:
		timeout := fmt.Errorf("kernel route notification was not observed within %s", maximumRouteNotificationDelay)
		if tracker.cancel(expectation) {
			return timeout
		}
		return <-expectation.result
	}
}

func (adapter *Adapter) replaceRoute(ctx context.Context, route *vnetlink.Route) error {
	expectation, err := adapter.routeMutations.expect(unix.RTM_NEWROUTE, route)
	if err != nil {
		return fmt.Errorf("register expected route replacement: %w", err)
	}
	if err := adapter.kernel.RouteReplace(route); err != nil {
		adapter.routeMutations.cancel(expectation)
		return err
	}
	if err := adapter.routeMutations.wait(ctx, expectation); err != nil {
		return fmt.Errorf("confirm route replacement notification: %w", err)
	}
	return nil
}

func (adapter *Adapter) deleteNetlinkRoute(ctx context.Context, route *vnetlink.Route) error {
	expectation, err := adapter.routeMutations.expect(unix.RTM_DELROUTE, route)
	if err != nil {
		return fmt.Errorf("register expected route deletion: %w", err)
	}
	if err := adapter.kernel.RouteDel(route); err != nil {
		adapter.routeMutations.cancel(expectation)
		return err
	}
	if err := adapter.routeMutations.wait(ctx, expectation); err != nil {
		return fmt.Errorf("confirm route deletion notification: %w", err)
	}
	return nil
}

func routeMutationIdentity(messageType uint16, route *vnetlink.Route) (routeMutationKey, error) {
	if messageType != unix.RTM_NEWROUTE && messageType != unix.RTM_DELROUTE {
		return routeMutationKey{}, fmt.Errorf("unsupported route notification type %d", messageType)
	}
	if route == nil {
		return routeMutationKey{}, errors.New("route mutation must not be nil")
	}
	family, validFamily := domainFamily(route.Family)
	if !validFamily {
		return routeMutationKey{}, fmt.Errorf("route mutation has unsupported family %d", route.Family)
	}
	prefix, err := canonicalRoutePrefix(family, route.Dst)
	if err != nil {
		return routeMutationKey{}, fmt.Errorf("route mutation destination: %w", err)
	}
	return routeMutationKey{
		messageType: messageType,
		family:      route.Family,
		table:       route.Table,
		protocol:    route.Protocol,
		routeType:   route.Type,
		prefix:      prefix,
		metric:      route.Priority,
	}, nil
}

func networkEventFromRouteUpdate(update vnetlink.RouteUpdate) domain.NetworkEvent {
	event := domain.NetworkEvent{
		Kind:      domain.NetworkEventRoute,
		Table:     update.Table,
		Protocol:  uint8(update.Protocol),
		RouteType: update.Route.Type,
		Metric:    update.Priority,
	}
	switch update.Type {
	case unix.RTM_NEWROUTE:
		event.Action = domain.NetworkEventUpsert
	case unix.RTM_DELROUTE:
		event.Action = domain.NetworkEventDelete
	}
	if family, ok := domainFamily(update.Family); ok {
		event.Family = family
		event.Prefix = domain.DefaultPrefix(family)
		if update.Dst != nil {
			if prefix := prefixFromIPNet(update.Dst); prefix.IsValid() {
				event.Prefix = prefix
			}
		}
	}
	return event
}

func domainFamily(family int) (domain.AddressFamily, bool) {
	switch family {
	case vnetlink.FAMILY_V4:
		return domain.IPv4, true
	case vnetlink.FAMILY_V6:
		return domain.IPv6, true
	default:
		return 0, false
	}
}
