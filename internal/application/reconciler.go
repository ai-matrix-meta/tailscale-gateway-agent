package application

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/port"
)

type ControllerDependencies struct {
	Kernel             port.KernelPrerequisiteChecker
	ProxyTunnel        port.ProxyTunnelDiscovery
	Network            port.NetworkDiscovery
	Routing            port.RoutingStore
	PacketFilter       port.PacketFilterStore
	Resolver           port.DNSResolver
	Tailnet            port.TailnetControl
	InternetCapability InternetCapabilityObserver
	Logger             *slog.Logger
}

type cachedDomainAddresses struct {
	addresses domain.ResolvedAddresses
	updatedAt time.Time
}

type Controller struct {
	configuration domain.Configuration
	dependencies  ControllerDependencies
	now           func() time.Time

	addressCache     map[string]cachedDomainAddresses
	lastPacketPolicy domain.PacketFilterPolicy
	hasPacketPolicy  bool
	lastTailnetLink  domain.LinkIdentity
	quarantined      bool
}

func NewController(configuration domain.Configuration, dependencies ControllerDependencies) (*Controller, error) {
	if err := configuration.Validate(); err != nil {
		return nil, fmt.Errorf("invalid controller configuration: %w", err)
	}
	if dependencies.Kernel == nil || dependencies.ProxyTunnel == nil || dependencies.Network == nil || dependencies.Routing == nil || dependencies.PacketFilter == nil || dependencies.Resolver == nil || dependencies.Tailnet == nil {
		return nil, errors.New("all controller dependencies are required")
	}
	if configuration.Tailnet.AdvertiseExitNode && dependencies.InternetCapability == nil {
		return nil, errors.New("internet capability observer is required when Exit advertisement is enabled")
	}
	if !configuration.Tailnet.AdvertiseExitNode && dependencies.InternetCapability != nil {
		return nil, errors.New("internet capability observer requires Exit advertisement to be enabled")
	}
	if dependencies.Logger == nil {
		dependencies.Logger = slog.Default()
	}
	return &Controller{
		configuration: configuration,
		dependencies:  dependencies,
		now:           time.Now,
		addressCache:  make(map[string]cachedDomainAddresses),
		quarantined:   true,
	}, nil
}

func (controller *Controller) Prepare(ctx context.Context) error {
	policy := controller.safetyPacketFilterPolicy()
	if _, err := controller.reconcilePacketFilter(ctx, policy); err != nil {
		return fmt.Errorf("establish forwarding quarantine: %w", err)
	}
	controller.lastPacketPolicy = policy
	controller.hasPacketPolicy = true
	controller.quarantined = true
	if _, err := controller.reconcileRouting(ctx, buildSafetyRouting(controller.configuration)); err != nil {
		return fmt.Errorf("establish fail-closed routing baseline: %w", err)
	}
	if err := controller.dependencies.Kernel.Check(ctx); err != nil {
		return fmt.Errorf("verify kernel prerequisites: %w", err)
	}
	if !controller.configuration.PacketFilter.LocalEgress.Enabled {
		return nil
	}

	resolverSnapshot, err := controller.dependencies.Resolver.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("read DNS resolver snapshot: %w", err)
	}
	localEgressAddresses, err := controller.resolveLocalEgress(ctx, resolverSnapshot)
	if err != nil {
		return fmt.Errorf("prepare local control-plane destinations: %w", err)
	}
	proxyTunnelLink, err := controller.dependencies.ProxyTunnel.DiscoverProxyTunnel(ctx, domain.ProxyTunnelDiscoveryRequest{
		Addresses: slices.Clone(controller.configuration.Network.ProxyTunnelAddresses),
	})
	if err != nil {
		return fmt.Errorf("discover proxy tunnel before managed process startup: %w", err)
	}
	if err := proxyTunnelLink.Validate(); err != nil {
		return fmt.Errorf("validate proxy tunnel before managed process startup: %w", err)
	}
	if _, err := controller.reconcileRouting(ctx, buildPreparedRouting(controller.configuration, proxyTunnelLink)); err != nil {
		return fmt.Errorf("prepare local control-plane routing: %w", err)
	}
	policy = controller.packetFilterPolicy(domain.NetworkSnapshot{}, localEgressAddresses, true)
	if _, err := controller.reconcilePacketFilter(ctx, policy); err != nil {
		return fmt.Errorf("prepare local control-plane packet marking: %w", err)
	}
	controller.lastPacketPolicy = policy
	return nil
}

func (controller *Controller) Reconcile(ctx context.Context) (domain.ReconcileReport, error) {
	report := domain.ReconcileReport{}
	disabledPreferences := domain.NewTailnetPreferences(nil)
	if err := controller.dependencies.Kernel.Check(ctx); err != nil {
		return report, fmt.Errorf("verify kernel prerequisites: %w", err)
	}
	tailnetState, err := controller.readTailnetState(ctx)
	if err != nil {
		return report, err
	}
	if !tailnetState.Running {
		return report, errors.New("tailscale backend is not running")
	}
	if !tailnetState.KernelTunnel {
		return report, errors.New("tailscale backend is not using a kernel tunnel")
	}
	if len(tailnetState.SelfAddresses) == 0 {
		return report, errors.New("tailscale backend reported no self addresses")
	}
	if controller.quarantined && !tailnetState.Preferences.Equal(disabledPreferences) {
		verifiedState, writeErr := controller.writeAndVerifyTailnetPreferences(ctx, disabledPreferences)
		if writeErr != nil {
			return report, fmt.Errorf("clear restored Tailscale advertisements: %w", writeErr)
		}
		report.TailnetWrites++
		report.Changed = true
		tailnetState = verifiedState
	}

	resolverSnapshot, err := controller.dependencies.Resolver.Snapshot(ctx)
	if err != nil {
		return report, fmt.Errorf("read DNS resolver snapshot: %w", err)
	}
	nameServers := resolverSnapshot.NameServers()
	if len(nameServers) == 0 {
		return report, errors.New("resolver configuration contains no usable nameservers")
	}
	localEgressAddresses, err := controller.resolveLocalEgress(ctx, resolverSnapshot)
	if err != nil {
		return report, err
	}
	request := domain.DiscoveryRequest{
		TailnetAddresses:     normalizeAddresses(tailnetState.SelfAddresses),
		ProxyTunnelAddresses: slices.Clone(controller.configuration.Network.ProxyTunnelAddresses),
		AdvertisedPrefixes:   slices.Clone(controller.configuration.Tailnet.AdvertiseRoutes),
		NameServers:          slices.Clone(nameServers),
	}
	if err := request.Validate(); err != nil {
		return report, fmt.Errorf("build network discovery request: %w", err)
	}
	snapshot, err := controller.dependencies.Network.Discover(ctx, request)
	if err != nil {
		return report, fmt.Errorf("discover network state: %w", err)
	}
	if err := snapshot.Validate(request); err != nil {
		return report, fmt.Errorf("validate network discovery: %w", err)
	}
	controller.lastTailnetLink = snapshot.TailnetLink

	activeExitDefaultRoutes := domain.ExitDefaultRouteSet{}
	if controller.configuration.Tailnet.AdvertiseExitNode {
		capabilitySnapshot, capabilityErr := controller.dependencies.InternetCapability.Observe(ctx, snapshot.ProxyTunnelLink)
		if capabilityErr != nil {
			return report, fmt.Errorf("observe Internet capability: %w", capabilityErr)
		}
		evaluation, evaluationErr := evaluateInternetCapability(capabilitySnapshot, snapshot.ProxyTunnelLink, controller.now())
		if evaluationErr != nil {
			return report, evaluationErr
		}
		report.Conditions = append(report.Conditions, evaluation.conditions...)
		activeExitDefaultRoutes = evaluation.activeExitDefaultRoutes
	}
	desiredRouting := buildDesiredRouting(controller.configuration, snapshot, activeExitDefaultRoutes)
	desiredPolicy := controller.packetFilterPolicy(snapshot, localEgressAddresses, false)
	desiredPreferences := domain.NewTailnetPreferences(controller.configuration.Tailnet.AdvertiseRoutes)
	if !activeExitDefaultRoutes.Empty() {
		desiredPreferences = domain.NewTailnetExitNodePreferences(controller.configuration.Tailnet.AdvertiseRoutes)
	}
	nonExitPreferencesMatch := slices.Equal(tailnetState.Preferences.RoutesWithoutExitDefaults(), desiredPreferences.RoutesWithoutExitDefaults())
	routingChanges, err := controller.planRouting(ctx, desiredRouting)
	if err != nil {
		return report, err
	}
	exitDefaultTransition, onlyExitDefaultRoutesChanged := classifyExitDefaultRouteTransition(routingChanges, controller.configuration.Network)
	packetFilterObservation, err := controller.observePacketFilter(ctx, desiredPolicy)
	if err != nil {
		return report, err
	}
	if routingChanges.Empty() && packetFilterObservation.Matches(desiredPolicy) {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if !tailnetState.Preferences.Equal(desiredPreferences) {
			if err := controller.verifyDataPlane(ctx, desiredRouting, desiredPolicy); err != nil {
				return report, err
			}
			verifiedState, writeErr := controller.writeAndVerifyTailnetPreferences(ctx, desiredPreferences)
			if writeErr != nil {
				return report, fmt.Errorf("publish Tailscale advertisements after final data-plane verification: %w", writeErr)
			}
			report.TailnetWrites++
			report.Changed = true
			tailnetState = verifiedState
		}
		controller.lastPacketPolicy = desiredPolicy
		controller.hasPacketPolicy = true
		controller.quarantined = false
		controller.recordRouteApprovals(&report, tailnetState, desiredPreferences)
		return report, nil
	}
	isolatedExitDefaultTransition := nonExitPreferencesMatch && onlyExitDefaultRoutesChanged &&
		packetFilterObservation.Matches(desiredPolicy)
	if isolatedExitDefaultTransition {
		if !desiredPreferences.AdvertisesExitNode() && tailnetState.Preferences.HasExitDefaultRoutes() {
			verifiedState, writeErr := controller.writeAndVerifyTailnetPreferences(ctx, desiredPreferences)
			if writeErr != nil {
				return report, fmt.Errorf("withdraw Exit Node advertisement before deactivating its final route: %w", writeErr)
			}
			report.TailnetWrites++
			report.Changed = true
			tailnetState = verifiedState
		}
		routingWrites, applyErr := controller.applyExitDefaultRouteTransition(
			ctx, desiredRouting, exitDefaultTransition,
		)
		report.RoutingWrites += routingWrites
		report.Changed = report.Changed || routingWrites > 0
		if applyErr != nil {
			return report, applyErr
		}
		if err := controller.verifyDataPlane(ctx, desiredRouting, desiredPolicy); err != nil {
			return report, err
		}
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if !tailnetState.Preferences.Equal(desiredPreferences) {
			verifiedState, writeErr := controller.writeAndVerifyTailnetPreferences(ctx, desiredPreferences)
			if writeErr != nil {
				return report, fmt.Errorf("publish atomic Exit Node advertisement after route verification: %w", writeErr)
			}
			report.TailnetWrites++
			report.Changed = true
			tailnetState = verifiedState
		}
		controller.lastPacketPolicy = desiredPolicy
		controller.hasPacketPolicy = true
		controller.quarantined = false
		controller.recordRouteApprovals(&report, tailnetState, desiredPreferences)
		return report, nil
	}

	closedPolicy := desiredPolicy
	closedPolicy.GateClosed = true
	packetFilterWrites, err := controller.reconcilePacketFilter(ctx, closedPolicy)
	report.PacketFilterWrites += packetFilterWrites
	report.Changed = report.Changed || packetFilterWrites > 0
	if err != nil {
		return report, fmt.Errorf("close forwarding gate before applying drift: %w", err)
	}
	controller.lastPacketPolicy = closedPolicy
	controller.hasPacketPolicy = true
	controller.quarantined = true

	if !tailnetState.Preferences.Equal(disabledPreferences) {
		verifiedState, writeErr := controller.writeAndVerifyTailnetPreferences(ctx, disabledPreferences)
		if writeErr != nil {
			return report, fmt.Errorf("clear Tailscale advertisements before applying drift: %w", writeErr)
		}
		report.TailnetWrites++
		report.Changed = true
		tailnetState = verifiedState
	}

	routingWrites, err := controller.applyRoutingPlan(ctx, desiredRouting, routingChanges)
	report.RoutingWrites += routingWrites
	report.Changed = report.Changed || routingWrites > 0
	if err != nil {
		return report, err
	}
	packetFilterWrites, err = controller.reconcilePacketFilter(ctx, desiredPolicy)
	report.PacketFilterWrites += packetFilterWrites
	report.Changed = report.Changed || packetFilterWrites > 0
	if err != nil {
		return report, fmt.Errorf("open forwarding gate after convergence: %w", err)
	}
	if err := controller.verifyDataPlane(ctx, desiredRouting, desiredPolicy); err != nil {
		return report, err
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if !tailnetState.Preferences.Equal(desiredPreferences) {
		verifiedState, writeErr := controller.writeAndVerifyTailnetPreferences(ctx, desiredPreferences)
		if writeErr != nil {
			return report, fmt.Errorf("publish Tailscale advertisements: %w", writeErr)
		}
		report.TailnetWrites++
		report.Changed = true
		tailnetState = verifiedState
	} else {
		tailnetState, err = controller.readTailnetState(ctx)
		if err != nil {
			return report, fmt.Errorf("refresh Tailscale approval after data-plane convergence: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	controller.lastPacketPolicy = desiredPolicy
	controller.hasPacketPolicy = true
	controller.quarantined = false
	controller.recordRouteApprovals(&report, tailnetState, desiredPreferences)
	return report, nil
}

func (controller *Controller) applyExitDefaultRouteTransition(
	ctx context.Context,
	desiredRouting domain.RoutingState,
	transition exitDefaultRouteTransition,
) (int, error) {
	writes := 0
	if !transition.deactivationChanges.Empty() {
		deactivationWrites, err := controller.applyRoutingChanges(ctx, transition.deactivationChanges)
		writes += deactivationWrites
		if err != nil {
			return writes, fmt.Errorf("deactivate unavailable Exit default routes: %w", err)
		}
		if err := controller.verifyPendingRoutingChanges(ctx, desiredRouting, transition.activationChanges); err != nil {
			return writes, fmt.Errorf("verify Exit default route deactivation: %w", err)
		}
	}
	if !transition.activationChanges.Empty() {
		activationWrites, err := controller.applyRoutingPlan(ctx, desiredRouting, transition.activationChanges)
		writes += activationWrites
		if err != nil {
			return writes, fmt.Errorf("activate available Exit default routes: %w", err)
		}
	}
	return writes, nil
}

func (controller *Controller) FailClosed(ctx context.Context) (domain.ReconcileReport, error) {
	return controller.failClosed(ctx, true)
}

func (controller *Controller) failClosed(ctx context.Context, retainLocalControlEgress bool) (domain.ReconcileReport, error) {
	report := domain.ReconcileReport{}
	policy := controller.safetyPacketFilterPolicy()
	if controller.hasPacketPolicy {
		policy = controller.lastPacketPolicy
		policy.GateClosed = true
	}
	defer func() {
		controller.lastPacketPolicy = policy
		controller.hasPacketPolicy = true
		controller.quarantined = true
	}()
	writes, packetFilterErr := controller.reconcilePacketFilter(ctx, policy)
	report.PacketFilterWrites += writes
	report.Changed = writes > 0
	if cancellationErr := ctx.Err(); cancellationErr != nil {
		return report, errors.Join(
			wrapOptional("close forwarding quarantine", packetFilterErr),
			cancellationErr,
		)
	}

	strictRouting := buildFailClosedRouting(controller.configuration, controller.lastTailnetLink, domain.LinkIdentity{})
	desiredRouting := strictRouting
	var recoveryStateErr error
	var recoveryPolicyErr error
	recoveryReady := false
	if retainLocalControlEgress && controller.configuration.PacketFilter.LocalEgress.Enabled && packetFilterErr == nil {
		var recoveryPolicy domain.PacketFilterPolicy
		desiredRouting, recoveryPolicy, recoveryStateErr = controller.liveFailClosedState(ctx)
		if recoveryStateErr == nil {
			writes, recoveryPolicyErr = controller.reconcilePacketFilter(ctx, recoveryPolicy)
			report.PacketFilterWrites += writes
			report.Changed = report.Changed || writes > 0
			if recoveryPolicyErr == nil {
				policy = recoveryPolicy
				recoveryReady = true
			} else {
				desiredRouting = strictRouting
			}
		} else {
			desiredRouting = strictRouting
		}
	}

	routingWrites, routingErr := controller.reconcileRouting(ctx, desiredRouting)
	report.RoutingWrites += routingWrites
	report.Changed = report.Changed || routingWrites > 0
	if routingErr == nil && recoveryReady {
		if err := controller.verifyRouting(ctx, desiredRouting); err != nil {
			routingErr = fmt.Errorf("verify local control-plane recovery routing: %w", err)
		} else if err := controller.dependencies.Kernel.Check(ctx); err != nil {
			routingErr = fmt.Errorf("reverify kernel prerequisites for local control-plane recovery: %w", err)
		}
	}
	if routingErr != nil && recoveryReady {
		fallbackWrites, fallbackErr := controller.reconcileRouting(ctx, strictRouting)
		report.RoutingWrites += fallbackWrites
		report.Changed = report.Changed || fallbackWrites > 0
		routingErr = errors.Join(routingErr, wrapOptional("restore strict fail-closed routing after recovery-path failure", fallbackErr))
	}
	if cancellationErr := ctx.Err(); cancellationErr != nil {
		return report, errors.Join(
			wrapOptional("close forwarding quarantine", packetFilterErr),
			wrapOptional("verify local control-plane recovery path", recoveryStateErr),
			wrapOptional("refresh fail-closed local control-plane marking", recoveryPolicyErr),
			wrapOptional("establish fail-closed routing", routingErr),
			cancellationErr,
		)
	}

	tailnetState, readErr := controller.readTailnetState(ctx)
	var preferenceErr error
	if readErr == nil {
		disabled := domain.NewTailnetPreferences(nil)
		if !tailnetState.Preferences.Equal(disabled) {
			_, preferenceErr = controller.writeAndVerifyTailnetPreferences(ctx, disabled)
			if preferenceErr == nil {
				report.TailnetWrites++
				report.Changed = true
			}
		}
	}
	return report, errors.Join(
		wrapOptional("close forwarding quarantine", packetFilterErr),
		wrapOptional("verify local control-plane recovery path", recoveryStateErr),
		wrapOptional("refresh fail-closed local control-plane marking", recoveryPolicyErr),
		wrapOptional("establish fail-closed routing", routingErr),
		wrapOptional("read Tailscale state while failing closed", readErr),
		wrapOptional("clear Tailscale advertisements while failing closed", preferenceErr),
	)
}

func (controller *Controller) liveFailClosedState(ctx context.Context) (domain.RoutingState, domain.PacketFilterPolicy, error) {
	if err := controller.dependencies.Kernel.Check(ctx); err != nil {
		return domain.RoutingState{}, domain.PacketFilterPolicy{}, fmt.Errorf("verify kernel prerequisites: %w", err)
	}
	resolverSnapshot, err := controller.dependencies.Resolver.Snapshot(ctx)
	if err != nil {
		return domain.RoutingState{}, domain.PacketFilterPolicy{}, fmt.Errorf("read DNS resolver snapshot: %w", err)
	}
	localEgressAddresses, err := controller.resolveLocalEgress(ctx, resolverSnapshot)
	if err != nil {
		return domain.RoutingState{}, domain.PacketFilterPolicy{}, fmt.Errorf("resolve local control-plane destinations: %w", err)
	}
	proxyTunnelLink, err := controller.dependencies.ProxyTunnel.DiscoverProxyTunnel(ctx, domain.ProxyTunnelDiscoveryRequest{
		Addresses: slices.Clone(controller.configuration.Network.ProxyTunnelAddresses),
	})
	if err != nil {
		return domain.RoutingState{}, domain.PacketFilterPolicy{}, fmt.Errorf("discover proxy tunnel: %w", err)
	}
	if err := proxyTunnelLink.Validate(); err != nil {
		return domain.RoutingState{}, domain.PacketFilterPolicy{}, fmt.Errorf("validate proxy tunnel: %w", err)
	}
	return buildFailClosedRouting(controller.configuration, controller.lastTailnetLink, proxyTunnelLink),
		controller.packetFilterPolicy(domain.NetworkSnapshot{}, localEgressAddresses, true), nil
}

func (controller *Controller) Shutdown(ctx context.Context) error {
	_, err := controller.failClosed(ctx, false)
	return err
}

func (controller *Controller) reconcileRouting(ctx context.Context, desired domain.RoutingState) (int, error) {
	changes, err := controller.planRouting(ctx, desired)
	if err != nil {
		return 0, err
	}
	return controller.applyRoutingPlan(ctx, desired, changes)
}

func (controller *Controller) planRouting(ctx context.Context, desired domain.RoutingState) (domain.RoutingChanges, error) {
	ownership := routingOwnership(controller.configuration)
	observed, err := controller.dependencies.Routing.ReadRouting(ctx, ownership)
	if err != nil {
		return domain.RoutingChanges{}, fmt.Errorf("read managed routing state: %w", err)
	}
	changes, err := domain.DiffRouting(desired, observed, ownership)
	if err != nil {
		return domain.RoutingChanges{}, fmt.Errorf("plan managed routing changes: %w", err)
	}
	return changes, nil
}

func (controller *Controller) applyRoutingPlan(ctx context.Context, desired domain.RoutingState, changes domain.RoutingChanges) (int, error) {
	if changes.Empty() {
		return 0, nil
	}
	writes, err := controller.applyRoutingChanges(ctx, changes)
	if err != nil {
		return writes, err
	}
	if err := controller.verifyRouting(ctx, desired); err != nil {
		return writes, err
	}
	return writes, nil
}

func (controller *Controller) applyRoutingChanges(ctx context.Context, changes domain.RoutingChanges) (int, error) {
	if changes.Empty() {
		return 0, nil
	}
	writes, err := controller.dependencies.Routing.ApplyRouting(ctx, changes)
	if err != nil {
		return writes, fmt.Errorf("apply managed routing state: %w", err)
	}
	return writes, nil
}

func (controller *Controller) verifyPendingRoutingChanges(ctx context.Context, desired domain.RoutingState, expected domain.RoutingChanges) error {
	remaining, err := controller.planRouting(ctx, desired)
	if err != nil {
		return err
	}
	if !remaining.Equal(expected) {
		return fmt.Errorf("managed routing transition has unexpected pending changes: got %#v, want %#v", remaining, expected)
	}
	return nil
}

func (controller *Controller) verifyRouting(ctx context.Context, desired domain.RoutingState) error {
	ownership := routingOwnership(controller.configuration)
	verified, err := controller.dependencies.Routing.ReadRouting(ctx, ownership)
	if err != nil {
		return fmt.Errorf("verify managed routing state: %w", err)
	}
	remaining, err := domain.DiffRouting(desired, verified, ownership)
	if err != nil {
		return fmt.Errorf("validate verified managed routing state: %w", err)
	}
	if !remaining.Empty() {
		return fmt.Errorf("managed routing state did not converge: %#v", remaining)
	}
	return nil
}

func (controller *Controller) reconcilePacketFilter(ctx context.Context, policy domain.PacketFilterPolicy) (int, error) {
	observation, err := controller.observePacketFilter(ctx, policy)
	if err != nil {
		return 0, err
	}
	if observation.Matches(policy) {
		return 0, nil
	}
	if err := controller.dependencies.PacketFilter.Apply(ctx, policy, observation); err != nil {
		return 0, fmt.Errorf("apply managed nftables state: %w", err)
	}
	verified, err := controller.observePacketFilter(ctx, policy)
	if err != nil {
		return 1, fmt.Errorf("verify managed nftables state: %w", err)
	}
	if !verified.Matches(policy) {
		return 1, errors.New("managed nftables state did not converge")
	}
	return 1, nil
}

func (controller *Controller) observePacketFilter(ctx context.Context, policy domain.PacketFilterPolicy) (domain.PacketFilterObservation, error) {
	if err := policy.Validate(); err != nil {
		return domain.PacketFilterObservation{}, fmt.Errorf("validate desired nftables policy: %w", err)
	}
	observation, err := controller.dependencies.PacketFilter.Observe(ctx, policy)
	if err != nil {
		return domain.PacketFilterObservation{}, fmt.Errorf("observe managed nftables state: %w", err)
	}
	return observation, nil
}

func (controller *Controller) verifyDataPlane(ctx context.Context, routing domain.RoutingState, policy domain.PacketFilterPolicy) error {
	if err := controller.verifyRouting(ctx, routing); err != nil {
		return fmt.Errorf("final routing verification: %w", err)
	}
	observation, err := controller.observePacketFilter(ctx, policy)
	if err != nil {
		return fmt.Errorf("final nftables verification: %w", err)
	}
	if !observation.Matches(policy) {
		return errors.New("final nftables verification observed drift")
	}
	if err := controller.dependencies.Kernel.Check(ctx); err != nil {
		return fmt.Errorf("final kernel prerequisite verification: %w", err)
	}
	return nil
}

func (controller *Controller) resolveLocalEgress(ctx context.Context, resolver port.DNSResolverSnapshot) (domain.ResolvedAddresses, error) {
	configuration := controller.configuration.PacketFilter.LocalEgress
	if !configuration.Enabled {
		return domain.ResolvedAddresses{}, nil
	}
	now := controller.now()
	var combined []netip.Addr
	var resolutionErrors []error
	for _, domainName := range configuration.Domains {
		cached, exists := controller.addressCache[domainName]
		refreshDue := !exists || now.Sub(cached.updatedAt) >= configuration.RefreshInterval
		if refreshDue {
			addresses, err := resolver.Resolve(ctx, domainName)
			resolved := domain.NewResolvedAddresses(addresses)
			if err == nil && resolved.Empty() {
				err = errors.New("resolver returned no usable addresses")
			}
			if err == nil && !resolved.Empty() {
				cached = cachedDomainAddresses{addresses: resolved, updatedAt: now}
				controller.addressCache[domainName] = cached
				exists = true
			} else if !exists || now.Sub(cached.updatedAt) > configuration.MaximumStaleness {
				resolutionErrors = append(resolutionErrors, fmt.Errorf("resolve %s: %w", domainName, err))
				continue
			} else {
				controller.dependencies.Logger.WarnContext(ctx, "DNS resolution failed; retaining last-known-good addresses", "domain", domainName, "last_success", cached.updatedAt, "error", err)
			}
		}
		if exists {
			combined = append(combined, cached.addresses.All()...)
		}
	}
	if err := errors.Join(resolutionErrors...); err != nil {
		return domain.ResolvedAddresses{}, fmt.Errorf("resolve local-egress domains: %w", err)
	}
	resolved := domain.NewResolvedAddresses(combined)
	if resolved.Empty() {
		return domain.ResolvedAddresses{}, errors.New("local-egress domains resolved to an empty address set")
	}
	return resolved, nil
}

func (controller *Controller) safetyPacketFilterPolicy() domain.PacketFilterPolicy {
	configuration := controller.configuration
	return domain.PacketFilterPolicy{
		FilterTable:        configuration.PacketFilter.FilterTable,
		ForwardGuardChain:  configuration.PacketFilter.ForwardGuardChain,
		LocalEgressChain:   configuration.PacketFilter.LocalEgressChain,
		LocalEgressIPv4Set: configuration.PacketFilter.LocalEgressIPv4Set,
		LocalEgressIPv6Set: configuration.PacketFilter.LocalEgressIPv6Set,
		NATTable:           configuration.PacketFilter.NATTable,
		DNSMasqueradeChain: configuration.PacketFilter.DNSMasqueradeChain,
		GateClosed:         true,
		TailnetIPv4Prefix:  configuration.Network.TailnetIPv4Prefix,
		TailnetIPv6Prefix:  configuration.Network.TailnetIPv6Prefix,
	}
}

func (controller *Controller) packetFilterPolicy(snapshot domain.NetworkSnapshot, addresses domain.ResolvedAddresses, gateClosed bool) domain.PacketFilterPolicy {
	policy := controller.safetyPacketFilterPolicy()
	policy.GateClosed = gateClosed
	for _, path := range snapshot.DNSEgressPaths {
		policy.DNSTargets = append(policy.DNSTargets, domain.DNSSNATTarget{Address: path.NameServer, OutputInterface: path.Link.Name})
	}
	if !controller.configuration.PacketFilter.LocalEgress.Enabled {
		return policy
	}
	policy.LocalEgress = domain.LocalEgressPolicy{
		Enabled:   controller.configuration.PacketFilter.LocalEgress.Enabled,
		IPv4:      slices.Clone(addresses.IPv4),
		IPv6:      slices.Clone(addresses.IPv6),
		Protocols: slices.Clone(controller.configuration.PacketFilter.LocalEgress.Protocols),
		Ports:     slices.Clone(controller.configuration.PacketFilter.LocalEgress.Ports),
		Mark:      controller.configuration.Network.LocalEgressPacketMark,
	}
	return policy
}

func (controller *Controller) readTailnetState(ctx context.Context) (domain.TailnetState, error) {
	operationContext, cancel := context.WithTimeout(ctx, controller.configuration.Tailnet.OperationTimeout)
	defer cancel()
	state, err := controller.dependencies.Tailnet.ReadState(operationContext)
	if err != nil {
		return domain.TailnetState{}, fmt.Errorf("read Tailscale state: %w", err)
	}
	if err := state.Preferences.Validate(); err != nil {
		return domain.TailnetState{}, fmt.Errorf("validate Tailscale preferences: %w", err)
	}
	if err := state.Control.Validate(); err != nil {
		return domain.TailnetState{}, fmt.Errorf("validate Tailscale control observation: %w", err)
	}
	if !state.Control.SelfPresent {
		return domain.TailnetState{}, errors.New("tailscale status has no self node")
	}
	if !state.Control.InNetworkMap {
		return domain.TailnetState{}, errors.New("tailscale self node is absent from the current network map")
	}
	if !state.Control.Online {
		return domain.TailnetState{}, errors.New("tailscale control poll is offline")
	}
	if !state.Control.AllowedIPsAvailable {
		return domain.TailnetState{}, errors.New("tailscale self AllowedIPs is unavailable")
	}
	observationAge := controller.now().Sub(state.Control.ObservedAt)
	if observationAge < 0 || observationAge > controller.configuration.Tailnet.PreferenceAuditInterval {
		return domain.TailnetState{}, fmt.Errorf("tailscale control observation age %s is outside the freshness window", observationAge)
	}
	for _, address := range state.SelfAddresses {
		if !address.IsValid() || address.Zone() != "" {
			return domain.TailnetState{}, fmt.Errorf("tailscale reported invalid self address %q", address)
		}
	}
	normalized := normalizeAddresses(state.SelfAddresses)
	if len(normalized) != len(state.SelfAddresses) {
		return domain.TailnetState{}, errors.New("tailscale reported duplicate self addresses")
	}
	state.SelfAddresses = normalized
	selfPrefixes := make(map[netip.Prefix]struct{}, len(normalized))
	for _, address := range normalized {
		selfPrefixes[netip.PrefixFrom(address, address.BitLen())] = struct{}{}
	}
	for _, prefix := range state.Control.ApprovedRoutes {
		if _, selfAddress := selfPrefixes[prefix]; selfAddress {
			return domain.TailnetState{}, fmt.Errorf("tailscale approved routes still contain self address %s", prefix)
		}
	}
	state.Control.ApprovedRoutes = domain.NormalizeTailnetPreferences(state.Control.ApprovedRoutes).AdvertiseRoutes
	return state, nil
}

func (controller *Controller) writeTailnetPreferences(ctx context.Context, preferences domain.TailnetPreferences) error {
	if err := preferences.Validate(); err != nil {
		return fmt.Errorf("validate Tailscale preferences: %w", err)
	}
	operationContext, cancel := context.WithTimeout(ctx, controller.configuration.Tailnet.OperationTimeout)
	defer cancel()
	return controller.dependencies.Tailnet.WritePreferences(operationContext, preferences)
}

func (controller *Controller) writeAndVerifyTailnetPreferences(ctx context.Context, preferences domain.TailnetPreferences) (domain.TailnetState, error) {
	if err := controller.writeTailnetPreferences(ctx, preferences); err != nil {
		return domain.TailnetState{}, err
	}
	state, err := controller.readTailnetState(ctx)
	if err != nil {
		return domain.TailnetState{}, fmt.Errorf("verify Tailscale preferences: %w", err)
	}
	if !state.Preferences.Equal(preferences) {
		return domain.TailnetState{}, fmt.Errorf("tailscale preferences did not converge: got %v, want %v", state.Preferences.AdvertiseRoutes, preferences.AdvertiseRoutes)
	}
	return state, nil
}

func (controller *Controller) recordRouteApprovals(report *domain.ReconcileReport, state domain.TailnetState, desired domain.TailnetPreferences) {
	approved := make(map[netip.Prefix]struct{}, len(state.Control.ApprovedRoutes))
	for _, prefix := range state.Control.ApprovedRoutes {
		approved[prefix] = struct{}{}
	}
	report.ApprovalObserved = true
	report.RouteApprovals = make([]domain.RouteApproval, 0, len(desired.AdvertiseRoutes))
	for _, prefix := range desired.AdvertiseRoutes {
		_, exists := approved[prefix]
		report.RouteApprovals = append(report.RouteApprovals, domain.RouteApproval{Prefix: prefix, Approved: exists})
		if !exists {
			report.Conditions = append(report.Conditions, domain.ReconcileCondition{
				Kind: domain.ConditionRouteNotApproved, Family: domain.FamilyOfPrefix(prefix), Prefix: prefix,
			})
		}
	}
}

func normalizeAddresses(values []netip.Addr) []netip.Addr {
	result := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		value = value.Unmap()
		if value.IsValid() && value.Zone() == "" {
			result = append(result, value)
		}
	}
	slices.SortFunc(result, func(left, right netip.Addr) int { return left.Compare(right) })
	return slices.Compact(result)
}

func wrapOptional(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
