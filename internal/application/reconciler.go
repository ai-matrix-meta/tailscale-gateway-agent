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

type ReconcilerDependencies struct {
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

type Reconciler struct {
	configuration domain.Configuration
	dependencies  ReconcilerDependencies
	now           func() time.Time

	addressCache     map[string]cachedDomainAddresses
	lastPacketPolicy domain.PacketFilterPolicy
	hasPacketPolicy  bool
	lastTailnetLink  domain.LinkIdentity
	quarantined      bool
}

func NewReconciler(configuration domain.Configuration, dependencies ReconcilerDependencies) (*Reconciler, error) {
	if err := configuration.Validate(); err != nil {
		return nil, fmt.Errorf("invalid reconciler configuration: %w", err)
	}
	if dependencies.Kernel == nil || dependencies.ProxyTunnel == nil || dependencies.Network == nil || dependencies.Routing == nil || dependencies.PacketFilter == nil || dependencies.Resolver == nil || dependencies.Tailnet == nil {
		return nil, errors.New("all reconciler dependencies are required")
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
	return &Reconciler{
		configuration: configuration,
		dependencies:  dependencies,
		now:           time.Now,
		addressCache:  make(map[string]cachedDomainAddresses),
		quarantined:   true,
	}, nil
}

func (reconciler *Reconciler) Prepare(ctx context.Context) error {
	policy := reconciler.safetyPacketFilterPolicy()
	if _, err := reconciler.reconcilePacketFilter(ctx, policy); err != nil {
		return fmt.Errorf("establish forwarding quarantine: %w", err)
	}
	reconciler.lastPacketPolicy = policy
	reconciler.hasPacketPolicy = true
	reconciler.quarantined = true
	if _, err := reconciler.reconcileRouting(ctx, buildSafetyRouting(reconciler.configuration)); err != nil {
		return fmt.Errorf("establish fail-closed routing baseline: %w", err)
	}
	if err := reconciler.dependencies.Kernel.Check(ctx); err != nil {
		return fmt.Errorf("verify kernel prerequisites: %w", err)
	}
	if !reconciler.configuration.PacketFilter.LocalEgress.Enabled {
		return nil
	}

	resolverSnapshot, err := reconciler.dependencies.Resolver.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("read DNS resolver snapshot: %w", err)
	}
	localEgressAddresses, err := reconciler.resolveLocalEgress(ctx, resolverSnapshot)
	if err != nil {
		return fmt.Errorf("prepare local control-plane destinations: %w", err)
	}
	proxyTunnelLink, err := reconciler.dependencies.ProxyTunnel.DiscoverProxyTunnel(ctx, domain.ProxyTunnelDiscoveryRequest{
		Addresses: slices.Clone(reconciler.configuration.Network.ProxyTunnelAddresses),
	})
	if err != nil {
		return fmt.Errorf("discover proxy tunnel before managed process startup: %w", err)
	}
	if err := proxyTunnelLink.Validate(); err != nil {
		return fmt.Errorf("validate proxy tunnel before managed process startup: %w", err)
	}
	if _, err := reconciler.reconcileRouting(ctx, buildPreparedRouting(reconciler.configuration, proxyTunnelLink)); err != nil {
		return fmt.Errorf("prepare local control-plane routing: %w", err)
	}
	policy = reconciler.packetFilterPolicy(domain.NetworkSnapshot{}, localEgressAddresses, true)
	if _, err := reconciler.reconcilePacketFilter(ctx, policy); err != nil {
		return fmt.Errorf("prepare local control-plane packet marking: %w", err)
	}
	reconciler.lastPacketPolicy = policy
	return nil
}

func (reconciler *Reconciler) Reconcile(ctx context.Context) (domain.ReconcileReport, error) {
	report := domain.ReconcileReport{}
	disabledPreferences := domain.NewTailnetPreferences(nil)
	if err := reconciler.dependencies.Kernel.Check(ctx); err != nil {
		return report, fmt.Errorf("verify kernel prerequisites: %w", err)
	}
	tailnetState, err := reconciler.readTailnetState(ctx)
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
	if reconciler.quarantined && !tailnetState.Preferences.Equal(disabledPreferences) {
		verifiedState, writeErr := reconciler.writeAndVerifyTailnetPreferences(ctx, disabledPreferences)
		if writeErr != nil {
			return report, fmt.Errorf("clear restored Tailscale advertisements: %w", writeErr)
		}
		report.TailnetWrites++
		report.Changed = true
		tailnetState = verifiedState
	}

	resolverSnapshot, err := reconciler.dependencies.Resolver.Snapshot(ctx)
	if err != nil {
		return report, fmt.Errorf("read DNS resolver snapshot: %w", err)
	}
	nameServers := resolverSnapshot.NameServers()
	if len(nameServers) == 0 {
		return report, errors.New("resolver configuration contains no usable nameservers")
	}
	localEgressAddresses, err := reconciler.resolveLocalEgress(ctx, resolverSnapshot)
	if err != nil {
		return report, err
	}
	request := domain.DiscoveryRequest{
		TailnetAddresses:     normalizeAddresses(tailnetState.SelfAddresses),
		ProxyTunnelAddresses: slices.Clone(reconciler.configuration.Network.ProxyTunnelAddresses),
		AdvertisedPrefixes:   slices.Clone(reconciler.configuration.Tailnet.AdvertiseRoutes),
		NameServers:          slices.Clone(nameServers),
	}
	if err := request.Validate(); err != nil {
		return report, fmt.Errorf("build network discovery request: %w", err)
	}
	snapshot, err := reconciler.dependencies.Network.Discover(ctx, request)
	if err != nil {
		return report, fmt.Errorf("discover network state: %w", err)
	}
	if err := snapshot.Validate(request); err != nil {
		return report, fmt.Errorf("validate network discovery: %w", err)
	}
	reconciler.lastTailnetLink = snapshot.TailnetLink

	activeExitDefaultRoutes := domain.ExitDefaultRouteSet{}
	if reconciler.configuration.Tailnet.AdvertiseExitNode {
		capabilitySnapshot, capabilityErr := reconciler.dependencies.InternetCapability.Observe(ctx, snapshot.ProxyTunnelLink)
		if capabilityErr != nil {
			return report, fmt.Errorf("observe Internet capability: %w", capabilityErr)
		}
		evaluation, evaluationErr := evaluateInternetCapability(capabilitySnapshot, snapshot.ProxyTunnelLink, reconciler.now())
		if evaluationErr != nil {
			return report, evaluationErr
		}
		report.Conditions = append(report.Conditions, evaluation.conditions...)
		activeExitDefaultRoutes = evaluation.activeExitDefaultRoutes
	}
	desiredRouting := buildDesiredRouting(reconciler.configuration, snapshot, activeExitDefaultRoutes)
	desiredPolicy := reconciler.packetFilterPolicy(snapshot, localEgressAddresses, false)
	desiredPreferences := domain.NewTailnetPreferences(reconciler.configuration.Tailnet.AdvertiseRoutes)
	if !activeExitDefaultRoutes.Empty() {
		desiredPreferences = domain.NewTailnetExitNodePreferences(reconciler.configuration.Tailnet.AdvertiseRoutes)
	}
	nonExitPreferencesMatch := slices.Equal(tailnetState.Preferences.RoutesWithoutExitDefaults(), desiredPreferences.RoutesWithoutExitDefaults())
	routingChanges, err := reconciler.planRouting(ctx, desiredRouting)
	if err != nil {
		return report, err
	}
	exitDefaultTransition, onlyExitDefaultRoutesChanged := classifyExitDefaultRouteTransition(routingChanges, reconciler.configuration.Network)
	packetFilterObservation, err := reconciler.observePacketFilter(ctx, desiredPolicy)
	if err != nil {
		return report, err
	}
	if routingChanges.Empty() && packetFilterObservation.Matches(desiredPolicy) {
		return reconciler.reconcileNoDrift(
			ctx, report, tailnetState, desiredRouting, desiredPolicy, desiredPreferences, activeExitDefaultRoutes,
		)
	}
	isolatedExitDefaultTransition := nonExitPreferencesMatch && onlyExitDefaultRoutesChanged &&
		packetFilterObservation.Matches(desiredPolicy)
	if isolatedExitDefaultTransition {
		return reconciler.reconcileIsolatedExitDefaultTransition(
			ctx, report, tailnetState, desiredRouting, desiredPolicy, desiredPreferences, activeExitDefaultRoutes, exitDefaultTransition,
		)
	}

	return reconciler.reconcileGlobalDrift(
		ctx, report, tailnetState, desiredRouting, desiredPolicy, desiredPreferences, activeExitDefaultRoutes, routingChanges, disabledPreferences,
	)
}

func (reconciler *Reconciler) reconcileNoDrift(
	ctx context.Context,
	report domain.ReconcileReport,
	tailnetState domain.TailnetState,
	desiredRouting domain.RoutingState,
	desiredPolicy domain.PacketFilterPolicy,
	desiredPreferences domain.TailnetPreferences,
	activeExitDefaultRoutes domain.ExitDefaultRouteSet,
) (domain.ReconcileReport, error) {
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if !tailnetState.Preferences.Equal(desiredPreferences) {
		if err := reconciler.verifyDataPlane(ctx, desiredRouting, desiredPolicy); err != nil {
			return report, err
		}
		var writeErr error
		tailnetState, writeErr = reconciler.publishTailnetPreferences(
			ctx, &report, desiredPreferences, "publish Tailscale advertisements after final data-plane verification",
		)
		if writeErr != nil {
			return report, writeErr
		}
	}
	reconciler.finalizeSuccessfulReconcile(&report, tailnetState, desiredPreferences, activeExitDefaultRoutes, desiredPolicy)
	return report, nil
}

func (reconciler *Reconciler) reconcileIsolatedExitDefaultTransition(
	ctx context.Context,
	report domain.ReconcileReport,
	tailnetState domain.TailnetState,
	desiredRouting domain.RoutingState,
	desiredPolicy domain.PacketFilterPolicy,
	desiredPreferences domain.TailnetPreferences,
	activeExitDefaultRoutes domain.ExitDefaultRouteSet,
	transition exitDefaultRouteTransition,
) (domain.ReconcileReport, error) {
	if !desiredPreferences.AdvertisesExitNode() && tailnetState.Preferences.HasExitDefaultRoutes() {
		var writeErr error
		tailnetState, writeErr = reconciler.publishTailnetPreferences(
			ctx, &report, desiredPreferences, "withdraw Exit Node advertisement before deactivating its final route",
		)
		if writeErr != nil {
			return report, writeErr
		}
	}
	routingWrites, applyErr := reconciler.applyExitDefaultRouteTransition(ctx, desiredRouting, transition)
	report.RoutingWrites += routingWrites
	report.Changed = report.Changed || routingWrites > 0
	if applyErr != nil {
		return report, applyErr
	}
	if err := reconciler.verifyDataPlane(ctx, desiredRouting, desiredPolicy); err != nil {
		return report, err
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if !tailnetState.Preferences.Equal(desiredPreferences) {
		var writeErr error
		tailnetState, writeErr = reconciler.publishTailnetPreferences(
			ctx, &report, desiredPreferences, "publish atomic Exit Node advertisement after route verification",
		)
		if writeErr != nil {
			return report, writeErr
		}
	}
	reconciler.finalizeSuccessfulReconcile(&report, tailnetState, desiredPreferences, activeExitDefaultRoutes, desiredPolicy)
	return report, nil
}

func (reconciler *Reconciler) reconcileGlobalDrift(
	ctx context.Context,
	report domain.ReconcileReport,
	tailnetState domain.TailnetState,
	desiredRouting domain.RoutingState,
	desiredPolicy domain.PacketFilterPolicy,
	desiredPreferences domain.TailnetPreferences,
	activeExitDefaultRoutes domain.ExitDefaultRouteSet,
	routingChanges domain.RoutingChanges,
	disabledPreferences domain.TailnetPreferences,
) (domain.ReconcileReport, error) {
	closedPolicy := desiredPolicy
	closedPolicy.GateClosed = true
	packetFilterWrites, err := reconciler.reconcilePacketFilter(ctx, closedPolicy)
	report.PacketFilterWrites += packetFilterWrites
	report.Changed = report.Changed || packetFilterWrites > 0
	if err != nil {
		return report, fmt.Errorf("close forwarding gate before applying drift: %w", err)
	}
	reconciler.lastPacketPolicy = closedPolicy
	reconciler.hasPacketPolicy = true
	reconciler.quarantined = true

	if !tailnetState.Preferences.Equal(disabledPreferences) {
		var writeErr error
		tailnetState, writeErr = reconciler.publishTailnetPreferences(
			ctx, &report, disabledPreferences, "clear Tailscale advertisements before applying drift",
		)
		if writeErr != nil {
			return report, writeErr
		}
	}

	routingWrites, err := reconciler.applyRoutingPlan(ctx, desiredRouting, routingChanges)
	report.RoutingWrites += routingWrites
	report.Changed = report.Changed || routingWrites > 0
	if err != nil {
		return report, err
	}
	packetFilterWrites, err = reconciler.reconcilePacketFilter(ctx, desiredPolicy)
	report.PacketFilterWrites += packetFilterWrites
	report.Changed = report.Changed || packetFilterWrites > 0
	if err != nil {
		return report, fmt.Errorf("open forwarding gate after convergence: %w", err)
	}
	if err := reconciler.verifyDataPlane(ctx, desiredRouting, desiredPolicy); err != nil {
		return report, err
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if !tailnetState.Preferences.Equal(desiredPreferences) {
		var writeErr error
		tailnetState, writeErr = reconciler.publishTailnetPreferences(
			ctx, &report, desiredPreferences, "publish Tailscale advertisements",
		)
		if writeErr != nil {
			return report, writeErr
		}
	} else {
		tailnetState, err = reconciler.readTailnetState(ctx)
		if err != nil {
			return report, fmt.Errorf("refresh Tailscale approval after data-plane convergence: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	reconciler.finalizeSuccessfulReconcile(&report, tailnetState, desiredPreferences, activeExitDefaultRoutes, desiredPolicy)
	return report, nil
}

func (reconciler *Reconciler) publishTailnetPreferences(ctx context.Context, report *domain.ReconcileReport, preferences domain.TailnetPreferences, operation string) (domain.TailnetState, error) {
	verifiedState, writeErr := reconciler.writeAndVerifyTailnetPreferences(ctx, preferences)
	if writeErr != nil {
		return domain.TailnetState{}, fmt.Errorf("%s: %w", operation, writeErr)
	}
	report.TailnetWrites++
	report.Changed = true
	return verifiedState, nil
}

func (reconciler *Reconciler) finalizeSuccessfulReconcile(
	report *domain.ReconcileReport,
	tailnetState domain.TailnetState,
	desiredPreferences domain.TailnetPreferences,
	activeExitDefaultRoutes domain.ExitDefaultRouteSet,
	desiredPolicy domain.PacketFilterPolicy,
) {
	reconciler.lastPacketPolicy = desiredPolicy
	reconciler.hasPacketPolicy = true
	reconciler.quarantined = false
	reconciler.completeReconcileReport(report, tailnetState, desiredPreferences, activeExitDefaultRoutes)
}

func (reconciler *Reconciler) applyExitDefaultRouteTransition(
	ctx context.Context,
	desiredRouting domain.RoutingState,
	transition exitDefaultRouteTransition,
) (int, error) {
	writes := 0
	if !transition.deactivationChanges.Empty() {
		deactivationWrites, err := reconciler.applyRoutingChanges(ctx, transition.deactivationChanges)
		writes += deactivationWrites
		if err != nil {
			return writes, fmt.Errorf("deactivate unavailable Exit default routes: %w", err)
		}
		if err := reconciler.verifyPendingRoutingChanges(ctx, desiredRouting, transition.activationChanges); err != nil {
			return writes, fmt.Errorf("verify Exit default route deactivation: %w", err)
		}
	}
	if !transition.activationChanges.Empty() {
		activationWrites, err := reconciler.applyRoutingPlan(ctx, desiredRouting, transition.activationChanges)
		writes += activationWrites
		if err != nil {
			return writes, fmt.Errorf("activate available Exit default routes: %w", err)
		}
	}
	return writes, nil
}

func (reconciler *Reconciler) FailClosed(ctx context.Context) (domain.ReconcileReport, error) {
	return reconciler.failClosed(ctx, true)
}

func (reconciler *Reconciler) failClosed(ctx context.Context, retainLocalControlEgress bool) (domain.ReconcileReport, error) {
	report := domain.ReconcileReport{}
	policy := reconciler.safetyPacketFilterPolicy()
	if reconciler.hasPacketPolicy {
		policy = reconciler.lastPacketPolicy
		policy.GateClosed = true
	}
	defer func() {
		reconciler.lastPacketPolicy = policy
		reconciler.hasPacketPolicy = true
		reconciler.quarantined = true
	}()
	writes, packetFilterErr := reconciler.reconcilePacketFilter(ctx, policy)
	report.PacketFilterWrites += writes
	report.Changed = writes > 0
	if cancellationErr := ctx.Err(); cancellationErr != nil {
		return report, errors.Join(
			wrapOptional("close forwarding quarantine", packetFilterErr),
			cancellationErr,
		)
	}

	strictRouting := buildFailClosedRouting(reconciler.configuration, reconciler.lastTailnetLink, domain.LinkIdentity{})
	desiredRouting := strictRouting
	var recoveryStateErr error
	var recoveryPolicyErr error
	recoveryReady := false
	if retainLocalControlEgress && reconciler.configuration.PacketFilter.LocalEgress.Enabled && packetFilterErr == nil {
		var recoveryPolicy domain.PacketFilterPolicy
		desiredRouting, recoveryPolicy, recoveryStateErr = reconciler.liveFailClosedState(ctx)
		if recoveryStateErr == nil {
			writes, recoveryPolicyErr = reconciler.reconcilePacketFilter(ctx, recoveryPolicy)
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

	routingWrites, routingErr := reconciler.reconcileRouting(ctx, desiredRouting)
	report.RoutingWrites += routingWrites
	report.Changed = report.Changed || routingWrites > 0
	if routingErr == nil && recoveryReady {
		if err := reconciler.verifyRouting(ctx, desiredRouting); err != nil {
			routingErr = fmt.Errorf("verify local control-plane recovery routing: %w", err)
		} else if err := reconciler.dependencies.Kernel.Check(ctx); err != nil {
			routingErr = fmt.Errorf("reverify kernel prerequisites for local control-plane recovery: %w", err)
		}
	}
	if routingErr != nil && recoveryReady {
		fallbackWrites, fallbackErr := reconciler.reconcileRouting(ctx, strictRouting)
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

	tailnetState, readErr := reconciler.readTailnetState(ctx)
	var preferenceErr error
	if readErr == nil {
		disabled := domain.NewTailnetPreferences(nil)
		if !tailnetState.Preferences.Equal(disabled) {
			_, preferenceErr = reconciler.writeAndVerifyTailnetPreferences(ctx, disabled)
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

func (reconciler *Reconciler) liveFailClosedState(ctx context.Context) (domain.RoutingState, domain.PacketFilterPolicy, error) {
	if err := reconciler.dependencies.Kernel.Check(ctx); err != nil {
		return domain.RoutingState{}, domain.PacketFilterPolicy{}, fmt.Errorf("verify kernel prerequisites: %w", err)
	}
	resolverSnapshot, err := reconciler.dependencies.Resolver.Snapshot(ctx)
	if err != nil {
		return domain.RoutingState{}, domain.PacketFilterPolicy{}, fmt.Errorf("read DNS resolver snapshot: %w", err)
	}
	localEgressAddresses, err := reconciler.resolveLocalEgress(ctx, resolverSnapshot)
	if err != nil {
		return domain.RoutingState{}, domain.PacketFilterPolicy{}, fmt.Errorf("resolve local control-plane destinations: %w", err)
	}
	proxyTunnelLink, err := reconciler.dependencies.ProxyTunnel.DiscoverProxyTunnel(ctx, domain.ProxyTunnelDiscoveryRequest{
		Addresses: slices.Clone(reconciler.configuration.Network.ProxyTunnelAddresses),
	})
	if err != nil {
		return domain.RoutingState{}, domain.PacketFilterPolicy{}, fmt.Errorf("discover proxy tunnel: %w", err)
	}
	if err := proxyTunnelLink.Validate(); err != nil {
		return domain.RoutingState{}, domain.PacketFilterPolicy{}, fmt.Errorf("validate proxy tunnel: %w", err)
	}
	return buildFailClosedRouting(reconciler.configuration, reconciler.lastTailnetLink, proxyTunnelLink),
		reconciler.packetFilterPolicy(domain.NetworkSnapshot{}, localEgressAddresses, true), nil
}

func (reconciler *Reconciler) Shutdown(ctx context.Context) error {
	_, err := reconciler.failClosed(ctx, false)
	return err
}

func (reconciler *Reconciler) reconcileRouting(ctx context.Context, desired domain.RoutingState) (int, error) {
	changes, err := reconciler.planRouting(ctx, desired)
	if err != nil {
		return 0, err
	}
	return reconciler.applyRoutingPlan(ctx, desired, changes)
}

func (reconciler *Reconciler) planRouting(ctx context.Context, desired domain.RoutingState) (domain.RoutingChanges, error) {
	ownership := routingOwnership(reconciler.configuration)
	observed, err := reconciler.dependencies.Routing.ReadRouting(ctx, ownership)
	if err != nil {
		return domain.RoutingChanges{}, fmt.Errorf("read managed routing state: %w", err)
	}
	changes, err := domain.DiffRouting(desired, observed, ownership)
	if err != nil {
		return domain.RoutingChanges{}, fmt.Errorf("plan managed routing changes: %w", err)
	}
	return changes, nil
}

func (reconciler *Reconciler) applyRoutingPlan(ctx context.Context, desired domain.RoutingState, changes domain.RoutingChanges) (int, error) {
	if changes.Empty() {
		return 0, nil
	}
	writes, err := reconciler.applyRoutingChanges(ctx, changes)
	if err != nil {
		return writes, err
	}
	if err := reconciler.verifyRouting(ctx, desired); err != nil {
		return writes, err
	}
	return writes, nil
}

func (reconciler *Reconciler) applyRoutingChanges(ctx context.Context, changes domain.RoutingChanges) (int, error) {
	if changes.Empty() {
		return 0, nil
	}
	writes, err := reconciler.dependencies.Routing.ApplyRouting(ctx, changes)
	if err != nil {
		return writes, fmt.Errorf("apply managed routing state: %w", err)
	}
	return writes, nil
}

func (reconciler *Reconciler) verifyPendingRoutingChanges(ctx context.Context, desired domain.RoutingState, expected domain.RoutingChanges) error {
	remaining, err := reconciler.planRouting(ctx, desired)
	if err != nil {
		return err
	}
	if !remaining.Equal(expected) {
		return fmt.Errorf("managed routing transition has unexpected pending changes: got %#v, want %#v", remaining, expected)
	}
	return nil
}

func (reconciler *Reconciler) verifyRouting(ctx context.Context, desired domain.RoutingState) error {
	ownership := routingOwnership(reconciler.configuration)
	verified, err := reconciler.dependencies.Routing.ReadRouting(ctx, ownership)
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

func (reconciler *Reconciler) reconcilePacketFilter(ctx context.Context, policy domain.PacketFilterPolicy) (int, error) {
	observation, err := reconciler.observePacketFilter(ctx, policy)
	if err != nil {
		return 0, err
	}
	if observation.Matches(policy) {
		return 0, nil
	}
	if err := reconciler.dependencies.PacketFilter.Apply(ctx, policy, observation); err != nil {
		return 0, fmt.Errorf("apply managed nftables state: %w", err)
	}
	verified, err := reconciler.observePacketFilter(ctx, policy)
	if err != nil {
		return 1, fmt.Errorf("verify managed nftables state: %w", err)
	}
	if !verified.Matches(policy) {
		return 1, errors.New("managed nftables state did not converge")
	}
	return 1, nil
}

func (reconciler *Reconciler) observePacketFilter(ctx context.Context, policy domain.PacketFilterPolicy) (domain.PacketFilterObservation, error) {
	if err := policy.Validate(); err != nil {
		return domain.PacketFilterObservation{}, fmt.Errorf("validate desired nftables policy: %w", err)
	}
	observation, err := reconciler.dependencies.PacketFilter.Observe(ctx, policy)
	if err != nil {
		return domain.PacketFilterObservation{}, fmt.Errorf("observe managed nftables state: %w", err)
	}
	return observation, nil
}

func (reconciler *Reconciler) verifyDataPlane(ctx context.Context, routing domain.RoutingState, policy domain.PacketFilterPolicy) error {
	if err := reconciler.verifyRouting(ctx, routing); err != nil {
		return fmt.Errorf("final routing verification: %w", err)
	}
	observation, err := reconciler.observePacketFilter(ctx, policy)
	if err != nil {
		return fmt.Errorf("final nftables verification: %w", err)
	}
	if !observation.Matches(policy) {
		return errors.New("final nftables verification observed drift")
	}
	if err := reconciler.dependencies.Kernel.Check(ctx); err != nil {
		return fmt.Errorf("final kernel prerequisite verification: %w", err)
	}
	return nil
}

func (reconciler *Reconciler) resolveLocalEgress(ctx context.Context, resolver port.DNSResolverSnapshot) (domain.ResolvedAddresses, error) {
	configuration := reconciler.configuration.PacketFilter.LocalEgress
	if !configuration.Enabled {
		return domain.ResolvedAddresses{}, nil
	}
	now := reconciler.now()
	var combined []netip.Addr
	var resolutionErrors []error
	for _, domainName := range configuration.Domains {
		cached, exists := reconciler.addressCache[domainName]
		refreshDue := !exists || now.Sub(cached.updatedAt) >= configuration.RefreshInterval
		if refreshDue {
			addresses, err := resolver.Resolve(ctx, domainName)
			resolved := domain.NewResolvedAddresses(addresses)
			if err == nil && resolved.Empty() {
				err = errors.New("resolver returned no usable addresses")
			}
			if err == nil && !resolved.Empty() {
				cached = cachedDomainAddresses{addresses: resolved, updatedAt: now}
				reconciler.addressCache[domainName] = cached
				exists = true
			} else if !exists || now.Sub(cached.updatedAt) > configuration.MaximumStaleness {
				resolutionErrors = append(resolutionErrors, fmt.Errorf("resolve %s: %w", domainName, err))
				continue
			} else {
				reconciler.dependencies.Logger.WarnContext(ctx, "DNS resolution failed; retaining last-known-good addresses", "domain", domainName, "last_success", cached.updatedAt, "error", err)
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

func (reconciler *Reconciler) safetyPacketFilterPolicy() domain.PacketFilterPolicy {
	configuration := reconciler.configuration
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

func (reconciler *Reconciler) packetFilterPolicy(snapshot domain.NetworkSnapshot, addresses domain.ResolvedAddresses, gateClosed bool) domain.PacketFilterPolicy {
	policy := reconciler.safetyPacketFilterPolicy()
	policy.GateClosed = gateClosed
	for _, path := range snapshot.DNSEgressPaths {
		policy.DNSTargets = append(policy.DNSTargets, domain.DNSMasqueradeTarget{Address: path.NameServer, OutputInterface: path.Link.Name})
	}
	if !reconciler.configuration.PacketFilter.LocalEgress.Enabled {
		return policy
	}
	policy.LocalEgress = domain.LocalEgressPolicy{
		Enabled:   reconciler.configuration.PacketFilter.LocalEgress.Enabled,
		IPv4:      slices.Clone(addresses.IPv4),
		IPv6:      slices.Clone(addresses.IPv6),
		Protocols: slices.Clone(reconciler.configuration.PacketFilter.LocalEgress.Protocols),
		Ports:     slices.Clone(reconciler.configuration.PacketFilter.LocalEgress.Ports),
		Mark:      reconciler.configuration.Network.LocalEgressPacketMark,
	}
	return policy
}

func (reconciler *Reconciler) readTailnetState(ctx context.Context) (domain.TailnetState, error) {
	operationContext, cancel := context.WithTimeout(ctx, reconciler.configuration.Tailnet.OperationTimeout)
	defer cancel()
	state, err := reconciler.dependencies.Tailnet.ReadState(operationContext)
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
	observationAge := reconciler.now().Sub(state.Control.ObservedAt)
	if observationAge < 0 || observationAge > reconciler.configuration.Tailnet.PreferenceAuditInterval {
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

func (reconciler *Reconciler) writeTailnetPreferences(ctx context.Context, preferences domain.TailnetPreferences) error {
	if err := preferences.Validate(); err != nil {
		return fmt.Errorf("validate Tailscale preferences: %w", err)
	}
	operationContext, cancel := context.WithTimeout(ctx, reconciler.configuration.Tailnet.OperationTimeout)
	defer cancel()
	return reconciler.dependencies.Tailnet.WritePreferences(operationContext, preferences)
}

func (reconciler *Reconciler) writeAndVerifyTailnetPreferences(ctx context.Context, preferences domain.TailnetPreferences) (domain.TailnetState, error) {
	if err := reconciler.writeTailnetPreferences(ctx, preferences); err != nil {
		return domain.TailnetState{}, err
	}
	state, err := reconciler.readTailnetState(ctx)
	if err != nil {
		return domain.TailnetState{}, fmt.Errorf("verify Tailscale preferences: %w", err)
	}
	if !state.Preferences.Equal(preferences) {
		return domain.TailnetState{}, fmt.Errorf("tailscale preferences did not converge: got %v, want %v", state.Preferences.AdvertiseRoutes, preferences.AdvertiseRoutes)
	}
	return state, nil
}

func (reconciler *Reconciler) recordRouteApprovals(report *domain.ReconcileReport, state domain.TailnetState, desired domain.TailnetPreferences) {
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

func (reconciler *Reconciler) completeReconcileReport(
	report *domain.ReconcileReport,
	state domain.TailnetState,
	desired domain.TailnetPreferences,
	activeExitDefaultRoutes domain.ExitDefaultRouteSet,
) {
	reconciler.recordRouteApprovals(report, state, desired)
	report.DataPlaneAvailable = !reconciler.configuration.Tailnet.AdvertiseExitNode || !activeExitDefaultRoutes.Empty()
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
