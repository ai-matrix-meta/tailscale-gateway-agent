package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/adapter/environment"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/adapter/filelock"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/adapter/install"
	internetprobeadapter "github.com/ai-matrix-meta/tailscale-gateway-agent/internal/adapter/internetprobe"
	kerneladapter "github.com/ai-matrix-meta/tailscale-gateway-agent/internal/adapter/kernel"
	kubernetesadapter "github.com/ai-matrix-meta/tailscale-gateway-agent/internal/adapter/kubernetes"
	netlinkadapter "github.com/ai-matrix-meta/tailscale-gateway-agent/internal/adapter/netlink"
	nftablesadapter "github.com/ai-matrix-meta/tailscale-gateway-agent/internal/adapter/nftables"
	processadapter "github.com/ai-matrix-meta/tailscale-gateway-agent/internal/adapter/process"
	resolveradapter "github.com/ai-matrix-meta/tailscale-gateway-agent/internal/adapter/resolver"
	tailscaleadapter "github.com/ai-matrix-meta/tailscale-gateway-agent/internal/adapter/tailscale"
	telemetryadapter "github.com/ai-matrix-meta/tailscale-gateway-agent/internal/adapter/telemetry"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/application"
	capabilityapplication "github.com/ai-matrix-meta/tailscale-gateway-agent/internal/application/capability"
)

const (
	installedAgentPath = "/tools/tailscale-gateway-agent"
	containerbootPath  = "/usr/local/bin/containerboot"
)

var (
	version   = "development"
	commit    = "unknown"
	buildDate = "unknown"
)

func Run(ctx context.Context, arguments []string) error {
	command := "run"
	if len(arguments) > 0 {
		command = arguments[0]
	}
	if len(arguments) > 1 {
		return fmt.Errorf("command %q does not accept positional arguments", command)
	}

	switch command {
	case "run":
		return runAgent(ctx, false)
	case "supervise-containerboot":
		return runAgent(ctx, true)
	case "install":
		if err := install.CopySelf(installedAgentPath); err != nil {
			return fmt.Errorf("install gateway agent: %w", err)
		}
		return nil
	case "version":
		_, err := fmt.Fprintf(os.Stdout, "tailscale-gateway-agent version=%s commit=%s build_date=%s\n", version, commit, buildDate)
		return err
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func runAgent(ctx context.Context, superviseContainerboot bool) error {
	configuration, err := environment.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	var childEnvironment []string
	mode := application.RuntimeModeExternal
	if superviseContainerboot {
		mode = application.RuntimeModeSuperviseContainerboot
	}
	if err := application.ValidateRuntimeMode(configuration, mode); err != nil {
		return err
	}
	if superviseContainerboot {
		childEnvironment, err = environment.ContainerbootEnvironment()
		if err != nil {
			return fmt.Errorf("build containerboot environment: %w", err)
		}
	}

	logger := configureLogger(configuration.Runtime.LogLevel)
	logger.InfoContext(ctx, "starting gateway agent", "version", version, "commit", commit, "mode", mode)

	internetProber, err := configureInternetProber(
		configuration.Tailnet.AdvertiseExitNode,
		configuration.InternetCapability.IPv4ProbeURL,
		configuration.InternetCapability.IPv6ProbeURL,
		configuration.InternetCapability.ProbeTimeout,
	)
	if err != nil {
		return err
	}

	var ownershipCoordinator interface {
		Run(context.Context, func(context.Context) error) error
	}
	if superviseContainerboot {
		ownershipCoordinator, err = kubernetesadapter.NewCoordinator(configuration.Coordination)
		if err != nil {
			return fmt.Errorf("configure Kubernetes coordination: %w", err)
		}
	} else {
		ownershipCoordinator = filelock.NewCoordinator(configuration.Coordination)
	}

	network, err := netlinkadapter.New()
	if err != nil {
		return fmt.Errorf("configure rtnetlink adapter: %w", err)
	}
	defer func() {
		if closeErr := network.Close(); closeErr != nil {
			logger.ErrorContext(context.WithoutCancel(ctx), "close rtnetlink adapter", "error", closeErr)
		}
	}()

	resolver := resolveradapter.New(configuration.Runtime.ResolverPath, configuration.Runtime.DNSLookupTimeout)
	packetFilter := nftablesadapter.New()
	tailnet := tailscaleadapter.NewControl(configuration.Tailnet.SocketPath)
	status := application.NewStatus(configuration.Runtime.ReadinessMaximumAge)
	telemetry, err := telemetryadapter.New(configuration.Runtime.HealthListenAddress, status, logger)
	if err != nil {
		return fmt.Errorf("configure telemetry: %w", err)
	}
	defer func() {
		if closeErr := telemetry.Close(); closeErr != nil {
			logger.ErrorContext(context.WithoutCancel(ctx), "close telemetry listener", "error", closeErr)
		}
	}()
	var internetCapability application.InternetCapabilityObserver
	if internetProber != nil {
		tracker, trackerErr := capabilityapplication.NewTracker(
			configuration.InternetCapability,
			configuration.Network.LocalEgressPacketMark,
			internetProber,
			telemetry,
		)
		if trackerErr != nil {
			return fmt.Errorf("configure Internet capability tracker: %w", trackerErr)
		}
		internetCapability = tracker
	}
	reconciler, err := application.NewReconciler(configuration, application.ReconcilerDependencies{
		Kernel: kerneladapter.NewForwardingChecker(), ProxyTunnel: network, Network: network, Routing: network,
		PacketFilter: packetFilter, Resolver: resolver, Tailnet: tailnet, InternetCapability: internetCapability, Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("configure reconciler: %w", err)
	}
	controller, err := application.NewController(configuration, reconciler, network, tailnet, status, telemetry, logger)
	if err != nil {
		return fmt.Errorf("configure controller: %w", err)
	}

	dependencies := application.SupervisorDependencies{
		Coordinator: ownershipCoordinator,
		Reconciler:  reconciler,
		Controller:  controller,
		Status:      status,
		Health:      telemetry,
		Logger:      logger,
	}
	if superviseContainerboot {
		processSpecification := processadapter.NewSpecification(containerbootPath, nil, childEnvironment)
		dependencies.Processes = processadapter.NewLauncher()
		dependencies.Process = &processSpecification
	}
	supervisor, err := application.NewSupervisor(configuration, dependencies)
	if err != nil {
		return fmt.Errorf("configure supervisor: %w", err)
	}
	return supervisor.Run(ctx)
}

func configureInternetProber(advertiseExitNode bool, ipv4URL, ipv6URL string, timeout time.Duration) (*internetprobeadapter.Adapter, error) {
	if !advertiseExitNode {
		return nil, nil
	}
	prober, err := internetprobeadapter.New(ipv4URL, ipv6URL, timeout)
	if err != nil {
		return nil, fmt.Errorf("configure internet capability prober: %w", err)
	}
	return prober, nil
}

func configureLogger(level string) *slog.Logger {
	var slogLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slogLevel}))
	slog.SetDefault(logger)
	return logger
}
