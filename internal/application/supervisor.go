package application

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/port"
)

type SupervisorDependencies struct {
	Coordinator port.Coordinator
	Reconciler  *Reconciler
	Controller  *Controller
	Status      *Status
	Health      port.HealthServer
	Processes   port.ProcessLauncher
	Process     *domain.ProcessSpec
	Logger      *slog.Logger
}

type Supervisor struct {
	configuration domain.Configuration
	dependencies  SupervisorDependencies
}

func NewSupervisor(configuration domain.Configuration, dependencies SupervisorDependencies) (*Supervisor, error) {
	if err := configuration.Validate(); err != nil {
		return nil, fmt.Errorf("invalid supervisor configuration: %w", err)
	}
	if dependencies.Coordinator == nil || dependencies.Reconciler == nil || dependencies.Controller == nil || dependencies.Status == nil || dependencies.Health == nil {
		return nil, errors.New("all supervisor control-plane dependencies are required")
	}
	if dependencies.Process != nil && dependencies.Processes == nil {
		return nil, errors.New("process launcher is required for supervised process mode")
	}
	if dependencies.Logger == nil {
		dependencies.Logger = slog.Default()
	}
	return &Supervisor{configuration: configuration, dependencies: dependencies}, nil
}

type componentResult struct {
	name string
	err  error
}

func (supervisor *Supervisor) Run(parent context.Context) error {
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	results := make(chan componentResult, 2)
	go func() {
		results <- componentResult{name: "coordination", err: supervisor.dependencies.Coordinator.Run(ctx, supervisor.runOwned)}
	}()
	go func() {
		results <- componentResult{name: "health", err: supervisor.dependencies.Health.Run(ctx)}
	}()

	var supervisorErrors []error
	for completed := 0; completed < 2; completed++ {
		result := <-results
		if result.err == nil && context.Cause(ctx) == nil {
			result.err = errors.New("component exited unexpectedly")
		}
		if result.err != nil && !errors.Is(result.err, context.Canceled) {
			supervisorErrors = append(supervisorErrors, fmt.Errorf("%s: %w", result.name, result.err))
		}
		if context.Cause(ctx) == nil {
			cancel(result.err)
		}
	}
	return errors.Join(supervisorErrors...)
}

func (supervisor *Supervisor) runOwned(ctx context.Context) error {
	prepareContext, cancelPrepare := context.WithTimeout(ctx, supervisor.configuration.Runtime.ReconcileTimeout)
	prepareErr := supervisor.dependencies.Reconciler.Prepare(prepareContext)
	cancelPrepare()
	if prepareErr != nil {
		return errors.Join(fmt.Errorf("prepare gateway quarantine: %w", prepareErr), supervisor.shutdownReconciler(ctx))
	}
	supervisor.dependencies.Status.MarkQuarantined()

	var process port.ManagedProcess
	var processResult <-chan error
	if supervisor.dependencies.Process != nil {
		started, err := supervisor.dependencies.Processes.Start(*supervisor.dependencies.Process)
		if err != nil {
			return errors.Join(fmt.Errorf("start supervised process: %w", err), supervisor.shutdownReconciler(ctx))
		}
		process = started
		result := make(chan error, 1)
		go func() { result <- process.Wait() }()
		processResult = result
		supervisor.dependencies.Logger.InfoContext(ctx, "supervised process started", "executable", supervisor.dependencies.Process.Executable)
	}

	controlContext, cancelControl := context.WithCancelCause(ctx)
	controllerResult := make(chan error, 1)
	go func() { controllerResult <- supervisor.dependencies.Controller.Run(controlContext) }()

	var supervisorErrors []error
	controllerExited := false
	processExited := false
	select {
	case <-ctx.Done():
		cancelControl(context.Cause(ctx))
	case controllerErr := <-controllerResult:
		controllerExited = true
		if controllerErr == nil {
			controllerErr = errors.New("controller exited unexpectedly")
		}
		supervisorErrors = append(supervisorErrors, controllerErr)
		cancelControl(controllerErr)
	case processErr := <-processResult:
		processExited = true
		if processErr == nil {
			processErr = errors.New("supervised process exited without an error")
		}
		supervisorErrors = append(supervisorErrors, fmt.Errorf("supervised process exited unexpectedly: %w", processErr))
		cancelControl(processErr)
	}

	if !controllerExited {
		if controllerErr := <-controllerResult; controllerErr != nil && !errors.Is(controllerErr, context.Canceled) {
			supervisorErrors = append(supervisorErrors, fmt.Errorf("controller shutdown: %w", controllerErr))
		}
	}
	supervisor.dependencies.Status.MarkStopping()
	if shutdownErr := supervisor.shutdownReconciler(ctx); shutdownErr != nil {
		supervisorErrors = append(supervisorErrors, shutdownErr)
	}

	if process != nil && !processExited {
		shutdownContext, cancelShutdown := context.WithTimeout(context.WithoutCancel(ctx), supervisor.configuration.Runtime.ShutdownTimeout)
		terminateErr := process.Terminate(shutdownContext)
		cancelShutdown()
		if terminateErr != nil {
			supervisorErrors = append(supervisorErrors, fmt.Errorf("terminate supervised process: %w", terminateErr))
			supervisor.dependencies.Logger.ErrorContext(context.WithoutCancel(ctx), "supervised process termination failed", "error", terminateErr)
		} else {
			supervisor.dependencies.Logger.InfoContext(context.WithoutCancel(ctx), "supervised process stopped")
		}
	}
	return errors.Join(supervisorErrors...)
}

func (supervisor *Supervisor) shutdownReconciler(ctx context.Context) error {
	shutdownContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), supervisor.configuration.Runtime.ShutdownTimeout)
	defer cancel()
	if err := supervisor.dependencies.Reconciler.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("shutdown gateway reconciler: %w", err)
	}
	return nil
}
