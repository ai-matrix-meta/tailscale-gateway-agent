package application

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/port"
)

type RuntimeDependencies struct {
	Coordinator port.Coordinator
	Controller  *Controller
	Runner      *Runner
	Status      *Status
	Health      port.HealthServer
	Processes   port.ProcessLauncher
	Process     *domain.ProcessSpec
	Logger      *slog.Logger
}

type Runtime struct {
	configuration domain.Configuration
	dependencies  RuntimeDependencies
}

func NewRuntime(configuration domain.Configuration, dependencies RuntimeDependencies) (*Runtime, error) {
	if err := configuration.Validate(); err != nil {
		return nil, fmt.Errorf("invalid runtime configuration: %w", err)
	}
	if dependencies.Coordinator == nil || dependencies.Controller == nil || dependencies.Runner == nil || dependencies.Status == nil || dependencies.Health == nil {
		return nil, errors.New("all runtime control-plane dependencies are required")
	}
	if dependencies.Process != nil && dependencies.Processes == nil {
		return nil, errors.New("process launcher is required for supervised runtime mode")
	}
	if dependencies.Logger == nil {
		dependencies.Logger = slog.Default()
	}
	return &Runtime{configuration: configuration, dependencies: dependencies}, nil
}

type componentResult struct {
	name string
	err  error
}

func (runtime *Runtime) Run(parent context.Context) error {
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	results := make(chan componentResult, 2)
	go func() {
		results <- componentResult{name: "coordination", err: runtime.dependencies.Coordinator.Run(ctx, runtime.runOwned)}
	}()
	go func() {
		results <- componentResult{name: "health", err: runtime.dependencies.Health.Run(ctx)}
	}()

	var runtimeErrors []error
	for completed := 0; completed < 2; completed++ {
		result := <-results
		if result.err == nil && context.Cause(ctx) == nil {
			result.err = errors.New("component exited unexpectedly")
		}
		if result.err != nil && !errors.Is(result.err, context.Canceled) {
			runtimeErrors = append(runtimeErrors, fmt.Errorf("%s: %w", result.name, result.err))
		}
		if context.Cause(ctx) == nil {
			cancel(result.err)
		}
	}
	return errors.Join(runtimeErrors...)
}

func (runtime *Runtime) runOwned(ctx context.Context) error {
	prepareContext, cancelPrepare := context.WithTimeout(ctx, runtime.configuration.Runtime.ReconcileTimeout)
	prepareErr := runtime.dependencies.Controller.Prepare(prepareContext)
	cancelPrepare()
	if prepareErr != nil {
		return errors.Join(fmt.Errorf("prepare gateway quarantine: %w", prepareErr), runtime.shutdownController(ctx))
	}
	runtime.dependencies.Status.MarkQuarantined()

	var process port.ManagedProcess
	var processResult <-chan error
	if runtime.dependencies.Process != nil {
		started, err := runtime.dependencies.Processes.Start(*runtime.dependencies.Process)
		if err != nil {
			return errors.Join(fmt.Errorf("start supervised process: %w", err), runtime.shutdownController(ctx))
		}
		process = started
		result := make(chan error, 1)
		go func() { result <- process.Wait() }()
		processResult = result
		runtime.dependencies.Logger.InfoContext(ctx, "supervised process started", "executable", runtime.dependencies.Process.Executable)
	}

	controlContext, cancelControl := context.WithCancelCause(ctx)
	runnerResult := make(chan error, 1)
	go func() { runnerResult <- runtime.dependencies.Runner.Run(controlContext) }()

	var runtimeErrors []error
	runnerExited := false
	processExited := false
	select {
	case <-ctx.Done():
		cancelControl(context.Cause(ctx))
	case runnerErr := <-runnerResult:
		runnerExited = true
		if runnerErr == nil {
			runnerErr = errors.New("reconciler exited unexpectedly")
		}
		runtimeErrors = append(runtimeErrors, runnerErr)
		cancelControl(runnerErr)
	case processErr := <-processResult:
		processExited = true
		if processErr == nil {
			processErr = errors.New("supervised process exited without an error")
		}
		runtimeErrors = append(runtimeErrors, fmt.Errorf("supervised process exited unexpectedly: %w", processErr))
		cancelControl(processErr)
	}

	if !runnerExited {
		if runnerErr := <-runnerResult; runnerErr != nil && !errors.Is(runnerErr, context.Canceled) {
			runtimeErrors = append(runtimeErrors, fmt.Errorf("reconciler shutdown: %w", runnerErr))
		}
	}
	runtime.dependencies.Status.MarkStopping()
	if shutdownErr := runtime.shutdownController(ctx); shutdownErr != nil {
		runtimeErrors = append(runtimeErrors, shutdownErr)
	}

	if process != nil && !processExited {
		shutdownContext, cancelShutdown := context.WithTimeout(context.WithoutCancel(ctx), runtime.configuration.Runtime.ShutdownTimeout)
		terminateErr := process.Terminate(shutdownContext)
		cancelShutdown()
		if terminateErr != nil {
			runtimeErrors = append(runtimeErrors, fmt.Errorf("terminate supervised process: %w", terminateErr))
			runtime.dependencies.Logger.ErrorContext(context.WithoutCancel(ctx), "supervised process termination failed", "error", terminateErr)
		} else {
			runtime.dependencies.Logger.InfoContext(context.WithoutCancel(ctx), "supervised process stopped")
		}
	}
	return errors.Join(runtimeErrors...)
}

func (runtime *Runtime) shutdownController(ctx context.Context) error {
	shutdownContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), runtime.configuration.Runtime.ShutdownTimeout)
	defer cancel()
	if err := runtime.dependencies.Controller.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("shutdown gateway controller: %w", err)
	}
	return nil
}
