//go:build linux

package process

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestEnvironmentValidationNeverIncludesSecretValues(t *testing.T) {
	const secret = "must-not-appear"
	err := validateEnvironment([]string{"TS_AUTHKEY=" + secret + "\x00"})
	if err == nil {
		t.Fatal("environment value containing NUL was accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("environment validation exposed secret material: %v", err)
	}
}

func TestTerminateConfirmsForcedProcessExit(t *testing.T) {
	if readyPath := os.Getenv("TAILSCALE_GATEWAY_PROCESS_TEST_READY"); readyPath != "" {
		signal.Ignore(syscall.SIGTERM)
		if err := os.WriteFile(readyPath, []byte("ready"), 0o600); err != nil {
			os.Exit(2)
		}
		for {
			time.Sleep(time.Hour)
		}
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	readyPath := filepath.Join(t.TempDir(), "ready")
	process, err := NewLauncher().Start(NewSpecification(
		executable,
		[]string{"-test.run=^TestTerminateConfirmsForcedProcessExit$"},
		[]string{"TAILSCALE_GATEWAY_PROCESS_TEST_READY=" + readyPath},
	))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_ = process.Terminate(cleanupContext)
	})

	readinessDeadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(readinessDeadline) {
			t.Fatal("helper process did not become ready")
		}
		time.Sleep(time.Millisecond)
	}

	terminationContext, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	terminateErr := process.Terminate(terminationContext)
	if !errors.Is(terminateErr, context.DeadlineExceeded) {
		t.Fatalf("forced termination did not report the exhausted graceful deadline: %v", terminateErr)
	}
	waited := make(chan struct{})
	go func() {
		_ = process.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("Terminate returned before the process exit was observable")
	}
}
