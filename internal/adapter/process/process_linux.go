//go:build linux

package process

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/port"
)

type Launcher struct{}

var environmentNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

const forcedTerminationConfirmationTimeout = 5 * time.Second

func NewLauncher() *Launcher { return &Launcher{} }

func (launcher *Launcher) Start(specification domain.ProcessSpec) (port.ManagedProcess, error) {
	if !filepath.IsAbs(specification.Executable) || filepath.Clean(specification.Executable) != specification.Executable {
		return nil, fmt.Errorf("process executable %q must be a clean absolute path", specification.Executable)
	}
	info, err := os.Lstat(specification.Executable)
	if err != nil {
		return nil, fmt.Errorf("inspect process executable: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("process executable %q must not be a symbolic link", specification.Executable)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("process executable %q is not an executable regular file", specification.Executable)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("process executable %q must not be group- or world-writable", specification.Executable)
	}
	if err := validateEnvironment(specification.Environment); err != nil {
		return nil, err
	}
	command := exec.Command(specification.Executable, specification.Arguments...)
	command.Env = append([]string(nil), specification.Environment...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM, Setpgid: true}
	if err := command.Start(); err != nil {
		return nil, err
	}
	process := &ManagedProcess{command: command, done: make(chan struct{})}
	go func() {
		process.mutex.Lock()
		process.waitErr = command.Wait()
		process.mutex.Unlock()
		close(process.done)
	}()
	return process, nil
}

type ManagedProcess struct {
	command       *exec.Cmd
	done          chan struct{}
	terminateOnce sync.Once
	mutex         sync.RWMutex
	waitErr       error
}

func (process *ManagedProcess) Wait() error {
	<-process.done
	process.mutex.RLock()
	defer process.mutex.RUnlock()
	return process.waitErr
}

func (process *ManagedProcess) Terminate(ctx context.Context) error {
	var signalErr error
	process.terminateOnce.Do(func() {
		signalErr = syscall.Kill(-process.command.Process.Pid, syscall.SIGTERM)
		if errors.Is(signalErr, os.ErrProcessDone) || errors.Is(signalErr, syscall.ESRCH) {
			signalErr = nil
		}
	})
	select {
	case <-process.done:
		return signalErr
	case <-ctx.Done():
		killErr := syscall.Kill(-process.command.Process.Pid, syscall.SIGKILL)
		if errors.Is(killErr, os.ErrProcessDone) || errors.Is(killErr, syscall.ESRCH) {
			killErr = nil
		}
		confirmationTimer := time.NewTimer(forcedTerminationConfirmationTimeout)
		defer confirmationTimer.Stop()
		select {
		case <-process.done:
			return errors.Join(signalErr, ctx.Err(), killErr)
		case <-confirmationTimer.C:
			return errors.Join(signalErr, ctx.Err(), killErr, errors.New("process group did not exit after SIGKILL"))
		}
	}
}

func validateEnvironment(entries []string) error {
	seen := make(map[string]struct{}, len(entries))
	for index, entry := range entries {
		name, _, found := strings.Cut(entry, "=")
		if !found || !environmentNamePattern.MatchString(name) {
			return fmt.Errorf("child-process environment entry at index %d has an invalid variable name", index)
		}
		if strings.ContainsRune(entry, '\x00') {
			return fmt.Errorf("child-process environment variable %s contains a NUL byte", name)
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("child-process environment variable %s is duplicated", name)
		}
		seen[name] = struct{}{}
	}
	return nil
}
