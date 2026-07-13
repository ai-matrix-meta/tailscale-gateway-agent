//go:build linux

package filelock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"golang.org/x/sys/unix"
)

type Coordinator struct {
	configuration domain.CoordinationConfiguration
}

func NewCoordinator(configuration domain.CoordinationConfiguration) *Coordinator {
	return &Coordinator{configuration: configuration}
}

func (coordinator *Coordinator) Run(ctx context.Context, owned func(context.Context) error) (runErr error) {
	if owned == nil {
		return errors.New("coordination callback is required")
	}
	fileDescriptor, err := unix.Open(coordinator.configuration.LockFile, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open coordination lock %s: %w", coordinator.configuration.LockFile, err)
	}
	lockFile := os.NewFile(uintptr(fileDescriptor), coordinator.configuration.LockFile)
	if lockFile == nil {
		_ = unix.Close(fileDescriptor)
		return fmt.Errorf("create coordination lock file handle %s", coordinator.configuration.LockFile)
	}
	defer func() {
		if closeErr := lockFile.Close(); closeErr != nil {
			runErr = errors.Join(runErr, fmt.Errorf("close coordination lock %s: %w", coordinator.configuration.LockFile, closeErr))
		}
	}()
	var fileStatus unix.Stat_t
	if err := unix.Fstat(fileDescriptor, &fileStatus); err != nil {
		return fmt.Errorf("inspect coordination lock %s: %w", coordinator.configuration.LockFile, err)
	}
	if fileStatus.Mode&unix.S_IFMT != unix.S_IFREG || fileStatus.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("coordination lock %s must be a regular file owned by the current user", coordinator.configuration.LockFile)
	}
	if err := unix.Fchmod(fileDescriptor, 0o600); err != nil {
		return fmt.Errorf("secure coordination lock %s: %w", coordinator.configuration.LockFile, err)
	}
	deadline := time.NewTimer(coordinator.configuration.AcquireTimeout)
	defer deadline.Stop()
	retry := time.NewTicker(coordinator.configuration.RetryPeriod)
	defer retry.Stop()
	for {
		err = unix.Flock(fileDescriptor, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return fmt.Errorf("acquire coordination lock %s: %w", coordinator.configuration.LockFile, err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-deadline.C:
			return fmt.Errorf("coordination lock %s was not acquired within %s", coordinator.configuration.LockFile, coordinator.configuration.AcquireTimeout)
		case <-retry.C:
		}
	}
	callbackErr := owned(ctx)
	releaseErr := unix.Flock(fileDescriptor, unix.LOCK_UN)
	if releaseErr != nil {
		releaseErr = fmt.Errorf("release coordination lock %s: %w", coordinator.configuration.LockFile, releaseErr)
	}
	return errors.Join(callbackErr, releaseErr)
}
