package install

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func CopySelf(destination string) error {
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return fmt.Errorf("installation destination %q must be a clean absolute path", destination)
	}
	parent := filepath.Dir(destination)
	info, err := os.Stat(parent)
	if err != nil {
		return fmt.Errorf("inspect installation directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("installation parent %q is not a directory", parent)
	}
	if destinationInfo, statErr := os.Lstat(destination); statErr == nil && destinationInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace symlink at %q", destination)
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect installation destination: %w", statErr)
	}

	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate current executable: %w", err)
	}
	source, err := os.Open(executable)
	if err != nil {
		return fmt.Errorf("open current executable: %w", err)
	}
	defer source.Close()

	temporary, err := os.CreateTemp(parent, ".tailscale-gateway-agent-*")
	if err != nil {
		return fmt.Errorf("create temporary installation file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if _, err := io.Copy(temporary, source); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("copy executable: %w", err)
	}
	if err := temporary.Chmod(0o555); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set executable permissions: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync executable: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary executable: %w", err)
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return fmt.Errorf("activate installed executable: %w", err)
	}
	directory, err := os.Open(parent)
	if err != nil {
		return fmt.Errorf("open installation directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync installation directory: %w", err)
	}
	return nil
}
