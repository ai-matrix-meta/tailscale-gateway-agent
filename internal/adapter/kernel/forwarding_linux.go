//go:build linux

package kernel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	ipv4ForwardingPath = "/proc/sys/net/ipv4/ip_forward"
	ipv6ForwardingPath = "/proc/sys/net/ipv6/conf/all/forwarding"
)

type fileReader func(string) ([]byte, error)

type ForwardingChecker struct {
	readFile fileReader
}

func NewForwardingChecker() *ForwardingChecker {
	return &ForwardingChecker{readFile: os.ReadFile}
}

func (checker *ForwardingChecker) Check(ctx context.Context) error {
	var checkErrors []error
	for _, item := range []struct {
		name string
		path string
	}{
		{name: "IPv4", path: ipv4ForwardingPath},
		{name: "IPv6", path: ipv6ForwardingPath},
	} {
		if err := ctx.Err(); err != nil {
			return err
		}
		value, err := checker.readFile(item.path)
		if err != nil {
			checkErrors = append(checkErrors, fmt.Errorf("read %s forwarding state: %w", item.name, err))
			continue
		}
		if strings.TrimSpace(string(value)) != "1" {
			checkErrors = append(checkErrors, fmt.Errorf("%s forwarding is disabled", item.name))
		}
	}
	return errors.Join(checkErrors...)
}
