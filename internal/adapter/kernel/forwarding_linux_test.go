//go:build linux

package kernel

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestForwardingCheckerRequiresBothAddressFamilies(t *testing.T) {
	values := map[string][]byte{
		ipv4ForwardingPath: []byte("1\n"),
		ipv6ForwardingPath: []byte("0\n"),
	}
	checker := &ForwardingChecker{readFile: func(path string) ([]byte, error) {
		value, exists := values[path]
		if !exists {
			return nil, errors.New("not found")
		}
		return value, nil
	}}
	if err := checker.Check(context.Background()); err == nil || !strings.Contains(err.Error(), "IPv6 forwarding is disabled") {
		t.Fatalf("disabled IPv6 forwarding was accepted: %v", err)
	}
	values[ipv6ForwardingPath] = []byte("1\n")
	if err := checker.Check(context.Background()); err != nil {
		t.Fatalf("enabled dual-stack forwarding was rejected: %v", err)
	}
}
