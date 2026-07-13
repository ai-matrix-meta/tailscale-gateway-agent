//go:build !linux

package kernel

import (
	"context"
	"errors"
)

var errUnsupported = errors.New("kernel forwarding checks are supported only on Linux")

type ForwardingChecker struct{}

func NewForwardingChecker() *ForwardingChecker { return &ForwardingChecker{} }
func (checker *ForwardingChecker) Check(context.Context) error {
	return errUnsupported
}
