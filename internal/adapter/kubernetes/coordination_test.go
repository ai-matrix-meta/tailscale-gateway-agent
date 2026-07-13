package kubernetes

import (
	"context"
	"errors"
	"testing"
)

func TestOwnedSessionPreventsStartupAfterCancellation(t *testing.T) {
	session := &ownedSession{}
	stopErr := errors.New("runtime is stopping")
	if started := session.stop(stopErr); started {
		t.Fatal("empty session reported a started callback")
	}
	if _, started := session.start(context.Background()); started {
		t.Fatal("owned callback started after shutdown won arbitration")
	}
}

func TestOwnedSessionCancellationWaitPathObservesCause(t *testing.T) {
	session := &ownedSession{}
	ownedContext, started := session.start(context.Background())
	if !started {
		t.Fatal("owned callback did not start")
	}
	stopErr := errors.New("coordination lost")
	if started := session.stop(stopErr); !started {
		t.Fatal("started callback was not reported to the wait path")
	}
	<-ownedContext.Done()
	if !errors.Is(context.Cause(ownedContext), stopErr) {
		t.Fatalf("unexpected cancellation cause: %v", context.Cause(ownedContext))
	}
}
