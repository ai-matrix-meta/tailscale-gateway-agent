package kubernetes

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetesvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

var errCoordinationLost = errors.New("kubernetes Lease ownership was lost")

type Coordinator struct {
	configuration  domain.CoordinationConfiguration
	client         kubernetes.Interface
	namespace      string
	holderIdentity string
}

type ownedSession struct {
	mutex    sync.Mutex
	stopping bool
	cancel   context.CancelCauseFunc
}

func (session *ownedSession) start(parent context.Context) (context.Context, bool) {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	if session.stopping || context.Cause(parent) != nil {
		return nil, false
	}
	ownedContext, cancelOwned := context.WithCancelCause(context.WithoutCancel(parent))
	session.cancel = cancelOwned
	return ownedContext, true
}

func (session *ownedSession) stop(cause error) bool {
	session.mutex.Lock()
	session.stopping = true
	cancelOwned := session.cancel
	session.mutex.Unlock()
	if cancelOwned != nil {
		cancelOwned(cause)
		return true
	}
	return false
}

func NewCoordinator(configuration domain.CoordinationConfiguration) (*Coordinator, error) {
	namespaceBytes, err := os.ReadFile(configuration.NamespacePath)
	if err != nil {
		return nil, fmt.Errorf("read coordination namespace file %s: %w", configuration.NamespacePath, err)
	}
	namespace := strings.TrimSpace(string(namespaceBytes))
	if namespace == "" {
		return nil, fmt.Errorf("coordination namespace file %s is empty", configuration.NamespacePath)
	}
	if validationErrors := kubernetesvalidation.IsDNS1123Label(namespace); len(validationErrors) != 0 {
		return nil, fmt.Errorf("coordination namespace %q is invalid: %s", namespace, strings.Join(validationErrors, "; "))
	}
	restConfiguration, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster Kubernetes configuration: %w", err)
	}
	restConfiguration.UserAgent = "tailscale-gateway-agent/v1"
	restConfiguration.QPS = 2
	restConfiguration.Burst = 4
	restConfiguration.Timeout = configuration.RenewDeadline
	client, err := kubernetes.NewForConfig(restConfiguration)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	holderIdentity, err := newHolderIdentity()
	if err != nil {
		return nil, err
	}
	return &Coordinator{configuration: configuration, client: client, namespace: namespace, holderIdentity: holderIdentity}, nil
}

func (coordinator *Coordinator) Run(parent context.Context, owned func(context.Context) error) error {
	if owned == nil {
		return errors.New("coordination callback is required")
	}
	electionContext, cancelElection := context.WithCancel(context.WithoutCancel(parent))
	defer cancelElection()
	acquired := make(chan struct{})
	ownedResult := make(chan error, 1)
	electionStopped := make(chan struct{})
	session := &ownedSession{}
	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{Name: coordinator.configuration.ResourceName, Namespace: coordinator.namespace},
		Client:    coordinator.client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: coordinator.holderIdentity,
		},
		Labels: map[string]string{
			"app.kubernetes.io/name":       "tailscale-gateway",
			"app.kubernetes.io/component":  "identity-coordination",
			"app.kubernetes.io/managed-by": "tailscale-gateway-agent",
		},
	}
	elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:            lock,
		LeaseDuration:   coordinator.configuration.LeaseDuration,
		RenewDeadline:   coordinator.configuration.RenewDeadline,
		RetryPeriod:     coordinator.configuration.RetryPeriod,
		ReleaseOnCancel: true,
		Name:            "tailscale-gateway-identity",
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(leadershipContext context.Context) {
				ownedContext, started := session.start(parent)
				if !started {
					cancelElection()
					return
				}
				close(acquired)
				go func() {
					<-leadershipContext.Done()
					session.stop(errCoordinationLost)
				}()
				ownedResult <- owned(ownedContext)
				cancelElection()
			},
			OnStoppedLeading: func() { close(electionStopped) },
			OnNewLeader:      func(string) {},
		},
	})
	if err != nil {
		return fmt.Errorf("configure kubernetes Lease coordination: %w", err)
	}
	go elector.Run(electionContext)

	acquireTimer := time.NewTimer(coordinator.configuration.AcquireTimeout)
	defer acquireTimer.Stop()
	select {
	case <-acquired:
	case <-parent.Done():
		started := session.stop(context.Cause(parent))
		cancelElection()
		<-electionStopped
		if started {
			return <-ownedResult
		}
		return nil
	case <-acquireTimer.C:
		acquireErr := fmt.Errorf("coordination lease %s/%s was not acquired within %s", coordinator.namespace, coordinator.configuration.ResourceName, coordinator.configuration.AcquireTimeout)
		started := session.stop(acquireErr)
		cancelElection()
		<-electionStopped
		if started {
			return errors.Join(acquireErr, <-ownedResult)
		}
		return acquireErr
	case <-electionStopped:
		stoppedErr := errors.New("kubernetes Lease coordination stopped before ownership was acquired")
		if session.stop(stoppedErr) {
			return errors.Join(stoppedErr, <-ownedResult)
		}
		return stoppedErr
	}

	select {
	case callbackErr := <-ownedResult:
		cancelElection()
		<-electionStopped
		return callbackErr
	case <-parent.Done():
		session.stop(context.Cause(parent))
		callbackErr := <-ownedResult
		cancelElection()
		<-electionStopped
		return callbackErr
	case <-electionStopped:
		session.stop(errCoordinationLost)
		callbackErr := <-ownedResult
		return errors.Join(errCoordinationLost, callbackErr)
	}
}

func newHolderIdentity() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("read hostname for coordination identity: %w", err)
	}
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate coordination identity: %w", err)
	}
	randomIdentity := hex.EncodeToString(randomBytes)
	identity := hostname + ":" + randomIdentity
	if len(identity) > 128 {
		hostnameDigest := sha256.Sum256([]byte(hostname))
		identity = hex.EncodeToString(hostnameDigest[:16]) + ":" + randomIdentity
	}
	return identity, nil
}
