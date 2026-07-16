# Exit Capability And Route Approval Design

## Decision

Exit capability monitoring is part of the existing Agent executable and
process. The Kubernetes `agent-installer` continues to copy that one static
executable into the shared tools volume, and the official Tailscale container
continues to run it as PID 1. The same executable runs directly under a VM or
LXC service manager.

This design adds no capability executable, process, container, sidecar, shared
state volume, local socket, file signal, or second configuration parser. An
additional container is not categorically forbidden, but it requires a
specific isolation, ownership, compliance, or independent-release need that
cannot be met in process. No such need exists for the current bounded control
plane probes.

An external Tailnet blackbox remains a separate release-validation layer. It
tests the complete client experience after advertisement; it cannot be the
pre-advertisement authority because a client cannot select an Exit Node that
has not yet advertised its default routes.

## Scope

The implementation must establish three independent observations:

1. Local advertisement intent from Tailscale preferences.
2. Control-plane approval from the current self node's AllowedIPs.
3. Fresh IPv4 and IPv6 Internet capability through the discovered proxy TUN,
   sing-box, and the configured upstream SOCKS transport.

Tailscale represents a selectable Exit Node as an indivisible pair of default
routes. Pinned upstream Tailscale evaluates `ExitNodeOption` through
`tsaddr.ContainsExitRoutes`, which returns true only when both `0.0.0.0/0` and
`::/0` are present. A single default is an ordinary subnet route, not a partial
Exit Node.

The Agent therefore derives two distinct states. Tailnet advertisement intent
contains both defaults when at least one address family has fresh capability,
and contains neither when both families are unavailable. The Exit routing table
independently installs an active default only for each healthy family and keeps
the higher-metric blackhole for every unavailable family. Control-plane
approval is observed for both defaults while the Exit Node is advertised; an
explicit rejection produces a bounded Degraded condition but never causes
readiness loss for an otherwise available data plane or preference-write
oscillation. Subnet advertisements and ordinary Tailnet IPv6 remain independent
of Internet capability.

The Agent still does not handle application data-plane packets. It creates two
small, bounded HTTPS control-plane requests. The kernel and sing-box carry
those requests over the same proxy TUN path used by Exit traffic.

## Non-Goals

- Inferring `run` versus `supervise-containerboot` from the environment.
- Inferring Internet capability from local addresses, DNS AAAA records, or
  internal routes.
- Installing an active Exit default without fresh capability evidence for its
  address family.
- Treating a single advertised default as a selectable Exit Node.
- Selecting a public probe provider in source or default configuration.
- Replacing the external Tailnet traffic matrix with an internal probe.
- Moving Tailscale, sing-box, or Kubernetes lifecycle ownership into the
  capability component.
- Writing Tailscale preferences from the monitor or probe adapter.

## Package And Call Direction

```text
cmd/tailscale-gateway-agent
  -> internal/bootstrap

internal/bootstrap
  -> internal/application
  -> internal/application/capability
  -> internal/adapter/internetprobe
  -> existing concrete adapters

internal/application
  -> internal/port
  -> internal/domain

internal/application/capability
  -> internal/port
  -> internal/domain

internal/adapter/internetprobe
  -> internal/port
  -> internal/domain

internal/port
  -> internal/domain

internal/domain
  -> Go standard library
```

The root application package does not import the capability subpackage. It
defines consumer-owned observation interfaces. The monitor satisfies those
interfaces implicitly, and bootstrap injects the concrete instance. This
keeps bootstrap as the only concrete composition root and prevents a package
cycle or an application-to-adapter dependency.

The architecture gate must reject every unknown production package, every
peer-adapter import, every third-party infrastructure import outside an
adapter, and every application subpackage edge not listed in the explicit DAG.
Passing the import gate remains necessary but is not evidence of correct
responsibility placement.

## Domain Model

### Tailnet Control Observation

The Tailnet state must distinguish:

- backend running state;
- kernel TUN state;
- normalized self addresses;
- local advertised preferences;
- whether a self status exists;
- whether self belongs to the current network map;
- whether the control poll is online;
- whether AllowedIPs is available rather than omitted;
- normalized approved routes; and
- the local time at which the complete LocalAPI observation succeeded.

A nil AllowedIPs view is unavailable, not an explicitly empty approval set.
Exact host prefixes for the node's own Tailscale addresses are removed from
AllowedIPs before the remaining prefixes are exposed as approved routes.
PrimaryRoutes is not part of the approval model because an approved HA standby
need not be primary.

### Internet Capability Snapshot

The immutable snapshot contains:

- the exact proxy `LinkIdentity` used by the probes;
- separate IPv4 and IPv6 availability values;
- the last conclusive observation time for each family;
- the expiration time for each successful family; and
- whether each family has completed its initial debounce threshold.

It contains no URL, HTTP response, DNS record, socket, Pod identity, producer
identity, sequence number, file path, or third-party type. Snapshot validation
rejects invalid links, reversed times, availability without a completed
observation, and mismatched address families.

### Exit Node Advertisement And Active Routes

`ExitDefaultRouteSet` is a routing-domain value that identifies which address
families may have active defaults in the Exit table. It is not a Tailnet
advertisement shape. Separate constructors make non-Exit and Exit Node intent
explicit; the Exit Node constructor always emits both defaults atomically.
LocalAPI normalization still accepts zero, one, or two observed defaults so the
controller can safely repair legacy, externally edited, or partially converged
preferences.

The states are intentionally not equivalent:

| Fresh capability | Tailnet defaults | IPv4 active route | IPv6 active route |
|---|---|---|---|
| neither | neither | absent; blackhole retained | absent; blackhole retained |
| IPv4 only | both | present | absent; blackhole retained |
| IPv6 only | both | absent; blackhole retained | present |
| both | both | present | present |

This asymmetry is required by the Tailscale client contract. An unavailable
family remains fail-closed even though its default is part of the atomic
advertisement pair. Phase becomes Degraded and bounded family-labeled
conditions expose the loss; readiness remains true while at least one verified
Exit family is active.

### Reconciliation Conditions

A reconciliation has three independent result channels:

- a technical error, which invokes the existing fail-closed transaction and
  bounded retry; and
- verified data-plane availability, which determines whether a current and
  fresh result may remain Kubernetes Ready; and
- bounded operational conditions, which return no error and set phase
  Degraded without implicitly deciding readiness.

Condition kinds are fixed enums. Initial capability, unavailable capability,
stale capability, proxy-link mismatch, and explicit route-not-approved are
operational conditions. LocalAPI failure, nil Self, missing network map,
offline control poll, nil AllowedIPs, invalid prefixes, write failure, or
failed readback are technical errors.

Condition values may carry only a configured prefix or address family. Error
text is never a metric label.

The Controller is the sole owner of `DataPlaneAvailable`. It sets the value
only after complete routing, nftables, kernel, and Tailnet preference readback.
When Exit advertisement is enabled, at least one active, independently verified
Exit family is required. Route approval conditions never change this value:
Admin Console approval controls reachability of that advertised prefix, not the
safety of the already verified local data plane.

## Port Contracts

The external probe port accepts only:

- an address family;
- a validated proxy `LinkIdentity`; and
- the existing Agent-owned low-16-bit packet mark.

Targets are immutable adapter construction inputs validated before
coordination or network writes. The application component does not receive an
HTTP client or response and treats ordinary probe failure as a conclusive
negative family observation, not as a process error.

The controller consumes a minimal capability observer:

```text
Observe(context, proxy LinkIdentity) -> snapshot, error
```

The error channel is reserved for cancellation or violated internal contracts.
DNS, connection, TLS, timeout, response, and path failures update the bounded
snapshot and telemetry without causing an error retry storm.

## Configuration Contract

All fields remain in the existing immutable `TAILSCALE_GATEWAY_*` v1
environment API:

```text
TAILSCALE_GATEWAY_CAPABILITY_PROBE_IPV4_URL
TAILSCALE_GATEWAY_CAPABILITY_PROBE_IPV6_URL
TAILSCALE_GATEWAY_CAPABILITY_PROBE_INTERVAL
TAILSCALE_GATEWAY_CAPABILITY_PROBE_TIMEOUT
TAILSCALE_GATEWAY_CAPABILITY_PROBE_VALIDITY
TAILSCALE_GATEWAY_CAPABILITY_PROBE_SUCCESS_THRESHOLD
TAILSCALE_GATEWAY_CAPABILITY_PROBE_FAILURE_THRESHOLD
```

Recommended non-endpoint defaults are:

```text
interval:          30s
timeout:           5s
validity:          2m
success threshold: 2
failure threshold: 2
```

URLs have no defaults. When Exit advertisement is false, both URLs must be
absent and no prober is constructed. When Exit advertisement is true, both are
required and must pass the static endpoint contract. This makes a missing
production decision fail before any side effect rather than silently
advertising or probing an invented provider.

The endpoint URL contract is deliberately narrow:

- scheme is exactly `https`;
- host is a DNS name, not an IP literal;
- port is absent or `443`;
- user information, query, and fragment are absent;
- path is absolute and non-empty; and
- a successful response is exactly HTTP 204 with an empty body.

Intervals and thresholds are bounded. Timeout is shorter than the interval and
fits inside the global reconciliation deadline. Validity exceeds the interval
and cannot allow an old success to live indefinitely. Threshold counters use
saturating arithmetic.

Base, prod, and cluster continue to use ConfigMap environment values. No YAML
payload or runtime overlay parser is introduced. Probe endpoints are cluster
facts and therefore belong only to the cluster overlay after approval.

## Probe Adapter Security Contract

Each probe cycle resolves and tests one configured endpoint per family. The
adapter must enforce all of the following:

1. Ignore HTTP proxy environment variables.
2. Reject every redirect.
3. Use the system trust store with normal hostname verification and TLS 1.2 or
   newer. `InsecureSkipVerify` is prohibited.
4. Resolve only the requested address family (`ip4` or `ip6`). A dual-stack
   endpoint, including the same URL for both configured probes, is valid
   because each probe receives only its requested family.
5. Require at least one and at most a small fixed number of addresses.
6. Reject unspecified, loopback, private, link-local, multicast, CGNAT,
   benchmarking, documentation, and other non-Internet destinations.
7. Pin each connection attempt to a previously validated resolved address so
   DNS rebinding cannot change the destination after validation.
8. Preserve the configured hostname for TLS SNI and certificate verification.
9. Set both `SO_MARK` and `SO_BINDTODEVICE` before connect, using the current
   proxy TUN identity and existing Agent mark.
10. Disable connection reuse and keep-alives; close every response body.
11. Bound dial, TLS handshake, response-header, total request, header bytes,
    response body, and address count.
12. Send no credentials, cookies, custom authorization, request body, or
    ambient headers.

All resolved addresses must be acceptable. The adapter does not ignore a
private or reserved answer merely because another answer is public. Within the
validated set, any successful address proves the family for that cycle.

The final scratch image must contain a reviewed CA trust bundle copied from a
pinned build stage. CI must build both platforms and execute an HTTPS trust
smoke test without publishing the image.

## Monitor State Machine

Runner remains the only scheduler. It adds a capability audit trigger using
the configured interval. Controller calls the monitor after discovering and
validating the current proxy TUN. The monitor probes when the interval is due,
on the first observation, after expiration, or when link identity changes.

IPv4 and IPv6 probes execute concurrently with a strict maximum of two
in-flight calls. Both inherit the reconciliation context and per-probe timeout,
and the monitor joins both calls before returning. It owns no long-lived
goroutine or timer.

For each family:

```text
initial
  -> success count reaches threshold -> available until validUntil
  -> failure count reaches threshold -> unavailable

available
  -> success -> refresh observedAt and validUntil
  -> failure below threshold -> retain availability only until validUntil
  -> failure reaches threshold or validity expires -> unavailable

unavailable
  -> success below threshold -> unavailable
  -> success reaches threshold -> available until validUntil
```

A success resets the failure counter. A failure resets the success counter.
Counters saturate at their configured threshold. Parent cancellation is
inconclusive and does not count as a family failure. A proxy link identity
change invalidates both old successes before probing the new link.

## Controller Transaction

Every pass follows this order:

1. Read and validate LocalAPI status and local preferences.
2. Capture one resolver snapshot and discover the current network state.
3. Observe Internet capability for the exact discovered proxy link.
4. Derive independent desired states:
   - configured subnet prefixes are always retained;
   - each family receives an active Exit default only when its snapshot is
     available, fresh, initialized, and bound to the same proxy link;
   - both Tailnet Exit defaults are desired when at least one active family
     exists, otherwise neither is desired.
5. Build and plan routing and nftables state.
6. If no active family remains, withdraw the complete Tailnet Exit Node pair
   before deleting the final active route. A partial observed default is also
   removed at this boundary.
7. If complete drift is limited to active Exit defaults and nftables already
   matches, apply a scoped route transaction: delete unavailable-family active
   routes, then require readback to show that the exact activation plan is the
   only remaining difference before installing any recovered-family routes.
   Read back the final state afterward. Otherwise enter the normal global
   quarantine transaction and clear all advertisements.
8. Converge and read back routing, nftables, and kernel prerequisites.
9. Publish the atomic Exit Node pair only after at least one active route and
   the complete data plane have been verified. Migrate a legacy single-default
   preference to the pair at this point. Single-family loss, second-family
   recovery, and cross-family replacement perform no Tailnet write while the
   pair remains desired.
10. Read back preferences and current control-plane approval.
11. Evaluate every desired subnet prefix and both Exit defaults against approved
   routes whenever the Exit Node pair is desired.
12. Report `DataPlaneAvailable=true` when the verified configuration can serve
    at least one required traffic path. Publish Ready only when that result is
    current and fresh; publish capability and approval conditions independently
    as Degraded diagnostics.

Capability loss is a family-scoped routing transaction. While another family
remains healthy, the Tailnet pair and configured subnet routes remain unchanged;
the Agent deletes only the unavailable family's active route, retains its
blackhole, and reads back the complete routing, nftables, and kernel state. When
the final healthy family is lost, the pair is withdrawn before that active route
is deleted. If the change is limited to active Exit defaults, the global
forwarding gate is not rewritten; unrelated drift or technical failure enters
the normal fail-closed transaction.

Capability recovery is also routing-scoped. The Agent installs and verifies the
newly eligible active route. Recovery of the first healthy family publishes the
atomic pair only after final routing, nftables, and kernel readback; recovery of
the second family performs no preference write. A direct IPv4-to-IPv6 or
IPv6-to-IPv4 transition deletes and verifies the old active route before
installing the new one while preserving the already-advertised pair.

Explicit Admin Console rejection is observed after local intent converges. It
does not alter local preferences, delete configuration, or trigger another
write. It keeps an otherwise available data plane Ready while phase and the
`route_not_approved` condition expose the administrative disablement. Approval
recovery changes only the observed condition and therefore returns phase to
Ready with zero preference writes.

## Event And Freshness Strategy

`StatusWithoutPeers` remains the authoritative observation because it contains
Self, AllowedIPs, control online state, TUN state, and backend state. A bounded
preference audit supplies the correctness backstop and maximum detection
window.

The Tailscale adapter also exposes a normalized event source backed by
`WatchIPNBus`. SelfChange, initial NetMap, later NetMap, and state changes only
dirty readiness and request a fresh authoritative read. Raw NetMap, Node,
Prefs, and watcher types never cross the adapter boundary. Watch reconnect
uses bounded application-owned backoff; periodic polling remains correct while
the hint stream is unavailable.

The production preference audit interval is 30 seconds. Watch events normally
make approval changes visible sooner; 30 seconds is the declared worst-case
polling window when LocalAPI remains reachable.

## Telemetry

Metrics use fixed, bounded labels:

- capability availability by `family`;
- capability probe attempts by `family` and fixed `result` enum;
- capability snapshot age by `family`;
- route approval by configured `prefix`;
- operational condition by fixed `kind`;
- verified data-plane availability; and
- existing reconciliation and write counters.

The configured route set is immutable and bounded, so prefix series cannot
grow at runtime. Stale series are explicitly removed when a complete
observation no longer contains an applicable configured prefix. Error strings,
URLs, resolved IP sets, LocalAPI objects, and response data are not labels.

Structured warning logs include only fixed condition kind, address family or
configured prefix, observation time, and a bounded sanitized reason. Probe
URLs and raw network responses are not logged.

## Runtime And Deployment

The Kubernetes topology remains unchanged:

```text
agent-installer init container
  -> copies /tailscale-gateway-agent to /tools

official tailscale application container
  -> /tools/tailscale-gateway-agent supervise-containerboot
     -> Runner
     -> Controller
     -> in-process capability monitor
     -> health and metrics
     -> official /usr/local/bin/containerboot child
```

All Pod containers already share the target network namespace. The probe uses
the same discovered proxy TUN and existing capabilities as the control plane.
No fixed interface name, Pod name, Downward API identity, or ServiceAccount
fact enters capability logic.

In external `run` mode, the service manager starts the same binary. Tailscaled
and sing-box remain externally managed, and the same configured proxy TUN
identity and probe contract apply.

Shutdown order remains Runner stop, fail-closed Controller cleanup, supervised
containerboot termination, and coordination release. Because the monitor owns
no long-lived goroutine, stopping Runner joins every possible probe before
Controller shutdown begins.

## Verification Contract

Unit and deterministic adapter tests must cover:

- strict endpoint parsing and missing conditional configuration;
- unknown, duplicate, empty, and cross-field environment errors;
- family-scoped dual-stack DNS acceptance and mixed/reserved resolver-result
  rejection;
- address pinning, redirect rejection, TLS verification, exact 204 response,
  empty body, timeout, cancellation, and size limits;
- `SO_MARK` and device binding through Linux-tagged socket tests;
- first observation, success/failure debounce, saturation, expiration,
  cancellation, and proxy-link replacement;
- both healthy, IPv4-only, IPv6-only, both failed, and stale snapshots;
- single-family capability loss preserving the atomic Tailnet pair while
  deleting only the failed-family active route and retaining its blackhole;
- final-family loss withdrawing the pair before deleting the final active route;
- first-family recovery verifying the complete data plane before publishing the
  pair, and second-family recovery producing no preference write;
- direct cross-family replacement deleting and reading back the old active route
  before installing the new route;
- migration of legacy single-default preferences to the atomic pair without
  unrelated routing or nftables writes;
- advertised and approved, explicitly unapproved, nil Self, missing netmap,
  offline control poll, nil AllowedIPs, HA standby, and separate Exit-default
  approval;
- Admin disable and restore with zero corrective preference writes; and
- no monitor goroutine, timer, process, container, volume, or IPC regression.

Linux integration must prove that sockets carry the configured mark, bind to
the discovered proxy TUN, traverse sing-box and upstream SOCKS, and reach the
approved IPv4-only and IPv6-only targets. The fourth-round runtime test must
also prove capability loss and recovery ordering without regressing route
event handling, zero-write convergence, or cleanup.

External acceptance still requires a real Tailnet client to validate subnet,
Exit, non-Exit, IPv4, IPv6, and DNS behavior. It must also prove
`ExitNodeOption=true` and confirm that AllowedIPs contains both defaults while
either data-plane family is healthy. Source or internal probe success does not
replace that matrix.

## Production Endpoint Ownership

The Agent has no provider default. Each deployment owns and explicitly selects
both probe URLs outside Agent source; the adapter still resolves and dials only
the requested family. Any deployment or endpoint change must record:

- requested-family DNS behavior and rejection of mixed or reserved
  destinations;
- exact HTTP 204 and empty-body behavior;
- endpoint operator and ownership;
- certificate and trust-chain expectations;
- availability and change-management policy;
- rate limit for the configured cadence;
- privacy and compliance conclusion; and
- successful execution through the real proxy path.

Endpoint selection does not close runtime acceptance by itself. P0-007 still
requires immutable-image live readback and the external Tailnet traffic matrix
for the actual proxy path; a failed family remains Degraded and blackholed
without suppressing the selectable Exit Node when the other family is healthy.
