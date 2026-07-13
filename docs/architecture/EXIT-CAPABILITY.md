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

The Agent may advertise the two Exit defaults only when all three observations
allow it. Subnet advertisements and ordinary Tailnet IPv6 remain independent
of Internet capability.

The Agent still does not handle application data-plane packets. It creates two
small, bounded HTTPS control-plane requests. The kernel and sing-box carry
those requests over the same proxy TUN path used by Exit traffic.

## Non-Goals

- Inferring `run` versus `supervise-containerboot` from the environment.
- Inferring Internet capability from local addresses, DNS AAAA records, or
  internal routes.
- Supporting a Tailscale-incompatible IPv4-only Exit Node.
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

### Reconciliation Conditions

A reconciliation has two independent result channels:

- a technical error, which invokes the existing fail-closed transaction and
  bounded retry; and
- bounded operational conditions, which return no error but make readiness
  false and phase Degraded.

Condition kinds are fixed enums. Initial capability, unavailable capability,
stale capability, proxy-link mismatch, and explicit route-not-approved are
operational conditions. LocalAPI failure, nil Self, missing network map,
offline control poll, nil AllowedIPs, invalid prefixes, write failure, or
failed readback are technical errors.

Condition values may carry only a configured prefix or address family. Error
text is never a metric label.

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
4. Resolve both A and AAAA records. The IPv4 target must have only IPv4
   results; the IPv6 target must have only IPv6 results.
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
4. Build and plan routing and nftables state.
5. Derive local advertisement intent:
   - configured subnet prefixes are always retained;
   - both Exit defaults are included only when both family snapshots are
     available, fresh, initialized, and bound to the same proxy link.
6. Converge and read back the data plane before increasing advertisement.
7. Write the exact advertisement preference at most once when it differs.
8. Read back preferences and current control-plane approval.
9. Evaluate every desired subnet prefix and each desired Exit default against
   approved routes.
10. Publish Ready only when no technical error, capability condition, approval
    condition, or newer event exists.

Capability loss is a preference-reduction transaction. It changes an existing
`subnets + 0.0.0.0/0 + ::/0` preference to `subnets` in one LocalAPI write and
does not remove subnet configuration or disable ordinary IPv6. If that write
or readback fails, the normal fail-closed path clears every advertisement.

Capability recovery is an advertisement-increase transaction. The Agent first
performs final routing, nftables, and kernel readback, then publishes both Exit
defaults together. There is no intermediate IPv4-only or IPv6-only Exit state.

Explicit Admin Console rejection is observed after local intent converges. It
does not alter local preferences, delete configuration, or trigger another
write. Approval recovery changes only the observed condition and therefore
returns to Ready with zero preference writes.

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
- operational condition by fixed `kind`; and
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
- public single-family DNS acceptance and mixed/reserved rejection;
- address pinning, redirect rejection, TLS verification, exact 204 response,
  empty body, timeout, cancellation, and size limits;
- `SO_MARK` and device binding through Linux-tagged socket tests;
- first observation, success/failure debounce, saturation, expiration,
  cancellation, and proxy-link replacement;
- both healthy, IPv4-only, IPv6-only, both failed, and stale snapshots;
- capability loss withdrawing both defaults while preserving subnet and
  internal IPv6 routes;
- recovery verifying the data plane before one dual-default preference write;
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
Exit, non-Exit, IPv4, IPv6, and DNS behavior. Source or internal probe success
does not replace that matrix.

## Unresolved Production Input

Production endpoint values are intentionally absent. Before P0-007 can close,
operations must approve two HTTPS endpoints and record:

- exclusive A or AAAA behavior;
- exact HTTP 204 and empty-body behavior;
- endpoint operator and ownership;
- certificate and trust-chain expectations;
- availability and change-management policy;
- rate limit for the configured cadence;
- privacy and compliance conclusion; and
- successful execution through the real proxy path.

Until then, implementation may be locally complete, but the release decision
remains `NO-GO` and no production endpoint or digest may be fabricated.
