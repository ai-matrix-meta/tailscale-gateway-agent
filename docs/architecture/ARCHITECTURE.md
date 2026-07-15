# Tailscale Gateway Agent Architecture

## Scope

The Agent owns gateway control-plane state in one Linux network namespace:

- routes in two explicitly configured policy tables;
- rules at two explicitly configured priorities;
- two nftables tables carrying Agent ownership metadata;
- the Tailscale `AdvertiseRoutes` preference field;
- single-writer coordination, health, readiness, and metrics.

Tailscaled owns the Tailnet tunnel and node state. Sing-box owns the proxy TUN,
packet processing, and upstream transport. The Agent never handles packets and
never invokes command-line networking tools.

## Dependency Direction

```text
cmd -> bootstrap
bootstrap -> application + adapter
application -> port + domain
adapter -> port + domain
port -> domain
domain -> Go standard library
```

`bootstrap` is the only composition root. Application services know ports, not
concrete adapters. Adapters do not call peer adapters. Port contracts expose no
third-party types. An architecture test parses every Go import and blocks
reverse, lateral, and command-execution dependencies.

## Domain Boundaries

- `domain`: configuration invariants, discovery facts, routing state,
  packet-filter policy, Tailnet preferences, and health state.
- `port`: discovery, routing, nftables, resolver, LocalAPI, coordination,
  process, kernel prerequisite, telemetry, and event contracts.
- `application`: pure desired-state planning, serialized reconciliation,
  scheduling, status epochs, and lifecycle ordering.
- `adapter`: Linux netlink/nftables/process/file-lock implementations,
  Tailscale LocalAPI, Kubernetes Lease, DNS, and telemetry.
- `bootstrap`: mode selection and dependency wiring only.
- `cmd`: signals, exit status, and the call into bootstrap only.

## Configuration Boundary

The v1 configuration is immutable for a process lifetime. Environment parsing
distinguishes missing values from explicit empty values, rejects unknown owned
variables, preserves duplicates for domain rejection, and aggregates errors in
stable order. Deployment-specific proxy TUN addresses are mandatory; interface
names, orchestrator identity, and credentials are not part of the Agent API.

Kubernetes performs lifecycle layering before process start. VM and LXC service
managers can inject the same final v1 environment directly. The Agent does not
implement a second overlay engine.

## Discovery

Every reconciliation first captures one immutable resolver snapshot, then
rebuilds a `DiscoveryRequest` from current facts:

1. LocalAPI supplies this node's Tailnet addresses.
2. The resolver snapshot supplies every configured IPv4 and IPv6 nameserver;
   local-control DNS queries and nameserver route discovery use that same
   snapshot for the complete pass.
3. Static configuration supplies proxy TUN addresses and advertised prefixes.
4. Native netlink identifies exactly one healthy TUN for each complete address
   identity.
5. Every nameserver and advertised-prefix probe uses kernel FIB-match route
   resolution for the actual managed target.
6. The result preserves each target's gateway, output link, and on-link flag.

Discovery rejects zero or multiple candidates, non-unicast dispositions,
multipath, unsupported route attributes, missing or unhealthy links, managed
tunnel recursion, incomplete prefix coverage, and any more-specific route that
prevents one deterministic advertised-prefix projection.

Link, address, and route subscriptions are the primary trigger. A periodic
full audit remains mandatory because kernel event delivery is not a durable
queue and does not cover every external state class.

## Desired Routing

The exit table contains:

- healthy default routes through the discovered proxy TUN;
- direct Tailnet-prefix routes through the discovered Tailnet TUN;
- direct projections for every advertised prefix;
- direct host routes for actual DNS targets not covered by an advertised
  prefix;
- higher-metric blackhole routes for every safety-critical destination.

An incoming-interface rule selects that table only for Tailnet ingress. Normal
host and non-exit traffic does not use it.

When local egress is enabled, a low-16-bit packet-mark rule selects the second
table. Nftables preserves the upper 16 bits, including Tailscale-owned mark
bytes, while replacing only the Agent-owned low bits. Its healthy defaults use
the proxy TUN and its fallback defaults are blackholes.

Netlink ownership requires the configured table or priority and the dedicated
Agent route protocol. A foreign object inside an owned identity is a conflict,
not an invitation to delete it. Routes are installed before rules are enabled;
rules are removed before obsolete routes.

Each Exit default additionally requires fresh Internet capability for its own
address family through the discovered proxy TUN and control-plane approval of
that default route. Capability monitoring runs inside the existing Agent
process; its detailed ownership, security, and transaction contracts are
defined in
[Exit capability and route approval](EXIT-CAPABILITY.md).

## Packet Filter

The Agent manages one inet filter table and one optional inet NAT table. Each
table contains a reserved metadata chain with a full SHA-256 desired-state
revision. An existing table without valid ownership metadata is never adopted
or deleted.

The filter table provides:

- a bidirectional forwarding quarantine matching Tailnet source and destination
  prefixes in both address families;
- bounded IPv4 and IPv6 sets for resolved local-control destinations;
- output route-hook rules that apply the configured packet mark.

The NAT table creates exact DNS masquerade rules per address and transport
protocol. Every rule matches the Tailnet source prefix, actual DNS destination,
port 53, and that destination's independently discovered output interface.

Changed tables are replaced in one nftables transaction. Complete structural
readback, not metadata alone, determines convergence.

## Serialized State Machine

```text
Starting -> Quarantined -> Reconciling -> Ready
                                |          |
                                +-> Degraded
Ready/Degraded -> Stopping
```

Only the Runner goroutine calls the Controller after startup. Event collectors,
timers, health handlers, and coordination callbacks never write managed state.
A network event atomically dirties readiness, cancels the active pass, and
schedules fresh discovery; the Runner then enforces fail-closed state before
retrying. A monotonically increasing dirty epoch closes the registration race
between an event and the active cancellation function.

Startup order:

1. Parse and validate all static configuration.
2. Reserve the telemetry listener so address conflicts fail before ownership
   acquisition or managed-state writes.
3. Acquire the configured single-writer owner.
4. Close forwarding and remove stale local marking before any routing mutation,
   then install the blackhole routing baseline.
5. Resolve configured local-control domains and discover the proxy TUN.
6. Install and verify table 101 defaults, mark selectors, and nftables marking
   before any managed process can initiate control-plane traffic.
7. In supervised mode, start official containerboot.
8. Subscribe to kernel events before the first full observation.
9. Read LocalAPI and clear restored advertisements while quarantined.
10. Discover current links and target-specific FIB paths.
11. Reconcile and read back routing and nftables.
12. Open the forwarding gate and perform a final data-plane readback.
13. Publish and read back the exact Tailnet preferences.
14. Mark readiness true only if no newer event exists.

The first full LocalAPI observation can race tailscaled's initial Self/netmap.
A live failure pass therefore preserves the prepared local-control path only
after independently repeating its kernel, resolver-freshness, proxy-TUN,
packet-filter, routing-readback, and final kernel checks. This is a recovery
lane for the supervised control process, not an Exit or forwarding path.

Live failure closure is deliberately redundant:

1. close the nftables forwarding gate;
2. converge every Exit selector to blackhole-backed routing;
3. retain table 101 active only when the complete local-control recovery path
   is freshly revalidated, otherwise converge it to blackholes too;
4. clear Tailnet advertisements;
5. keep readiness false and retry with bounded exponential backoff.

Normal supervised shutdown first stops scheduling and waits for the active
reconciliation, then executes strict fail-closed cleanup that blackholes both
managed policy tables, then terminates the containerboot process group.
Coordination ownership is retained until that cleanup completes. Ownership
loss uses the same strict path; it never retains the live recovery lane.

Startup preparation and every reconciliation have the same configured global
deadline. A timeout is a failed pass: readiness remains false and the Runner
immediately starts a bounded fail-closed pass. That pass inherits lifecycle
cancellation; if termination or ownership loss races with it, Runtime waits for
Runner to stop and then owns the one complete shutdown transaction under an
independent deadline.

## Runtime Modes

`run` requires the file-lock backend. The external service manager owns
tailscaled and sing-box processes.

`supervise-containerboot` requires the Kubernetes Lease backend. The namespace
comes from the projected service-account namespace file. Holder identity is a
hostname plus cryptographically random process identity; no orchestrator object
name or UID enters the domain model. Only the supervised child receives an
exact allowlist of containerboot variables.

Mode inference is prohibited. A wrong mode is an ownership error and must fail
before side effects.

## Release Invariants

- Source, race, static analysis, vulnerability, cross-build, and isolated Linux
  integration gates run again for every release.
- The scratch image contains one static executable and runs as UID/GID 65532.
- The OCI index contains exactly `linux/amd64` and `linux/arm64`; ARM64 targets
  Linux on Apple Silicon hosts, not the native macOS kernel.
- Multi-platform registry manifests, runtime metadata, SBOM, provenance, and
  keyless signature are read back before a release tag is promoted.
- Every execution uses a unique candidate tag. Release promotion is by the
  build-produced OCI digest only and is the final external write in the job.
