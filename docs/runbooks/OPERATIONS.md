# Operations Runbook

## Platform Boundary

The Agent requires a Linux network namespace with rtnetlink, nftables, policy
routing, TUN, dual-stack forwarding, and access to Tailscale LocalAPI. Release
images support `linux/amd64` and `linux/arm64`. Apple Silicon is supported when
it hosts Linux; native macOS is outside the runtime contract.

## Health Interpretation

- `/livez` confirms that the Agent process and health server are alive. It does
  not claim that the gateway is safe to advertise.
- `/readyz` requires a recent, complete, unsuperseded reconciliation. A kernel
  event revokes readiness immediately, before the next write pass starts.
- `/metrics` reports reconciliation trigger, latency, outcome, and write counts.
  A healthy no-drift audit reports zero routing, nftables, and Tailnet writes.

The runtime-neutral default binds these endpoints to `127.0.0.1:8080`. VM and
LXC monitoring should use a local collector or explicitly configure a protected
non-loopback listener. The Kubernetes workload explicitly binds `:8080`,
publishes the internal `tailscale-gateway-metrics` Service even while the Pod is
not ready, and allows ingress only when both of these labels are present:

- monitoring namespace: `observability.vertex-cosmos.io/metrics-access=true`;
- scraper Pod: `observability.vertex-cosmos.io/scraper=true`.

The Service and labels are transport contracts, not an assumption about a
specific monitoring product. Alerting and retention require a separately
managed monitoring system.

Do not use readiness failures as a liveness restart condition. DNS, upstream,
LocalAPI, or kernel drift may be external; the Agent already closes forwarding
and advertisements while retaining diagnostics.

## Startup Investigation

1. Confirm static configuration validation succeeded.
2. Confirm the configured file lock or Kubernetes Lease was acquired.
3. Confirm the proxy process created one healthy dual-stack TUN carrying all
   configured proxy addresses.
4. Confirm startup preparation established table 101 and local-control marking
   before containerboot started.
5. Confirm LocalAPI reports `Running`, a kernel tunnel, and node addresses.
6. Confirm target-specific route discovery completed for every nameserver and
   advertised prefix.
7. Confirm final routing, nftables, and Tailnet preference readback converged.

Never work around discovery failure by configuring an interface name or a
public probe address. Resolve the missing, ambiguous, down, multipath, or
unsupported kernel route.

## Degraded Runtime

On any reconciliation failure, the expected state is:

1. Tailnet forwarding is blocked in both directions.
2. Owned policy selectors terminate in blackhole-backed tables.
3. AdvertiseRoutes is empty.
4. Readiness is false.
5. The serialized runner retries with bounded exponential backoff while periodic
   audits remain available as a lost-event backstop.

If these conditions do not hold, treat the incident as a control-plane safety
failure. Preserve logs and kernel state, stop selecting the gateway as an exit
node, and do not manually insert objects into Agent-owned tables or priorities.

## Exit Capability Degradation

Exit advertisement requires fresh successful IPv4 and IPv6 probes through the
currently discovered proxy TUN. Initial debounce, either family being
unavailable, an expired success, or a proxy-link replacement produces an
operational condition: readiness becomes false and both Exit defaults are
withdrawn, while configured subnet advertisements and ordinary Tailnet IPv6
remain intact. These conditions do not restart the process or create a
technical-error retry storm.

Use the bounded `internet_capability_available`,
`internet_capability_probe_total`, `internet_capability_snapshot_age_seconds`,
and `condition_active` metric families to identify the affected address family
and state. Probe URLs, resolved addresses, and raw responses are intentionally
absent from metrics and logs. A recovery is not advertised until both families
pass debounce and the Agent has repeated final routing, nftables, and kernel
readback.

Endpoint values are cluster-owned production contracts. Do not substitute an
unapproved public service during an incident. Confirm the approved endpoint's
DNS family exclusivity, exact HTTPS 204 response, certificate chain, rate
limit, and upstream SOCKS reachability outside the Agent before changing
configuration.

## Kubernetes State And Credentials

Two Secrets have intentionally different ownership:

- The credential Secret is supplied by the repository SecretContract and holds
  only the declared auth key and proxy listener credentials.
- The Tailscale state Secret is an empty, declaratively pre-created object whose
  `data` is exclusively written by official kubestore. It must never be rendered
  from credential values or replaced with an empty payload.

The identity Lease is also pre-created. RBAC grants only get/update on that
Lease and get/update/patch on the one state Secret. Pod, Event, and namespace
wide Create permissions are not part of the runtime contract.

Credential rotation is an ordered operation:

1. Validate and update the credential Secret through its SecretContract tooling.
2. Increment `credentials.vertex-cosmos.io/revision` in the cluster Deployment
   patch in the Kubernetes configuration repository.
3. Render and client-dry-run the complete cluster overlay.
4. Perform the authorized deployment change as one operation.
5. Verify config rendering, proxy listener health, Agent readiness, and zero
   steady-state writes.

The revision is required because proxy credentials are consumed by init-time
rendering. Updating the Secret alone does not rebuild an existing Pod.

## Shutdown And Ownership Loss

Normal termination and Kubernetes Lease loss use the same order:

1. stop and join the serialized runner;
2. close the forwarding gate;
3. converge fail-closed routing;
4. clear and verify advertisements;
5. terminate the supervised containerboot process group;
6. release coordination ownership.

Do not terminate containerboot first. That ordering can leave restored or stale
advertisements without a live owner capable of closing the data plane.

## Release Handoff

CI and Release call the same version-controlled verification workflow, but each
trigger executes it independently against its exact full commit SHA. Every
release therefore re-runs source gates and isolated Linux integration tests,
builds a `linux/amd64` and `linux/arm64` OCI index, generates SBOM and provenance,
signs the immutable digest, and verifies both platforms. Each workflow attempt
uses a unique candidate tag. The public semver tag is promoted only as the last
external write.

Use only the real OCI digest reported by the completed release metadata. Do not
deploy a candidate tag, signature artifact tag, old digest, or mutable semver
tag. Update the Kubernetes image digest only after the Agent commit is pushed
and the complete release workflow succeeds.
