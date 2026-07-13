# Documentation

This directory is the authoritative documentation root for the Agent. Product
metadata remains at the repository root; design, reference, security, and
operational content must be placed in one of the ownership categories below.

## Architecture

- [System architecture](architecture/ARCHITECTURE.md): layer direction,
  ownership, discovery, state transitions, fail-closed behavior, and release
  invariants.
- [Exit capability and route approval](architecture/EXIT-CAPABILITY.md):
  in-process dual-stack probing, control-plane approval, advertisement
  transactions, security constraints, and validation evidence.

## Reference

- [Configuration reference](reference/CONFIGURATION.md): complete v1
  environment API, defaults, validation, and containerboot boundary.

## Runbooks

- [Operations](runbooks/OPERATIONS.md): health interpretation, startup and
  degraded-state diagnosis, credential rotation, shutdown, and release handoff.

## Security

- [Security model](security/SECURITY-MODEL.md): trust boundaries, privileges,
  state ownership, secret handling, and supply-chain controls.

New documents must have one primary owner category. Do not duplicate normative
contracts between categories; link to the authoritative document instead.
