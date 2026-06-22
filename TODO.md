# Architecture and protocol TODO

This file tracks only open work. Current implementation claims are based on the
code and [`REFACTOR_REPORT.md`](REFACTOR_REPORT.md). [`WORKER_PLAN.md`](WORKER_PLAN.md)
describes future design intent and is not evidence that the worker architecture
already exists.

## Checklist

| Done | ID | Priority | Area | Task |
|---|---|---:|---|---|
| [ ] | U1 | P1 | Accounts | Add PAM account checks and correctly owned PAM session lifecycle |
| [ ] | R2 | P1 | Architecture | Finish enforcing one-way app, protocol, security, and Unix-platform dependencies |
| [ ] | W1 | P1 | Worker boundary | Move each authenticated post-auth runtime into a disposable account worker |
| [ ] | W2 | P1 | Worker IPC | Add bounded, versioned worker startup, readiness, activation, and frame IPC |
| [ ] | W3 | P1 | Worker lifecycle | Supervise workers and relays with bounded, connection-fatal cleanup |
| [ ] | N1 | P2 | Identity | Separate dial endpoint, host verification identity, server name, and audit identity |
| [ ] | X1 | P2 | Transport | Restrict transport to immutable Noise-backed encrypted framing |
| [ ] | K1 | P2 | Keys | Make key identity canonical, immutable, and algorithm-tagged |
| [ ] | P4 | P2 | Process service | Add configurable resource limits, cgroups, and optional sandbox controls |
| [ ] | W4 | P2 | Authorization | Add monitor-owned request authorization and idempotent resource leases |
| [ ] | B1 | P2 | Verification | Add adversarial, fuzz, lifecycle, and automated release gates |
| [ ] | L1 | P3 | APIs | Rename misleading packages after the dependency boundaries stabilize |

Priority meanings: **P0** blocks a secure functional daemon, **P1** is required
for a credible v1, **P2** is important hardening/design work, and **P3** is
cleanup after the boundaries are stable.

## Task notes

### U1 — Integrate PAM policy and sessions

Add PAM account-status and deployment-policy checks before authentication
success. Define PAM session ownership around authorized command execution,
including environment and credential handling, deterministic close on command,
channel, worker, connection, or server termination, and generic peer-visible
failures.

### R2 — Finish dependency-boundary cleanup

Keep application code responsible for composing protocol, security policy, and
Unix adapters. Protocol packages must not import accounts, filesystem or trust
policy, process launch policy, or service implementations. Review remaining
`lib` package placement, prefer `internal/` for unstable application APIs, and
enforce boundaries through package placement and import direction.

### W1 — Introduce the monitor/worker boundary

Following the design in [`WORKER_PLAN.md`](WORKER_PLAN.md), keep the accepted
network connection, Noise state, server keys, client authentication, account
resolution, connection authorization, worker supervision, and final network
close in the monitor. Run one disposable post-auth mux, command service, PTY,
and process runtime in a worker launched directly with the resolved account's
UID, GID, and supplementary groups. The worker must not receive the client
socket, Noise state, private keys, trust-file authority, or authority to choose
its identity or permissions.

### W2 — Define worker startup and IPC

Use an anonymous Unix `SOCK_SEQPACKET` pair with a bounded, versioned protocol
for startup, readiness, activation, control records, and relayed session
frames. Bind startup to a monitor-generated connection ID, fresh launch nonce,
and authenticated connection exporter or digest. Validate credentials,
permissions, hard limits, process identity, socket type, inherited descriptors,
environment, record order, packet size, truncation, and ancillary data before
readiness. A narrow internal worker mode must fail closed when invoked without
the expected inherited resources.

### W3 — Relay and supervise workers

Gate authentication success on worker readiness, then activate one relay in
each direction between encrypted network frames and worker IPC records. Treat
network, Noise, IPC, phase, timeout, and worker failures as connection-fatal.
Use bounded startup and shutdown, cancellation propagation, graceful then
forced worker termination, worker and child reaping, no orphaned processes,
and one terminal connection result. Keep authoritative connection and
authorization audit events in the monitor and tag worker diagnostics with
trusted monitor metadata.

### N1 — Separate endpoint and identity concepts

Model the network address used for dialing separately from the normalized
identity used for host-key verification, an optional virtual server selector,
and server-side audit metadata. Define port, DNS case and trailing-dot, IPv6,
and future IDNA handling. Do not treat the client-supplied
`reference_identity` as authoritative server audit identity.

### X1 — Narrow and harden transport

Keep transport focused on the Noise handshake, channel binding/exporter,
encrypted frame send/receive, deadlines, and close. Make suite configuration
immutable, distinguish maximum plaintext from ciphertext/frame limits, and
make encryption or write failure terminal because cipher state may already
have advanced. Keep protobuf encoding and validation above transport and move
phase-specific operational logging to application composition.

### K1 — Harden key representation

Replace mutable key byte slices with an immutable canonical public-key identity
that includes the algorithm and excludes comments, and calculate fingerprints
over that canonical encoding. Replace panic-based signing and verification
APIs with explicit errors, clone mutable material at every ownership boundary,
and retain bounded file reads before private-key parsing.

### P4 — Add process resource isolation

Extend authorized process policy and the process owner with configurable,
mandatory-bounded resource limits. Add monitor-selected cgroup integration
where available and optional sandbox controls without allowing peer input to
select or relax them. Ensure setup failures occur before start acceptance and
cleanup follows the existing process-group and worker termination lifecycle.

### W4 — Add monitor-owned authorization leases

Extend the worker boundary with a bounded request/decision IPC for privileged
authorization that cannot safely become a transferable snapshot, including
future PAM sessions and monitor-owned resources. Bind decisions and opaque
lease IDs to the connection, worker launch, channel, and request. Lease close
must be idempotent and must occur on normal completion, worker crash, client
disconnect, or server shutdown without depending on peer acknowledgment.

### B1 — Strengthen verification and release gates

Make tests, race detection, vet/static analysis, vulnerability scanning, and
formatting deterministic project gates. Add parser fuzzing and broader
adversarial authentication coverage. For the worker boundary, test real
subprocesses and inherited socket-pair descriptors, malformed and out-of-order
IPC, bounds and truncation failures, credential/binding mismatches, startup
timeouts, crashes, disconnects, shutdown, relay failure, worker and child
reaping, generic peer errors, idempotent cleanup, and raw terminal-byte
preservation.

### L1 — Simplify composition APIs

Keep protocol constructors free of application logger plumbing and retain
application ownership of diagnostic logger configuration. Rename generic or
misleading packages, especially the global post-auth `session` mux, after the
worker and dependency boundaries are stable.

## Explicitly deferred

These are not checklist items until the foundations above are stable:

- SSH wire compatibility.
- Reconnect or session resume.
- Broad algorithm negotiation without a second supported suite.
- A generic plugin/service framework.
- Port forwarding before destination-specific authorization, limits, and
  lifecycle ownership are designed.
- Separating authentication parsing into another disposable worker after the
  monitor/post-auth worker boundary is established.
