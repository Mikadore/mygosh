# Architecture and protocol TODO

This checklist is distilled from [`REVIEW.md`](REVIEW.md). Finding IDs match the review; `R1`–`R5` are cross-cutting refactors derived from its recommended architecture. The table reflects the current implementation status.

## Checklist

| Done | ID | Priority | Area | Task |
|---|---|---:|---|---|
| [x] | A1 | P0 | Authentication | Separate cryptographic authentication from account authorization |
| [x] | A2 | P1 | Authentication | Make auth success guarantee a complete, usable connection identity |
| [x] | T1 | P0 | Trust/files | Use bounded, race-resistant secure opens for every sensitive file |
| [ ] | T2 | P1 | Trust/files | Define and enforce supported `authorized_keys` and `known_hosts` semantics |
| [x] | T3 | P1 | Authentication | Stop disclosing local authorization and filesystem details to peers |
| [x] | S1 | P0 | Connection mux | Prevent handlers and writes from blocking the sole receive owner |
| [x] | S2 | P1 | Connection mux | Add hard connection-wide resource limits |
| [x] | S3 | P1 | Connection mux | Formalize channel state, ordering, identity, and cancellation cleanup |
| [ ] | E1 | P0 | Server app | Replace the one-connection demo with a bounded daemon accept loop |
| [x] | E2 | P1 | Lifecycle | Give each connection phase one clear lifetime and close owner |
| [ ] | P1 | P1 | Process service | Prevent no-reply exec requests from leaking started children |
| [ ] | P2 | P1 | Process service | Remove peer-dependent and pre-exec indefinite waits |
| [ ] | P3 | P1 | Process service | Own, terminate, and reap complete child process groups |
| [x] | C1 | P1 | Credentials | Introduce immutable per-connection credentials tied to the authenticated connection |
| [x] | C2 | P1 | Authorization | Add connection-level permissions and concrete request authorization |
| [ ] | N1 | P2 | Identity | Separate dial endpoint, host verification identity, server name, and audit identity |
| [ ] | X1 | P2 | Transport | Restrict transport to Noise-backed encrypted framing |
| [ ] | K1 | P2 | Keys | Make key identity canonical, immutable, and algorithm-tagged |
| [ ] | D1 | P2 | Client terminal | Make terminal input forwarding cancellable |
| [ ] | D2 | P1 | Service protocol | Replace the PTY-only command demo with explicit shell and exec semantics |
| [ ] | B1 | P2 | Verification | Add adversarial, fuzz, lifecycle, and end-to-end release gates |
| [ ] | L1 | P3 | APIs | Replace composition-heavy `WithLogger` APIs and misleading package names |
| [x] | R1 | P0 | Authentication | Implement staged verified-proof → policy → accept/reject server authentication |
| [ ] | R2 | P1 | Architecture | Enforce one-way app, protocol, security, and Unix-platform dependencies |
| [x] | R3 | P1 | Trust/files | Split path policy, secure opening, parsing, matching, and authorization policy |
| [x] | R4 | P1 | Accounts | Establish deliberate NSS, PAM, and process-credential seams |
| [x] | R5 | P1 | Services | Define a credential-aware service registry and authorized launch/forward specifications |

Priority meanings: **P0** blocks a secure functional daemon, **P1** is required for a credible v1, **P2** is important hardening/design work, and **P3** is cleanup after the boundaries are stable.

## Task notes

### A1 — Separate authentication from authorization

Keep `lib/auth` responsible for transcript construction, signature verification, protocol state, and the wire accept/reject exchange. Move NSS lookup, `authorized_keys` policy, Unix accounts, permissions, and service decisions into server application composition; see finding **A1** in [`REVIEW.md`](REVIEW.md#findings).

### A2 — Make auth success mean ready

Do not send auth success until account resolution, mandatory policy checks, permission calculation, and credential validation have completed. A successful peer response must guarantee that the server can construct the post-auth connection and is ready to evaluate service requests; see **A2**.

### T1 — Secure every sensitive file read

Route host keys, client keys, `known_hosts`, and `authorized_keys` through bounded descriptor-based opens with explicit owner, mode, type, symlink, directory, and size policies. Adapt `strictfiles` for root-owned and target-account-owned paths instead of continuing to use unbounded `os.ReadFile`; see **T1**.

### T2 — Define trust-file semantics

Choose and document the supported subset of OpenSSH file formats, including options, revoked keys, certificate-authority markers, hashed/wildcard hosts, malformed entries, and host-plus-port identities. Unsupported security-significant syntax must fail explicitly or produce explicit constraints rather than being silently skipped; see **T2**.

### T3 — Return generic authentication failures

Keep precise NSS, parser, path, and key-matching errors in server logs while returning stable generic failure codes/messages to the peer. Authentication must not reveal whether a username exists, which files were checked, or why local policy rejected the attempt; see **T3**.

### S1 — Keep the receive owner non-blocking

Retain exactly one frame decoder, but do not let it synchronously run arbitrary service work or wait on network writes/replies. Introduce bounded dispatch and serialized bounded writing so handler reentrancy, NSS/PAM work, process startup, and best-effort disconnects cannot deadlock the connection; see **S1**.

### S2 — Bound all peer-controlled resources

Add configurable limits for channels, pending opens, outstanding requests, queued frames and bytes, empty data frames, control payloads, auth attempts, and relevant timeouts. Per-channel byte windows alone do not prevent cheap connection-wide memory and ID exhaustion; see **S2**.

### S3 — Formalize channel state

Implement explicit opening, open, half-closed, closing, closed, and failed transitions, and validate every incoming frame against them. Detect duplicate peer channel IDs, reject data after EOF, prevent pre-accept channel use, remove canceled waiters, and define consistent rollback after send failures; see **S3**.

### E1 — Build a real server accept loop

Load long-lived configuration and host keys before listening, then accept multiple clients with global/per-source concurrency controls, temporary-error backoff, per-connection panic containment, connection IDs, and graceful shutdown. TCP lifecycle and admission policy remain app responsibilities; see **E1**.

### E2 — Clarify connection ownership

Give the raw socket, secure transport, authentication phase, and post-auth connection explicit ownership transfer rules. Move handshake/auth timeout machinery out of the session package and ensure only the current/final owner closes the connection and reports its terminal error; see **E2**.

### P1 — Fix no-reply exec lifecycle

When a shell/exec service is reintroduced, an exec request with `want_reply=false` must not be able to start a child before forwarding, waiting, and cleanup ownership are active. Either require replies for process-start requests or restructure startup so process ownership and reaping are active before any child can exist; see **P1**.

### P2 — Make channel completion locally enforceable

Future shell/exec channels must complete locally even if the peer withholds a close acknowledgment. Define bounded close behavior, proper stdin half-close semantics, write deadlines, and terminal states that complete independently of peer cooperation; see **P2**.

### P3 — Own the full process tree

Create a process runner for the future service layer that owns the command, PTY or pipes, process group/session, wait result, signaling sequence, and descriptor cleanup. On channel, connection, timeout, or server shutdown, terminate descendants with bounded graceful and forced phases and reap every child exactly once; see **P3**.

### C1 — Use immutable connection credentials

Construct one validated credential snapshot containing authentication facts, account data, and broad permissions, and carry it alongside the authenticated connection for its whole lifetime. Hide or copy mutable byte/group slices, and prevent production services from being paired with an anonymous directly constructed mux; see **C1**.

### C2 — Add a two-level permission model

Before auth success, resolve every permission and constraint knowable from the peer, key, account, configuration, and later PAM policy. Before resource creation, authorize the concrete shell, command, PTY, environment, subsystem, or forwarding target against that immutable connection policy; see **C2**.

### N1 — Separate endpoint and identity concepts

Model the network address used for dialing separately from the normalized identity used for host-key verification, an optional virtual server selector, and server-side audit metadata. Define handling for ports, DNS case/trailing dots, IPv6, and future IDNA rather than trusting a client-supplied `reference_identity` as a server fact; see **N1**.

### X1 — Narrow the transport package

Keep transport focused on the Noise handshake, channel binding/exporter, encrypted frame send/receive, deadlines, and close. Move protobuf encoding/validation and phase logging upward, make algorithm choices immutable, distinguish plaintext and ciphertext limits, and make any encryption/write failure fatal; see **X1**.

### K1 — Harden key representation

Use immutable canonical public-key identity that includes the algorithm and excludes comments, and calculate fingerprints over that encoding. Avoid panic-based signing APIs, clone key material at ownership boundaries, and apply file-size limits before parsing private keys; see **K1**.

### D1 — Cancel terminal input safely

When an interactive client path returns, do not leave a goroutine blocked on `os.Stdin` after a remote process or connection ends, because it can later consume input intended for the restored local shell. Use polling/select on a dedicated descriptor, a safely closable duplicate, or a single terminal-I/O owner; see **D1**.

### D2 — Define real shell and exec requests

The current app path stays connected with a reject-all mux and no service implementation. Replace that placeholder with optional PTY setup followed by exactly one shell or exec request. Add non-PTY stdout/stderr separation, account-config-selected login shells, exit status/signals, filtered environment requests, and correct remote exit propagation; see **D2**.

### B1 — Strengthen verification and release gates

Make tests, race detection, vet/static analysis, vulnerability scanning, and formatting deterministic project gates. Add malformed-auth, duplicate-ID, data-after-EOF, callback-reentrancy, cancellation, queue-limit, parser fuzzing, terminal restoration, descendant cleanup, and fully authenticated process-launch tests; see **B1**.

### L1 — Simplify composition APIs

Remove constructors whose names encode protocol role, storage format, policy, and logger wiring all at once. Prefer small configs and pure parser/matcher primitives, let the app own operational logging, and rename generic or ambiguous packages such as the global `session` mux and current `service` protocol; see **L1**.

### R1 — Implement staged server authentication

Expose a verified client proof and a one-shot pending auth decision from the protocol layer, then let server policy resolve credentials before calling accept or reject. The post-auth mux must not be constructible or exposed through this production path until acceptance succeeds; see “Authentication and credential API shape” in [`REVIEW.md`](REVIEW.md#authentication-and-credential-api-shape).

### R2 — Enforce dependency direction

Restructure packages so app code composes protocol, security, and Unix adapters, while protocol packages never import accounts, filesystems, deployment policy, or service implementations. Consider `internal/` for unstable application APIs and use package placement/import direction—not the name `lib`—to enforce boundaries; see “Recommended architecture.”

### R3 — Decompose trust handling

Make the app choose file paths, precedence, missing-file behavior, and strictness; make secure-file code only open/check caller-selected paths; make parsers consume supplied streams; and make pure matchers return entries/constraints. Account authorization should combine these primitives without living in either the auth protocol or parser package; see “Safe trust-file API.”

### R4 — Establish NSS and PAM seams

Create a Unix account resolver that deliberately follows NSS and snapshots username, UID, GID, groups, home, and login shell, then place future PAM account/auth checks before auth success. Keep PAM session lifecycle and process credential changes in the privileged account/process layer rather than the wire protocol; see “NSS, PAM, and Unix credentials.”

### R5 — Define credential-aware services

Create a connection service registry that receives the immutable credential snapshot and routes only supported channel types. Each service must turn a decoded peer request plus credentials into an authorized launch or forwarding specification before allocating a PTY, starting a process, or opening a socket; see “Where authorization should occur” and “Service model for shell, exec, and forwarding.”

## Explicitly deferred

These are not checklist items until the foundations above are stable:

- SSH wire compatibility.
- Reconnect or session resume.
- Broad algorithm negotiation without a second supported suite.
- A generic plugin/service framework.
- Immediate process separation before credential and launch interfaces settle.
- Port forwarding on top of the current synchronous, unbounded handler model.
