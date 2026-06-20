# `mygosh` post-refactor architecture review

> Review date: 2026-06-21
>
> Reviewed revision: `cb0a7b2c67ce` (`master`)
>
> Scope: the current tracked Go, protobuf, build, and support code, with emphasis on the architecture required by [`WORKER_PLAN.md`](WORKER_PLAN.md).
>
> Evidence rule: the previous review is accepted as the pre-refactor baseline. Claims in `REFACTOR_REPORT.md`, `AGENTS.md`, `README.md`, `TODO.md`, and other summaries were checked against the implementation and tests before being used here.

## Executive summary

The refactor was substantial and directionally successful. The repository is no longer in the architectural state described by the old review:

- cryptographic authentication is staged before app-owned account and key authorization;
- auth success is withheld until immutable connection credentials and the post-auth session configuration exist;
- sensitive key and trust files are read through bounded descriptor-relative checks;
- the post-auth mux has a single receive owner, a serialized writer, bounded queues, explicit channel states, duplicate-ID checks, and cancellation cleanup;
- command handling is a separate directional protocol rather than a generic PTY payload;
- shell and exec requests are authorized before process creation;
- process ownership now includes PTY/pipes, process groups, wait, descendant termination, and bounded cleanup;
- local terminal input can be canceled without consuming input after the client returns.

These changes establish most of the in-process prerequisites identified by the old review. They do **not** implement the security boundary in `WORKER_PLAN.md`.

The current server still runs the post-auth mux, command parser, PTY handling, and process service in the same process that holds:

- the host private key;
- account and trust-file authority;
- the authenticated Noise transport and network socket;
- the authorization policy object;
- all post-auth service state.

There is no worker entrypoint, IPC protocol, `SOCK_SEQPACKET` transport, startup snapshot, readiness/activation exchange, relay, worker supervisor, privilege-demoted worker launch, or worker process test. More importantly, the current establishment and authorization APIs still encode assumptions that are incompatible with the planned split:

1. [`PendingServer.Accept`](lib/establish/server.go#L141) can commit authentication only by binding the secure transport directly to an in-process `session.Session` and then transferring close ownership to that session.
2. `ConnectionCredentials`, `ConnectionPermissions`, and `AuthorizedChannel` are immutable enough for one address space, but they have no versioned plain-data encoding and use an in-process pointer token to bind channel authorization to credentials.
3. The worker cannot construct the current command service from a validated snapshot alone because the only implementations able to mint the private authorization values are methods on the monitor-side `*authz.Authz` object.

The right next milestone is therefore not more command functionality. It is to make the monitor/worker boundary real while preserving the current authenticated shell and exec path.

### Overall assessment

| Area | Current assessment |
|---|---|
| Auth transcript and staging | Good foundation; app authorization is now outside the auth protocol |
| Credentials and authorization | Good in-process snapshot; not yet a transferable worker startup contract |
| Secure-file handling | Materially improved; all production key/trust reads are bounded and checked |
| Session mux | Stronger and suitably transport-neutral, with one remaining started-write cancellation problem |
| Command protocol | Credible and well-separated from Unix policy |
| Process lifecycle | Strong prerequisite for a worker; currently executes inside the privileged server process |
| Monitor/worker split | Not implemented |
| Server lifecycle | Still a one-connection demo rather than a long-lived monitor |
| Trust semantics | Still incomplete and security-significant |
| Verification | Healthy unit/race baseline, but no fuzzing, daemon tests, or real subprocess IPC tests |

The concise conclusion is:

> The refactor made the process split feasible without redesigning the external protocol, but the repository has not crossed the process boundary yet.

---

## Verification performed

The worktree was clean before this review replaced `REVIEW.md`.

The following passed with Go 1.26.4:

```text
go test ./...
go test -race -count=1 ./...
go vet ./...
go test -shuffle=on -count=5 \
  ./lib/session ./lib/establish ./lib/command \
  ./app/server/process ./app/commandchannel
go mod verify
go build ./bin
gofmt -d on all handwritten Go files
```

`gofmt -d` produced no output.

Statement coverage from `go test -count=1 -coverprofile=... ./...` was **51.1%**, including generated protobuf code. Relevant package results:

| Package | Coverage |
|---|---:|
| `lib/wire` | 96.3% |
| `lib/transport` | 86.2% |
| `lib/establish` | 79.1% |
| `app/server/process` | 75.5% |
| `app/server/authz` | 73.5% |
| `lib/command` | 73.0% |
| `lib/session` | 72.6% |
| `app/commandchannel` | 66.7% |
| `lib/trust` | 46.4% |
| `app/server/command` | 34.4% |
| `app/server` | 19.8% |
| direct `lib/auth` tests | 9.3% |
| `bin` | 0.0% |

The suite contains 157 ordinary tests and no fuzz tests.

Not performed:

- manual `run-tmux.sh` smoke testing;
- vulnerability scanning;
- a worker/IPC smoke test, because no worker implementation exists;
- a daemon concurrency test, because the server accepts only one connection.

---

## Current architecture reconstructed from code

### Server sequence

The production server path is currently:

```text
load host key securely
  -> construct account/key/permission authorization
  -> listen
  -> accept exactly one TCP connection
  -> Noise handshake
  -> verify client cryptographic proof
  -> resolve account and authorized_keys
  -> construct immutable credentials and permissions
  -> construct command service and credential-bound registry
  -> prepare and bind in-process post-auth session
  -> send auth success
  -> activate in-process session workers
  -> parse commands and start processes in the server process
  -> wait for that one connection and exit
```

The central composition is visible in [`app/server/server.go`](app/server/server.go):

- the host key is loaded before listening;
- [`establish.BeginAccept`](lib/establish/server.go#L51) returns a verified but undecided auth exchange;
- [`Authz.AuthorizeConnection`](app/server/authz/authz.go#L82) resolves the account, securely reads `authorized_keys`, applies policy, and creates credentials;
- the command service and registry are created before wire success;
- [`session.Prepare`](lib/session/session.go#L130) validates limits and captures the handler graph;
- [`PendingServer.Accept`](lib/establish/server.go#L141) binds the mux, sends auth success, activates the mux, and transfers transport ownership to it.

This ordering is a real improvement over the pre-refactor code. In the current one-process topology, auth success now means that mandatory connection policy and post-auth construction have succeeded.

### Current ownership

```text
app/server
  owns listener and accepted TCP connection initially

lib/establish.runtime
  owns raw connection during handshake
  owns Noise transport during auth and policy

lib/session.Session
  receives the Noise transport on acceptance
  owns post-auth reads, writes, close, channels, and handlers

app/server/command + app/server/process
  run inside the same process as all of the above
```

The target ownership from `WORKER_PLAN.md` is different:

```text
monitor
  permanently owns Noise transport, network socket, auth authority,
  worker creation, relay, supervision, reaping, and final network close

worker
  owns only its IPC endpoint, session mux, command/PTY service,
  child processes, and connection-local cleanup
```

The current ownership transfer to `Session` is correct for the in-process design but must be changed for the worker design.

### Protocol and service boundaries

The implementation now has useful boundaries:

```text
transport.Transport
  encrypted byte frames + channel binding

wire.Framer / wire.FramedConn
  transport-neutral frame contract

auth
  auth protobuf state and cryptographic proof

session
  transport-neutral post-auth mux

command
  transport-neutral directional command protocol

commandchannel
  session.Channel <-> command.FrameConn adapter

server authz
  account, authorized_keys, credentials, permissions, launch authorization

server process
  already-authorized Unix process runtime
```

This is close to the dependency shape needed by a worker. The remaining issue is that the app authorization values are still designed as private in-process capabilities rather than a monitor-minted snapshot that a worker can validate and enforce.

---

## Refactor outcomes verified in code

### Authentication and app authorization are separated

`lib/auth` no longer imports accounts, filesystems, trust paths, or Unix process policy. [`VerifiedClient`](lib/auth/auth.go#L101) clones the proved and server public keys, while [`PendingServerAuth`](lib/auth/server_auth.go#L17) provides a one-shot accept/reject decision after signature verification.

`app/server/authz` now owns:

- NSS-aware account resolution;
- `authorized_keys` path policy;
- secure file reads;
- key matching;
- account policy;
- connection permission calculation;
- request-specific command authorization.

This resolves the old A1/R1 boundary problem.

### Auth success is delayed until current in-process readiness

The server authorizes the client, builds the service registry, prepares the mux, and binds it before [`PendingServerAuth.Accept`](lib/auth/server_auth.go#L57) sends success. Session workers exist before acceptance but wait on explicit activation.

This resolves the old A2 issue for the current topology. Worker readiness must become the new readiness condition.

### Credentials are immutable at their public boundaries

[`ConnectionCredentials`](app/server/authz/credentials.go#L13) keeps fields private, clones the public key and account, and returns copies. `ConnectionPermissions` similarly clones its environment allowlist. The service registry stores one credential value for the connection.

The general `keys.PublicKey`, `keys.Keypair`, and `account.Account` types still expose mutable slices, but the security-sensitive connection boundary no longer leaks those slices directly.

### Sensitive file reads are checked and bounded

Production host keys, client keys, `known_hosts`, and `authorized_keys` are all loaded through [`app/securefiles.Read`](app/securefiles/read.go#L22). It:

- pins an app-selected anchor;
- rejects `..`;
- traverses with descriptor-relative opens;
- forbids symlinks below the anchor;
- checks file and directory type, owner, and write mode;
- applies a size bound before and during reading;
- uses close-on-exec descriptors.

No production credential or trust path uses `os.ReadFile`.

This resolves the main old T1 finding. The app still deliberately allows a selected anchor itself to be reached through symlinks, then validates the opened target; that is a policy choice worth keeping explicit.

### Peer-visible local authorization failures are generic

Local account, file, parser, and key-match errors are logged on the server. Rejection through [`PendingServerAuth.Reject`](lib/auth/server_auth.go#L74) uses the stable `authentication-failed` response.

Protocol-version and malformed-auth failures may still produce protocol-specific public errors, but the previous user/file enumeration path through app authorization has been removed.

### The mux is substantially hardened

The session implementation now has:

- a receiver loop that does not execute service handlers;
- a serialized writer loop;
- a bounded dispatch queue;
- per-channel event workers;
- configurable defaults and compiled hard maxima;
- channel, pending-open, request, frame, byte, type, code, message, and payload limits;
- explicit opening/open/half-closed/closing/closed/failed states;
- duplicate peer channel-ID rejection;
- duplicate request and EOF checks;
- rejection of empty channel data;
- data-after-EOF rejection;
- waiter removal on caller cancellation;
- bounded local channel-close timeout;
- fatal handling of started write failure;
- preservation of already queued data before remote-close EOF.

This materially resolves the old S1–S3 findings. One important cancellation flaw remains and is documented below.

### Command and process architecture is credible

The new command path has a clean protocol/application split:

- `lib/command` knows neither session nor Unix process policy;
- `app/commandchannel` is the only protocol adapter;
- channel open and exact launch requests are authorized before process creation;
- the runner receives a plain authorized process specification;
- non-PTY stdout/stderr remain separate;
- PTY output is merged;
- shell, exec, environment, resize, EOF, status, and signal semantics are explicit.

The process runner:

- applies explicit UID, GID, and supplementary groups;
- rejects unprivileged identity mismatch;
- starts a process group or PTY session;
- has one wait owner;
- terminates descendants with bounded `SIGTERM` then `SIGKILL`;
- reaps the leader once;
- cleans residual descendants after leader exit;
- does not require peer close acknowledgment.

This resolves the main old P1–P3 and D1–D2 findings and gives the future worker a suitable service runtime.

---

## `WORKER_PLAN.md` readiness matrix

| Worker-plan requirement | Status in current code |
|---|---|
| Monitor retains encrypted network transport for full connection | **Not met.** Ownership transfers to in-process `Session`. |
| One disposable worker per authenticated connection | **Not implemented.** |
| Worker receives framed cleartext, not TCP or Noise state | Framer abstraction exists; IPC/relay does not. |
| Anonymous Unix `SOCK_SEQPACKET` socket pair | **Not implemented.** |
| Versioned startup/control protocol | **Not implemented.** |
| Connection ID, launch nonce, and authenticated binding | **Not represented.** |
| Plain transferable credential and permission snapshot | In-process values exist; no transferable form or decoder exists. |
| Independent worker validation | **Not implemented.** |
| Worker launched under final UID/GID/groups | Process children can use explicit credentials; worker launch does not exist. |
| Worker verifies its effective identity | Per-process runner checks some identity state; no startup check exists. |
| Narrow worker entrypoint bypassing normal app startup | **Not implemented.** All commands run the normal persistent pre-run. |
| Worker readiness before client auth success | In-process mux preparation follows this pattern; no worker readiness exchange exists. |
| Explicit activation after auth success | In-process `Session.Activate` exists; no cross-process activation protocol exists. |
| Bidirectional bounded relay | **Not implemented.** |
| Monitor owns worker supervision and reaping | **Not implemented.** |
| Worker cannot access keys, trust files, listener, or network fd | No isolation boundary exists yet. |
| Snapshot-only request authorization | Conceptually possible, but current private grant types prevent reconstruction outside `authz`. |
| Monitor-owned authorization/lease RPC seam | **Not implemented.** |
| Real subprocess and inherited-fd tests | **Not implemented.** |
| Long-lived bounded daemon | **Not met.** Server accepts one connection and exits. |

---

## Findings

Severity meanings:

- **Blocker**: the target worker architecture cannot be implemented correctly without changing this boundary.
- **High**: required for a credible initial worker slice or contains a current security/liveness defect.
- **Medium**: important hardening or later worker-plan work.
- **Low**: cleanup that should follow the boundary work.

### Summary

| ID | Severity | Finding |
|---|---|---|
| W1 | Blocker | Establishment can commit auth only by handing Noise transport to an in-process session |
| W2 | Blocker | No worker process, IPC protocol, relay, or supervisor exists |
| W3 | High | Credentials and permissions are not a versioned, independently validatable startup snapshot |
| W4 | High | Channel and launch authorization grants are in-process capabilities that cannot cross or be reconstructed behind IPC |
| W5 | High | Worker readiness, auth commit, and relay activation have no explicit cross-process state machine |
| W6 | High | Monitor-owned relay failure, close ownership, worker termination, and reaping are undefined in code |
| W7 | High | Worker privilege, descriptor, environment, and direct-invocation checks are absent |
| W8 | High | A canceled started session write can spin and wait indefinitely |
| W9 | High | The server is still a one-connection process, not a long-lived monitor |
| W10 | Medium | Transport details still need cleanup before becoming the permanent monitor relay endpoint |
| W11 | Medium | Trust, endpoint identity, key identity, and production policy remain monitor-side security debt |
| W12 | Medium | Verification does not cover the planned process boundary or hostile IPC |

### W1 — Establishment hardwires acceptance to an in-process mux

**References**

- [`PendingServer.Accept`](lib/establish/server.go#L141)
- direct bind of `p.secureConn` at [`lib/establish/server.go:159`](lib/establish/server.go#L159)
- auth success at [`lib/establish/server.go:170`](lib/establish/server.go#L170)
- transfer/release at [`lib/establish/server.go:179`](lib/establish/server.go#L179)

`BeginAccept` correctly keeps Noise and auth pending while app policy runs. The problem is the only successful completion path:

1. accept a `*session.Prepared`;
2. bind it directly to the Noise `Transport`;
3. make the session the close owner;
4. send auth success;
5. activate the session;
6. release establishment ownership.

The worker design requires the opposite post-auth ownership:

- the monitor keeps `Transport`;
- the worker binds `Session` to IPC;
- auth success is committed only after the worker is ready;
- monitor relays begin only after commit;
- monitor remains final network owner.

There is currently no API that lets server orchestration:

- retain the authenticated secure framer;
- commit the pending auth decision without constructing a local mux;
- bind that commitment to a ready worker;
- start relay while keeping final close ownership.

This is the primary boundary refactor.

Recommended shape:

```text
BeginAccept
  -> pending verified auth + monitor-owned secure connection
  -> app authorization
  -> worker supervisor starts and validates readiness
  -> pending.CommitAccept(readiness binding)
  -> monitor activates relay
  -> monitor waits for client, relay, worker, or shutdown failure
```

The exact exported API can vary, but `lib/establish` must stop assuming that every accepted server connection becomes a local `session.Session`.

### W2 — The process boundary itself does not exist

There is no implementation of:

- `socketpair(AF_UNIX, SOCK_SEQPACKET, ...)`;
- IPC packet send/receive;
- startup/control records;
- ancillary-data rejection;
- truncation detection;
- inherited worker descriptor handling;
- an internal worker mode;
- worker process creation;
- readiness or activation;
- bidirectional frame relay;
- worker exit supervision or reaping.

The only binary modes registered in [`bin/mygosh.go`](bin/mygosh.go) are `server` and `connect`. A source search finds no worker, relay, seqpacket, socketpair, launch nonce, or readiness implementation.

The initial worker milestone should remain deliberately narrow:

```text
one authenticated connection
  -> one worker
  -> current command service
  -> current PTY/non-PTY process runner
```

Port forwarding, PAM RPC, and a generalized plugin system are unnecessary for proving this boundary.

### W3 — The credential model is immutable but not transferable

**References**

- [`ConnectionCredentials`](app/server/authz/credentials.go#L13)
- [`ConnectionPermissions`](app/server/authz/permissions.go#L52)
- [`account.Account`](lib/account/user.go#L25)

The current credential object is good for in-process use. It contains:

- authentication method;
- key fingerprint and proved key;
- requested username;
- peer address;
- resolved account including UID, GID, groups, home, and shell;
- matched authorization source;
- command/shell/exec/PTY/environment permissions.

It does not provide the worker startup contract required by the plan:

- no IPC protocol version;
- no startup message type;
- no monitor-generated connection identifier;
- no launch nonce;
- no binding to the authenticated Noise connection;
- no selected service configuration;
- no session limits/timeouts snapshot;
- no explicit unknown-field or unknown-permission policy;
- no encoded total/field/count limits;
- no constructor/decoder for rebuilding validated credentials in another process.

The authenticated Noise channel binding exists on `transport.Transport`, but it is not carried in `VerifiedClient` or `ConnectionCredentials`. The monitor can include a digest of it in startup data, but this needs an explicit design rather than an accidental dependency on a live Go object.

Independent validation also needs to be stronger than current credential validation. The worker should reject:

- duplicate or excessive supplementary groups;
- a primary GID repeated as supplementary;
- non-normalized home or shell paths;
- empty or oversized resolved usernames and policy sources;
- fingerprint/key mismatch;
- unsupported auth methods or permission bits;
- limits above worker hard maxima;
- permission/constraint combinations the worker does not understand.

Use a versioned plain-data message, probably protobuf because the project already uses it, but keep it separate from external auth and session schemas.

### W4 — Authorization grants are tied to one address space

**References**

- private credential token in [`app/server/authz/credentials.go:11`](app/server/authz/credentials.go#L11)
- [`AuthorizedChannel`](app/server/authz/launch.go#L20)
- pointer-identity check at [`app/server/authz/launch.go:159`](app/server/authz/launch.go#L159)
- [`app/server/command.NewService`](app/server/command/service.go#L29)
- [`services.Registry`](app/server/services/registry.go#L25)

`AuthorizedChannel` binds itself to credentials through a private `*credentialIdentity`. That is a sensible in-process anti-mixup check, but pointer identity cannot be serialized.

The worker cannot simply implement equivalent authorization outside the `authz` package:

- `AuthorizedChannel` fields are private;
- `AuthorizedLaunchSpec` fields are private;
- `ConnectionCredentials.validate` is private;
- only methods on `*Authz` can mint the required values;
- `Authz.New` requires resolver and `authorized_keys` configuration, authority the worker must not receive.

Although current `AuthorizeChannel` and `AuthorizeLaunch` use only the credential snapshot after connection authorization, their type design still couples pure enforcement to the monitor-side policy object.

Before the split, separate:

1. **monitor policy**, which resolves accounts, files, PAM/account status, and broad permissions;
2. **snapshot validation/enforcement**, which operates only on plain validated startup data;
3. **optional monitor RPC**, for future PAM leases or privileged request decisions.

For the initial split, the worker can mint connection-local grants after validating the startup snapshot. Use stable connection or credential IDs rather than transferred pointer identity.

### W5 — There is no cross-process readiness and activation state machine

The current in-process sequence is a useful template:

```text
prepare handler graph
  -> bind session without activation
  -> send auth success
  -> activate session
```

The worker sequence needs explicit records and one-shot transitions:

```text
monitor: STARTUP(connection_id, nonce, binding, credentials, limits)
worker:  READY(connection_id, nonce)
monitor: commit client auth success
monitor: ACTIVATE(connection_id, nonce)
worker:  begin session receive/write workers
```

Current code has no representation for:

- repeated or out-of-order startup;
- session frames arriving before startup or activation;
- readiness for the wrong connection;
- stale activation after a worker restart;
- worker crash between readiness and auth commit;
- client disconnect while the worker is starting;
- a bounded transition queue.

The auth timeout currently remains active while app policy runs. Worker startup also needs a bounded deadline. It may share a complete pre-auth deadline or use a separately capped worker-start timeout, but client auth success must still wait for readiness.

### W6 — Relay and terminal ownership are not implemented

The monitor must own two concurrent relay directions:

```text
network ReceiveFrame -> IPC session-frame record
IPC session-frame record -> network SendFrame
```

Either direction failing is connection-fatal. The monitor must converge:

- client disconnect;
- decrypt/encrypt or network I/O failure;
- malformed/truncated/oversized IPC packet;
- unexpected ancillary data;
- worker crash or IPC close;
- monitor shutdown;
- startup or activation violation.

Current `establish.runtime` transfers ownership away after acceptance. It does not own:

- a worker process;
- an IPC endpoint;
- two relay goroutines;
- a supervisor wait result;
- bounded worker termination;
- worker reaping;
- final cause selection across all participants.

The new monitor connection owner should have one terminal transition and idempotent cleanup. It should close the network connection itself, close IPC, cancel both relays, terminate the worker when required, reap it, and report one authoritative connection result.

### W7 — Worker startup is not narrow or independently checked

Every current Cobra command executes the root [`PersistentPreRunE`](bin/mygosh.go#L51), which:

- loads `mygosh.toml`;
- constructs ordinary application logging;
- may open a configured log file.

A worker must not take that path. It needs an internal entrypoint that consumes only expected inherited descriptors and startup data. Direct invocation without those resources must fail closed.

The monitor also does not currently launch a process with the account's UID, primary GID, and supplementary groups. [`app/server/process`](app/server/process/runner.go) contains valuable identity validation for child processes, but that validation occurs when starting each command, not before a worker acknowledges readiness.

Before `READY`, the worker must verify:

- effective UID and GID;
- supplementary groups;
- whether privilege is expected or forbidden;
- IPC descriptor number and connected `SOCK_SEQPACKET` type;
- close-on-exec behavior;
- absence of unexpected inherited listener, network, key, trust, or log descriptors;
- filtered environment;
- absence of unsafe loader variables;
- absolute policy-derived shell and working directory;
- supported compiled hard limits.

The secure-file code already uses close-on-exec descriptors, and Go-created network descriptors normally do as well. That is helpful defense, not a substitute for explicit worker descriptor validation.

### W8 — Started session writes do not honor caller cancellation

**Reference**

- [`Session.sendEnvelopeAfter`](lib/session/session.go#L924)

The writer queue fixed the old receive-loop blocking defect, but cancellation is incomplete.

When a caller context is canceled, `sendEnvelopeAfter` returns only if it can atomically change the write from `writeQueued` to `writeCanceled`. If the writer has already changed it to `writeStarted`, the compare-and-swap fails and the loop continues waiting for the writer result.

Because `ctx.Done()` remains continuously ready, the function can spin until the underlying write completes. If that write is blocked, the caller's timeout is neither a completion bound nor an interruption mechanism.

Consequences:

- a command output or exit send can outlive its advertised timeout;
- a service goroutine can spin while the writer is blocked;
- cleanup may still depend on closing the whole session connection;
- the planned IPC relay cannot rely on caller contexts to bound a started `SOCK_SEQPACKET` send.

This means the old S1/P2 work is materially improved but not completely finished.

Fix the contract before IPC:

- use nonblocking I/O plus `poll`, or real write deadlines, for relay and framed connections;
- make started-write cancellation close/fail the owning connection when a frame cannot be abandoned safely;
- ensure `sendEnvelopeAfter` returns without spinning;
- test a write that has definitely started and whose peer never reads.

For Noise writes, failure after cipher-state advancement must remain connection-fatal.

### W9 — The server is not yet a long-lived monitor

**Reference**

- one [`listener.Accept`](app/server/server.go#L83)

The server:

1. listens;
2. accepts one connection;
3. waits for that connection;
4. exits.

The first worker slice could preserve one-connection behavior while proving IPC, but the full worker plan describes a long-lived monitor. It eventually needs:

- an accept loop;
- global and optionally per-source admission limits;
- connection IDs;
- one supervised monitor connection owner per client;
- temporary accept-error backoff;
- panic containment;
- graceful shutdown that stops acceptance;
- active worker termination and reaping;
- a bounded wait for all connections;
- tests showing one worker crash does not terminate other connections.

Do not put this admission policy in transport or session packages.

### W10 — Transport needs cleanup before permanent monitor ownership

`lib/transport` is smaller than before: protobuf encoding has moved to `lib/wire`. Remaining issues:

- mutable exported Noise algorithm globals in [`lib/transport/algos.go`](lib/transport/algos.go);
- logging construction concerns in transport handshake functions;
- redundant write locking;
- non-idiomatic exported protocol constants and mutex names;
- handshake failures return a partially initialized non-nil `*Transport`;
- `MaxPayloadSize` is a ciphertext/chunk bound, while `SendFrame` accepts plaintext and adds an authentication tag;
- no explicit internal terminal state prevents reuse after encryption or write failure.

Current establishment/session callers close on failures, so these are not all active exploits. The monitor relay will make `Transport` a long-lived authority, so the contract should be explicit:

```text
immutable suite
maximum plaintext
maximum ciphertext
one concurrent reader
one serialized writer
any decrypt/encrypt/write failure makes transport unusable
deadlines and close unblock both directions
```

The existing channel-binding accessor already returns a copy and is suitable input to a worker-launch binding digest.

### W11 — Monitor-side security debt remains

These issues do not have to block the first worker demonstration, but the split does not solve them.

#### Trust semantics

[`ParseAuthorizedKeys`](lib/trust/authorized_keys_ssh.go#L11) silently skips every entry with options. Therefore `restrict`, forced command, no-PTY, environment, source, and forwarding constraints never become permissions.

[`ParseKnownHosts`](lib/trust/known_hosts_ssh.go#L13):

- skips revoked entries instead of preserving an overriding denial;
- does not implement certificate-authority semantics;
- stores wildcard, negated, hashed, and host-plus-port forms as exact strings;
- performs only exact identity lookup;
- has implicit malformed-entry behavior.

The process split must not freeze the current demo permissions as the long-term policy format. Parse key-entry constraints in the monitor and include only validated normalized constraints in the worker snapshot.

#### Endpoint and identity

The dial endpoint, host verification identity, client-supplied `reference_identity`, and audit identity remain conflated. Host identity omits port and normalization. The client supplies the value later exposed as a verified host identity.

Define distinct values before they become startup/audit fields:

- network endpoint;
- normalized known-host identity;
- optional configured server name;
- trusted monitor-generated connection/audit identity.

#### Key representation

General key values remain mutable. Fingerprints hash raw key bytes without an algorithm tag. Signing APIs panic for invalid key values. Auth username and reference-identity protobuf fields have minimum lengths but no conservative maxima.

The startup validator should not inherit these loose general APIs.

#### Production policy and PAM

The production permission policy is hardcoded to allow command, shell, exec, PTY, and a small environment list for every matched key. There is no account-status or PAM check and no PAM session lifecycle.

The initial worker may use a complete snapshot. Later PAM session state or privileged leases should remain monitor-owned and use explicit worker-monitor RPC.

### W12 — Tests do not exercise the target security boundary

The new command, process, session, secure-file, and terminal tests are valuable. The required worker tests are absent because the implementation is absent.

Before calling the split complete, add real subprocess tests for:

- successful startup, readiness, auth commit, activation, and PTY shell;
- non-PTY exec and separate stderr;
- exact raw-byte preservation through network, monitor, IPC, session, and command layers;
- malformed, zero-length, oversized, truncated, repeated, and out-of-order IPC records;
- unexpected or truncated ancillary data;
- connection ID, nonce, or binding mismatch;
- unsupported startup version and unknown security flags;
- wrong UID, GID, supplementary groups, or root privilege;
- direct worker invocation without inherited resources;
- unexpected inherited descriptors and environment variables;
- worker startup timeout and crash before readiness;
- worker crash after activation;
- client disconnect during startup and active relay;
- blocked IPC send in either direction;
- monitor shutdown;
- child process and descendant cleanup;
- idempotent connection and future lease cleanup;
- a second connection surviving another worker's failure.

Also add fuzzers for auth/session/command protobuf ingress, private/public key decoding, `authorized_keys`, `known_hosts`, and the IPC control protocol.

---

## Recommended architecture for the next milestone

The existing external client protocol does not need to change.

### Monitor composition

Conceptually:

```text
server accept loop
  -> monitor connection owner
      -> Noise handshake
      -> staged auth proof
      -> account/key/policy authorization
      -> immutable startup snapshot
      -> worker supervisor
      -> auth commit
      -> bidirectional frame relay
      -> final network close + worker reap
```

The monitor should be the only component with:

- accepted network descriptors;
- Noise state;
- host private key;
- account resolver;
- key/trust-file access;
- connection authorization policy;
- worker identity selection;
- authoritative connection audit.

### Worker composition

```text
internal worker entrypoint
  -> verify inherited IPC descriptor and process identity
  -> receive and validate exactly one startup snapshot
  -> construct snapshot-only authorization enforcement
  -> construct command service and process runner
  -> prepare and bind session to IPC
  -> send READY
  -> wait for ACTIVATE
  -> run post-auth session until local or monitor termination
```

The existing packages that should largely survive in the worker are:

- `lib/session`;
- `lib/command`;
- `app/commandchannel`;
- `app/server/command`;
- `app/server/process`;
- credential-aware service routing, after its authorization input becomes reconstructible from plain data.

### IPC protocol

Use a distinct internal envelope with explicit record types, for example:

```text
STARTUP
READY
ACTIVATE
SESSION_FRAME
SHUTDOWN
WORKER_EVENT
```

Every record should have a small fixed header or protobuf envelope containing:

- IPC version;
- message type;
- connection ID;
- launch nonce where applicable.

Only `SESSION_FRAME` carries the opaque external session protobuf bytes. The monitor normally does not decode those bytes.

Use `sendmsg`/`recvmsg` semantics that allow:

- `MSG_TRUNC` and control truncation detection;
- rejection of unexpected ancillary data;
- exact one-record reads;
- hard packet maxima;
- nonblocking or deadline-bound sends.

Do not use ordinary stream framing for this boundary unless there is a compelling portability reason; the project is Unix-only and the plan's seqpacket choice is sound.

### Snapshot and authorization split

Introduce a plain startup snapshot with no interfaces or pointer capabilities. Keep monitor policy separate from worker enforcement:

```text
monitor:
  verified proof + peer + account + files + config
    -> validated ConnectionSnapshot

worker:
  decode + independent validation
    -> WorkerCredentials
    -> snapshot-only ChannelPolicy
    -> snapshot-only LaunchPolicy
```

For future privileged authorization:

```text
worker -> monitor: authorize/open request
monitor -> worker: decision + lease ID
worker -> monitor: close lease
```

The initial command service does not need that RPC if all launch decisions are pure and nonblocking.

### Establishment API change

Keep client establishment mostly as-is. Split server establishment into:

1. pre-auth secure transport and verified proof;
2. one-shot public auth decision;
3. monitor-owned accepted secure transport/relay lifecycle.

Do not make `lib/establish` import worker service implementations. It may provide lifecycle primitives, but app/server should compose worker startup and policy.

### First complete slice

The smallest convincing delivery is:

1. retain the current single accepted connection;
2. authenticate and authorize in the monitor;
3. start one demoted worker over seqpacket;
4. validate startup and send readiness;
5. commit auth success;
6. relay session frames;
7. run the current interactive PTY shell in the worker;
8. prove client disconnect, worker crash, and monitor shutdown clean up the worker and process group.

Once that path is stable, add the daemon accept loop and non-PTY/exec coverage through the worker path. The command protocol already supports those semantics, so they should not require a protocol redesign.

---

## Feature work remaining after the first worker slice

These are part of the broader credible service described by the worker plan or the existing architecture roadmap.

### Required for the full worker plan

- bounded multi-connection monitor and admission control;
- authoritative worker supervision and reaping;
- worker operational event forwarding without log-file authority;
- resource limits supplied by trusted monitor policy and capped by worker hard maxima;
- monitor-owned lease RPC when PAM session state or privileged resources require it;
- robust startup, relay, crash, and shutdown audit events;
- complete subprocess/descriptor/IPC verification.

### Required for a credible secure remote-access service

- supported `authorized_keys` options and constraints;
- explicit revoked and unsupported trust semantics;
- correct normalized `known_hosts` identities, including port handling;
- configurable account and command permission policy;
- account-status checks;
- PAM account/session integration where required;
- canonical algorithm-tagged key identity and non-panicking key APIs;
- idle, request, and connection timeout policy;
- optional rlimits, cgroups, namespaces, or sandboxing;
- deterministic CI gates, fuzzing, and vulnerability scanning.

### Later features

- forwarding with broad connection permission plus exact target/listen authorization;
- additional authentication methods or bounded identity retry;
- stronger sandboxing;
- optional auth-parser process separation.

SSH wire compatibility, reconnect/resume, and a generic plugin framework remain outside the current goal.

---

## Recommended priority order

1. **Fix the started-write cancellation defect.** The worker relay and shutdown model need a dependable bounded-write primitive.
2. **Define the versioned startup/control schema and independent validator.**
3. **Split pure snapshot enforcement from monitor-side `Authz` and remove pointer-only transferable grants.**
4. **Implement and test the seqpacket framed connection.**
5. **Add a narrow internal worker entrypoint and credential-demoted supervisor.**
6. **Refactor server establishment so the monitor retains Noise transport and can commit auth after `READY`.**
7. **Implement relay, one terminal connection owner, worker termination, and reaping.**
8. **Move the current command/PTY path behind the worker boundary and prove it end to end.**
9. **Turn the server into a bounded multi-connection monitor.**
10. **Continue trust, identity, PAM, resource-limit, and verification hardening.**

---

## Final assessment

The current revision is a much stronger codebase than the pre-refactor snapshot. The authentication, authorization, mux, command, and process layers now have credible responsibilities, and the current test suite gives reasonable confidence in those in-process components.

The remaining work is not a wholesale rewrite. It is a concentrated ownership refactor:

- preserve the monitor's Noise and authorization authority;
- serialize only bounded plain connection state;
- independently validate that state in a demoted worker;
- bind readiness to auth success;
- relay opaque post-auth frames;
- supervise and reap one disposable worker per connection.

The repository is ready to begin that work, but it should not yet be described as process-separated or as a long-lived secure remote-access daemon.
