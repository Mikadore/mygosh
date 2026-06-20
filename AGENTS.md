# AGENTS.md

Guidance for agents working in this repository.

## How To Read This Document

This document deliberately distinguishes:

- **Current implementation facts**: behavior or structure verified in the code as it exists now.
- **Design intent**: the architecture and security properties future work should move toward.
- **Known gaps**: current behavior that must not be mistaken for an approved long-term design.

Do not infer that a stated design intent is already implemented. For a detailed review of the current code, see [`REVIEW.md`](REVIEW.md). For the actionable issue list, see [`TODO.md`](TODO.md).

## Project Intent

**Design intent:** `mygosh` is a from-scratch, minimal SSH-like client/server in Go. It is not intended to implement the SSH wire protocol. The goal is a small but credible secure remote-access service supporting public-key authentication, Unix account resolution, interactive shells, command execution, and later port forwarding.

**Current implementation fact:** the repository does not use an SSH transport or SSH session implementation. It does currently import `golang.org/x/crypto/ssh` for OpenSSH `authorized_keys` and `known_hosts` parsing.

**Design intent:** either replace those parser dependencies with small purpose-built parsers or explicitly retain them as narrowly scoped file-format compatibility helpers. Do not introduce an SSH transport/session library.

## Current Implementation Facts

The following describes the code as it exists now, not the target architecture:

- One Cobra binary provides `server`/`serve` and `connect`.
- `mygosh.toml` is required in the current working directory.
- `app/client` owns TCP dialing; `app/server` owns TCP listening and accepting.
- The server accepts exactly one connection and exits after that connection finishes.
- `lib/transport.Transport` performs a Noise NN handshake and encrypted length-prefixed frame I/O over a `net.Conn`.
- Auth traffic uses the protobuf `auth.AuthFrame`; post-auth traffic uses `session.Envelope`.
- `transport.SendProto` and `transport.ReceiveProto` perform protobuf marshaling and protovalidate validation inside the `lib/transport` package.
- `lib/establish.Connect` and `lib/establish.Accept` compose connection runtime, Noise, auth, and construction of `lib/session.Session`.
- `lib/session.Runtime` currently owns cancellation, target handoff, and handshake/auth timeout enforcement even though those phases precede the post-auth mux.
- `lib/auth` verifies server and client signatures and runs the auth wire state machine.
- `lib/auth` also defines and invokes client-key authorization and imports the Unix account model. Authentication and authorization are therefore not cleanly separated yet.
- `lib/session.Session` is the channel/global-request multiplexer. It does not contain authenticated credentials and can be constructed directly over any `transport.FramedConn`; “authenticated session” is a property of the normal app path, not one enforced by the type.
- `Session.Run` is the sole post-auth frame receiver in the normal path, but it invokes handlers and performs some writes synchronously.
- `lib/trust` currently combines path expansion, ordinary file reads, OpenSSH-format parsing, host verification, key authorization, `os/user`-backed account lookup, and policy logging.
- `lib/strictfiles` contains descriptor-based secure-open primitives, but current private-key, `known_hosts`, and `authorized_keys` reads do not use them.
- The client loads `~/.mygosh/id_ed25519` and checks `~/.mygosh/known_hosts`.
- The server loads `~/.mygosh/host_ed25519`, resolves the requested username through `os/user`, and checks `~/.mygosh/authorized_keys` and `~/.ssh/authorized_keys` in that account's home.
- The client verifies the server signature and host-key policy before using its client signer.
- The server verifies the client signature before invoking local account/key authorization.
- After auth, the default app path opens one `session` channel, requests a PTY, then requests execution of a command.
- The server executes its configured shell as `shell -c <client command>` under the account returned by authorization.
- The client uses its configured `core.shell` string as the default remote command when no command is supplied. This is not a distinct interactive-shell protocol request.
- Terminal channel data is carried as raw bytes and tested for byte preservation.

## Known Architectural And Security Gaps

These are current defects or incomplete boundaries. Do not preserve them merely because existing code uses them:

- `lib/auth` couples cryptographic proof, client-key authorization, and Unix account data.
- Auth success can be sent before a complete service-ready credential result has been centrally validated.
- Sensitive trust/key files use unchecked, unbounded `os.ReadFile` paths.
- Trust-file marker, option, revocation, host matching, and malformed-entry semantics are incomplete.
- Detailed NSS, path, and authorization errors can be returned to unauthenticated peers.
- Session callbacks and protocol-error writes can block the sole receive loop.
- Channels, pending requests, queued frames, and total connection memory are not bounded adequately.
- Channel state permits invalid ordering and incomplete cancellation cleanup.
- Connection close ownership is duplicated across app code, transport, runtime, and session.
- PTY process startup and cleanup have paths that can leak or wait indefinitely.
- Process cancellation does not deliberately own the full child process group.
- Key/account/auth result values expose mutable slices.
- There is no explicit connection-level permission model or concrete request authorization layer.
- Dial endpoint, host verification identity, client-supplied server name, and audit identity are conflated.
- The current command protocol is PTY-only and does not distinguish shell from non-PTY exec.
- The client terminal input goroutine is not reliably interruptible.

See [`REVIEW.md`](REVIEW.md#findings) for evidence and [`TODO.md`](TODO.md) for the checklist.

## Target Architecture

The following is design intent and should guide new work.

### Dependency Direction

Application code should compose protocol, security, policy, and Unix-platform components:

```text
app/client and app/server
    -> protocol transport/auth/connection/service packages
    -> security key/secure-file/parser/matcher packages
    -> Unix account/PTY/process adapters
```

Protocol packages must not import:

- Unix account models;
- trust-file paths or filesystem policy;
- NSS or PAM;
- service implementations;
- process-launch policy.

Prefer Go `internal/` packages while public API stability is not a project goal. A directory named `lib` does not itself enforce a library boundary.

### Connection Phases

The intended server sequence is:

1. app accepts and owns a TCP connection;
2. transport establishes the secure framed channel;
3. auth verifies the server/client cryptographic proofs;
4. server app policy resolves the account, trust sources, and connection permissions;
5. auth sends accept only after a complete immutable credential result exists;
6. the post-auth connection mux is constructed and becomes the receive owner;
7. each concrete service request is authorized before resource allocation;
8. an authorized launch/forward specification is handed to the service runtime.

Ownership should transfer clearly at each successful phase. Only the current/final owner closes the connection.

### Authentication And Credentials

`auth` should prove identities and manage the auth wire exchange. It should expose a staged server flow conceptually equivalent to:

```text
verified client proof -> app policy -> accept/reject
```

The server app should construct one immutable per-connection credential snapshot containing:

- authentication method and key fingerprint;
- requested and resolved username;
- UID, GID, supplementary groups, home, and login shell;
- matched policy source;
- connection-level permissions and constraints.

Services receive the same snapshot for the connection lifetime. Do not expose mutable key or group slices.

All authentication, account resolution, and broad connection permission decisions must complete before auth success. Decisions requiring request-specific data—such as an exact command or forwarding target—must happen after decoding that request but before starting a process or opening a socket.

### Trust And Files

The app decides:

- which files/stores to consult;
- path templates and precedence;
- missing-file behavior;
- strict-mode policy;
- host identity normalization and TOFU/update policy.

Reusable packages should separately provide:

- race-resistant descriptor-based opening and metadata checks;
- bounded parsing from an `io.Reader` or already bounded bytes;
- pure key/host matching;
- parsed constraints such as forced command, PTY, environment, and forwarding restrictions.

Parsers must not select paths. The auth protocol must not parse trust files or resolve accounts.

### Transport And Wire Code

`transport` should own only:

- Noise handshake and immutable suite configuration;
- channel binding/exporter material;
- encrypted frame send/receive;
- frame size enforcement;
- deadlines and close.

Protobuf codecs and schema validation should live above transport, either in a wire helper or the protocol package that owns each schema.

Treat encryption or write failure as fatal because Noise cipher state may already have advanced. Distinguish maximum plaintext from maximum ciphertext/frame size.

### Post-Auth Connection And Channels

The global post-auth object should eventually be named `connection` or `mux`; reserve “session” for the shell/exec channel concept.

Maintain:

- exactly one frame decoder/dispatcher;
- one bounded serialized writer;
- bounded per-channel workers or event queues;
- explicit channel state transitions;
- unique active peer channel IDs;
- limits on channels, pending operations, queued bytes, frame counts, and control payloads;
- cancellation that removes pending state;
- bounded best-effort disconnect and close behavior.

Do not let a handler wait for a reply that only the same blocked receive loop can process.

### Services And Authorization

The session/exec service should support:

- optional PTY setup;
- exactly one `shell` or `exec` start request;
- non-PTY execution;
- separate stdout/stderr for non-PTY exec;
- filtered environment requests;
- terminal resize only after PTY acceptance;
- exit status and exit signal;
- account/config-selected shell for shell requests.

Before starting work, turn peer input plus immutable credentials into an authorized launch specification. Process code should consume that specification rather than redo authentication or policy.

Future forwarding should follow the same pattern: broad permission in connection credentials, then exact destination/listen authorization before opening sockets.

### Unix Accounts, PAM, And Processes

Use a deliberate NSS-aware account adapter to snapshot account and group data. `os/user` is the current stub; a real login service also needs the login shell and account-status policy.

Leave a policy seam for future PAM checks before auth success. PAM session lifecycle, environment, credential switching, and process launch belong in the privileged account/process layer rather than the auth wire package.

A process owner must:

- own the command, PTY/pipes, process group, wait result, and descriptors;
- reap each child exactly once;
- terminate the whole process group on channel/connection/server cancellation;
- use bounded graceful then forced termination;
- complete locally without waiting indefinitely for peer acknowledgment.

## Current Repository Layout

This section is factual; package placement is expected to change during boundary cleanup.

- `bin/`: binary entrypoint and Cobra command setup.
- `app/root/`: settings/logging construction and shutdown hooks.
- `app/client/`: target parsing, TCP dialing, trust wiring, and terminal demo.
- `app/server/`: TCP listener, trust/account wiring, and PTY command demo.
- `lib/transport/`: Noise transport plus currently misplaced protobuf helpers.
- `lib/auth/`: auth schema, state machine, signed payloads, hooks, and currently coupled authorization result.
- `lib/establish/`: client/server composition of runtime, Noise, auth, and mux construction.
- `lib/session/`: post-auth mux plus currently misplaced connection runtime.
- `lib/service/`: current PTY/exec payload protocol.
- `lib/strictfiles/`: secure-open primitives not yet integrated into trust paths.
- `lib/trust/`: current combined trust parsing, file access, verification, authorization, and account lookup.
- `lib/keys/`, `lib/bincoder/`: key and binary encoding helpers.
- `lib/user/`: current `os/user`-backed account snapshot.
- `lib/tty/`: local raw TTY and server PTY mechanics.
- `lib/settings/`, `lib/logging/`: application configuration and logging infrastructure currently under `lib`.
- `proto/`: auth, session, and command service protobuf schemas.

## Development Rules

- Prefer small composable components and explicit ownership.
- Keep TCP dial/listen/admission policy in app code.
- Preserve separate auth and post-auth wire schemas.
- Do not put service/channel intent into auth messages.
- Keep terminal payload bytes unchanged.
- Use protobuf and protovalidate where applicable.
- Use deterministic protobuf serialization only for signed/transcript material.
- Use `github.com/rotisserie/eris` for wrapped errors unless a refactor deliberately standardizes error handling.
- Use `log/slog`; keep console presentation details out of protocol/security packages.
- Pass explicit loggers from app composition; do not mutate a global default logger.
- Keep private keys, authorization paths, account lookup, PAM, and process policy out of transport.
- Do not target Windows.
- Do not add SSH wire compatibility, reconnect/resume, ControlMaster-like behavior, or broad algorithm negotiation while the foundation remains unstable.
- Consider future process separation when defining trust and launch boundaries, but do not force a process split before the plain-data interfaces are stable.
- Avoid broad compatibility shims for obsolete internal APIs during architectural cleanup; update callers and tests together.

## Testing And Verification

Run the full suite:

```sh
go test ./...
go test -race ./...
go vet ./...
```

For protocol tests:

- use `net.Pipe` with deadlines for bidirectional behavior;
- ensure the peer reads when the test expects a write to complete;
- test malformed messages, invalid ordering, duplicate IDs, cancellation, blocking peers, and limit exhaustion;
- keep an explicit raw-terminal-byte preservation test.

For trust/security tests:

- cover owner/mode/symlink/path-race and size policies;
- fuzz key, `authorized_keys`, `known_hosts`, and protobuf parsers;
- test unsupported and revoked semantics explicitly;
- verify peer-visible errors remain generic.

For process/TTY tests:

- cover PTY and non-PTY execution;
- terminal restoration and input cancellation;
- resize behavior;
- exit status/signals;
- descendant termination and child reaping;
- disconnect and shutdown cleanup.

Manual smoke testing currently uses:

```sh
./run-tmux.sh
```

The current smoke path expects the key/trust files documented in [`README.md`](README.md), one accepted connection, successful auth, and one PTY-backed command. Treat successful smoke behavior as demo verification, not evidence of production security.
