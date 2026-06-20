# AGENTS.md

Guidance for agents working in this repository.

## How To Read This Document

This document deliberately distinguishes:

- **Current implementation facts**: behavior or structure verified in the code as it exists now.
- **Design intent**: the architecture and security properties future work should move toward.
- **Known gaps**: current behavior that must not be mistaken for an approved long-term design.

Do not infer that a stated design intent is already implemented. [`REVIEW.md`](REVIEW.md) preserves the review evidence that produced the roadmap and may describe pre-refactor code; [`TODO.md`](TODO.md) is the current completion checklist.

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
- `lib/wire` defines transport-neutral `Framer`/`FramedConn` contracts and performs protobuf marshaling plus protovalidate validation.
- `lib/establish.Connect` and `lib/establish.BeginAccept` compose connection runtime, Noise, auth, and binding/activation of `lib/session.Session`.
- `BeginAccept` returns a pending server establishment after client proof verification. Its context keeps the complete auth timeout active while app policy runs, and its one-shot `Accept`, `Reject`, and `Close` methods do not expose a mux before acceptance.
- Establishment-owned lifecycle management tracks pre-auth phases and transfers close ownership to `Session` only after the post-auth mux is bound.
- `lib/auth` verifies server and client signatures, runs the auth wire state machine, and returns an immutable `VerifiedClient` plus a one-shot accept/reject decision. It does not import Unix accounts or authorize client keys.
- `app/server/authz.Authz` resolves accounts, securely reads and matches `authorized_keys`, runs the account-policy seam, and returns immutable connection credentials before wire auth success.
- `lib/session.Session` is the channel/global-request multiplexer. It is prepared separately, bound to an authenticated `wire.FramedConn`, activates its own workers automatically, and still does not itself enforce authenticated credentials.
- `lib/trust` contains path-independent OpenSSH-format parsers and pure key/host matchers.
- `lib/strictfiles` provides caller-configurable checked directory/file opens. App-owned `app/securefiles` uses anchored `OpenAt` traversal and bounded reads for every private-key and trust file.
- The client securely loads `~/.mygosh/id_ed25519` and `~/.mygosh/known_hosts` before dialing.
- The server securely loads `~/.mygosh/host_ed25519` before listening, resolves the requested username through the injected `lib/user.Resolver`, and securely checks `~/.mygosh/authorized_keys` and `~/.ssh/authorized_keys` in that account's home.
- The client verifies the server signature and host-key policy before using its client signer.
- The server verifies the client signature before invoking local account/key authorization.
- After auth, the default app path activates a reject-by-default mux, logs success, and waits for cancellation or disconnect.
- Incoming channels and global requests are rejected normally when the nil handler is used.
- Terminal channel data is still carried as raw bytes and tested for byte preservation.

## Known Architectural And Security Gaps

These are current defects or incomplete boundaries. Do not preserve them merely because existing code uses them:

- Trust-file marker, option, revocation, host matching, and malformed-entry semantics are incomplete.
- Channels, pending requests, queued frames, and total connection memory are not bounded adequately.
- Channel state permits invalid ordering and incomplete cancellation cleanup.
- General key and account model values still expose mutable slices, although `VerifiedClient` and `ConnectionCredentials` clone mutable data at their boundaries and accessors return copies.
- There is no explicit connection-level permission model or concrete request authorization layer.
- Dial endpoint, host verification identity, client-supplied server name, and audit identity are conflated.
- The current app path exposes no shell, exec, PTY, or terminal service yet.

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
- `app/client/`: target parsing, secure client-key/known-host loading, TCP dialing, trust wiring, and reject-all post-auth activation.
- `app/securefiles/`: app-owned anchored traversal and bounded-read policy over `lib/strictfiles`.
- `app/server/`: secure host-key loading, TCP listener, staged establishment wiring, and reject-all post-auth activation.
- `app/server/authz/`: account resolution, `authorized_keys` path/file policy, immutable connection credentials, and account policy seam.
- `lib/transport/`: Noise handshake, channel binding, encrypted frame I/O, deadlines, and close.
- `lib/wire/`: transport-neutral framed-connection contracts and protobuf encoding/validation.
- `lib/auth/`: auth schema, state machine, signed payloads, proof result, and pending accept/reject decision.
- `lib/establish/`: client connection composition and pending server establishment lifecycle.
- `lib/session/`: prepared/bound post-auth mux, bounded callback queues, and serialized post-auth writing.
- `lib/service/`: current PTY/exec payload protocol.
- `lib/strictfiles/`: descriptor-based, caller-configurable secure-open primitives used by app file policy.
- `lib/trust/`: path-independent OpenSSH `authorized_keys`/`known_hosts` parsers and pure matchers.
- `lib/keys/`, `lib/bincoder/`: key and binary encoding helpers.
- `lib/user/`: account snapshot, resolver seam, and current `os/user` adapter; login shell may be empty.
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

The current smoke path expects the key/trust files documented in [`README.md`](README.md), one accepted connection, successful auth, and an idle authenticated connection that remains up until interrupted. Treat successful smoke behavior as demo verification, not evidence of production security.
