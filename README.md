# mygosh

`mygosh` is an experimental, from-scratch SSH-like client/server written in Go. It is not compatible with the SSH wire protocol.

> **Security status:** this is a hobby project and protocol prototype, not a production-ready remote login service. The authentication/authorization and secure-file boundaries are now staged, but trust-format, resource-limit, connection-lifecycle, and process-cleanup gaps remain. [`REVIEW.md`](REVIEW.md) contains the original review evidence; [`TODO.md`](TODO.md) tracks current completion.

## What Exists Today

This section describes the current implementation as it is.

- A Cobra CLI with `server`/`serve` and `connect` commands.
- TCP dialing in `app/client` and TCP listening in `app/server`.
- A Noise NN handshake and encrypted framed transport in `lib/transport`.
- Separate protobuf schemas for authentication and post-auth connection traffic.
- Ed25519 server and client proofs bound to the Noise channel and auth transcript.
- Client-side host-key verification before the client signs its authentication proof.
- Server-side client-signature verification before local key/account authorization.
- A staged server decision: verified proof, app-owned connection authorization, then generic accept/reject.
- Immutable connection credentials and an app-owned account policy seam in `app/server/authz`.
- A prepared/bound/activated post-auth channel/global-request multiplexer in `lib/session`.
- Bounded post-auth receive, dispatch, per-channel callback, and write queues.
- A reject-by-default post-auth connection that stays active until cancellation or disconnect.
- Bounded, descriptor-checked loading of OpenSSH Ed25519 private keys, `known_hosts`, and `authorized_keys`.
- Username/group lookup through Go's current `os/user` adapter.
- Structured `slog` logging with optional console and JSON logfile output.

The current server accepts exactly one connection, runs that connection, and exits.

### Dependency clarification

`mygosh` does not use a Go SSH transport, authentication, or session implementation. It currently does use `golang.org/x/crypto/ssh` to parse OpenSSH `known_hosts` and `authorized_keys` files. Replacing or explicitly narrowing that parser dependency is future work.

## Current Connection Flow

The default app path currently performs:

1. TCP connect/accept.
2. Noise NN handshake.
3. Server signature proof.
4. Client verification of the presented server key against `known_hosts`.
5. Client public-key signature proof for the requested username.
6. `lib/auth` returns an immutable verified client proof and pauses before its final response.
7. `app/server/authz` resolves the account, securely checks `authorized_keys`, runs account policy, and constructs immutable credentials.
8. The server binds a prepared post-auth mux before auth success, then sends generic accept/reject.
9. Successful auth activates a reject-by-default mux on both peers.
10. Client and server log success and remain connected until cancellation or disconnect.

The mux type can still be constructed directly without credentials, but the default application path now attaches only a nil handler that rejects all post-auth operations.

## Known Limitations

The most important current limitations are:

- trust-file options, markers, revocation, wildcard/hashed-host, and malformed-entry semantics remain incomplete;
- connection-level permissions and concrete request authorization are not yet modeled;
- channel/request/queue resources are not comprehensively bounded;
- channel state and cancellation cleanup are incomplete;
- the current app path exposes no shell, exec, PTY, or terminal service yet;
- there is no PAM integration, port forwarding, reconnect/resume, or SSH compatibility.

This list is intentionally abbreviated. See [`REVIEW.md`](REVIEW.md#findings) for evidence and design recommendations.

## Intended Direction

This section is aspirational and should not be read as implemented behavior.

The target design is:

- transport owns only Noise-backed encrypted framing;
- auth owns cryptographic proofs and a staged accept/reject exchange;
- server app policy resolves NSS accounts, trust sources, and broad permissions before auth success;
- successful auth produces one immutable per-connection credential snapshot;
- the post-auth connection mux is exposed only after that snapshot is complete;
- services receive those credentials and authorize each concrete command, PTY, subsystem, or forwarding request before allocating resources;
- filesystem path selection remains app-owned while reusable secure-open, parser, and matcher primitives remain policy-neutral;
- one bounded reader/dispatcher and one bounded writer own connection I/O;
- a process runtime owns the complete process group and always reaps it.

Future functional goals include:

- distinct interactive shell and non-PTY exec requests;
- NSS login-shell/config policy;
- PAM account/auth and session seams;
- a bounded multi-client daemon;
- port forwarding after the channel and permission layers are hardened.

## Configuration

`mygosh.toml` is currently required in the process working directory. Defaults apply to missing fields inside the file; a missing file is an error.

Example:

```toml
[core]
host = "localhost"
port = 42022

[log]
level = "DEBUG"
json = false
file = "mygosh.log"
```

Current field behavior:

- `core.host` and `core.port` form the server listen address.
- The client uses `core.port` when its target omits a port.
- Handshake/auth timeouts and trust-file paths are not configurable through this file.

Logging levels are `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`, `NONE`, or empty. CLI verbosity overrides the configured level:

```sh
mygosh server       # configured level
mygosh -v server    # INFO
mygosh -vv server   # DEBUG
```

When `log.file` is set, the process appends structured JSON logs to that path and sets its mode to `0600`.

## Required Key And Trust Files

The current hardcoded defaults are:

| Role | Path | Purpose |
|---|---|---|
| Client | `~/.mygosh/id_ed25519` | Unencrypted OpenSSH Ed25519 client private key |
| Client | `~/.mygosh/known_hosts` | Expected server Ed25519 host key |
| Server | `~/.mygosh/host_ed25519` | Unencrypted OpenSSH Ed25519 host private key |
| Server account | `~/.mygosh/authorized_keys` | Allowed client Ed25519 keys |
| Server account | `~/.ssh/authorized_keys` | Additional allowed client Ed25519 keys |

The `~` for server authorization files is expanded against the requested account's resolved home directory.

Current trust-file support is a strict and incomplete subset. In particular, `authorized_keys` options are skipped, host matching is exact, and marker/revocation behavior is not complete. Files are opened beneath app-selected anchors without following lower-path symlinks, are ownership/mode/type checked, and are bounded to 16 KiB for private keys or 1 MiB for trust files.

## Run

Start the one-connection server:

```sh
go run ./bin server
```

`serve` is an alias:

```sh
go run ./bin serve
```

Connect with the current username from `$USER`:

```sh
go run ./bin connect localhost:42022
```

Select a requested server-side username:

```sh
go run ./bin connect alice@localhost:42022
```

The server resolves the requested username, checks the account's configured authorization files, activates the authenticated reject-all mux, and then waits for cancellation or disconnect.

For the current two-pane smoke test:

```sh
./run-tmux.sh
```

The helper starts the one-connection server and one client in adjacent tmux panes.

## Build And Test

Build directly:

```sh
mkdir -p ./build
go build -o ./build/mygosh ./bin
```

Generate protobuf code and build through Task:

```sh
task build
```

Run the current verification suite:

```sh
go test ./...
go test -race ./...
go vet ./...
```

## Repository Guide

- `app/`: current CLI application composition and networking.
- `app/securefiles/`: app-owned anchored traversal and bounded credential/trust reads.
- `app/server/authz/`: account/key authorization, immutable credentials, and account policy seams.
- `lib/transport/`: Noise handshake, channel binding, and encrypted frame transport.
- `lib/wire/`: transport-neutral framed connections and protobuf encoding/validation.
- `lib/auth/`: cryptographic auth protocol and staged accept/reject decision.
- `lib/establish/`: client composition and pending server establishment lifecycle.
- `lib/session/`: prepared/bound post-auth mux and bounded callback/write workers.
- `lib/trust/`: path-independent OpenSSH-format parsers and pure matchers.
- `lib/strictfiles/`: caller-configurable secure-open primitives used by app file policy.
- `lib/service/`: current PTY/exec payload protocol.
- `proto/`: protobuf source schemas.

Package placement describes the current tree, not the intended final boundaries. See [`AGENTS.md`](AGENTS.md) for contributor guidance.

## Project Documents

- [`REVIEW.md`](REVIEW.md): comprehensive review of the current implementation and proposed architecture.
- [`TODO.md`](TODO.md): prioritized unchecked architecture/protocol checklist.
- [`AGENTS.md`](AGENTS.md): factual current-state notes plus explicit design intent for contributors.
- [`PLAN.md`](PLAN.md): older planning context; where it conflicts with the review or current code, prefer `REVIEW.md`, `TODO.md`, and `AGENTS.md`.
