# mygosh

`mygosh` is an experimental, from-scratch SSH-like client/server written in Go. It is not compatible with the SSH wire protocol.

> **Security status:** this is a hobby project and protocol prototype, not a production-ready remote login service. Authentication, authorization, command execution, connection lifecycle, mux limits, process cleanup, and secure-file boundaries are staged, but trust-format, daemon, PAM, and broader hardening gaps remain. [`REVIEW.md`](REVIEW.md) contains the original review evidence; [`TODO.md`](TODO.md) tracks current completion.

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
- Immutable connection credentials, deny-by-default permissions, and app-owned account/permission policy seams in `app/server/authz`.
- Channel-admission and launch-authorization boundaries plus a credential-aware command service.
- A prepared/bound/activated post-auth channel/global-request multiplexer in `lib/session`.
- Explicit channel states, duplicate-ID/order validation, cancellation cleanup, bounded close, and mandatory connection/per-channel resource limits.
- A directional protobuf command protocol carried only through `"command"` channel data.
- Interactive shell and shell `-c` exec modes, each with optional PTY allocation.
- Separate stdout/stderr for non-PTY commands, merged PTY output, terminal resize, stdin half-close, environment filtering, and remote exit propagation.
- A Unix process owner with explicit credentials, process-group cleanup, bounded TERM/KILL shutdown, and exactly-once reaping.
- Poll-based cancellable client input and restoration of local raw terminal state.
- Bounded, descriptor-checked loading of OpenSSH Ed25519 private keys, `known_hosts`, and `authorized_keys`.
- NSS-aware username, UID, GID, supplementary-group, home, and login-shell lookup through `lib/account`.
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
9. Successful auth activates the mux and the client opens a `"command"` channel.
10. The client sends one shell or exec start frame; the server authorizes the exact launch before creating a process.
11. Command stdin, output, resize, and exit frames travel only as channel data.
12. Process exit or cancellation drives bounded local cleanup and channel closure.

## Known Limitations

The most important current limitations are:

- trust-file options, markers, revocation, wildcard/hashed-host, and malformed-entry semantics remain incomplete;
- the server still accepts only one connection and uses a hardcoded demo command permission policy;
- command execution has no PAM session, cgroup, sandbox, or configurable resource-limit integration;
- there is no port forwarding, reconnect/resume, or SSH compatibility.

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

- configurable command and environment policy;
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

Run a non-PTY command through the account shell:

```sh
go run ./bin connect localhost:42022 printf hello
```

Force or disable PTY allocation:

```sh
go run ./bin connect -t localhost:42022 top
go run ./bin connect -T localhost:42022
```

Request allowlisted environment forwarding:

```sh
go run ./bin connect --env LANG --env COLORTERM=true localhost:42022
```

The current demo server permits command channels, shell, exec, PTY, and `TERM`, `COLORTERM`, `LANG`, `LC_ALL`, and `LC_CTYPE`. Authorization remains deny-by-default outside that explicit composition policy.

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
- `app/commandchannel/`: the only adapter between session channels and command framing.
- `app/securefiles/`: app-owned anchored traversal and bounded credential/trust reads.
- `app/server/authz/`: account/key authorization, immutable credentials and permissions, and channel/launch authorization.
- `app/server/command/`: command service and authorized-launch adapter.
- `app/server/process/`: Unix process, PTY/pipe, process-group, and reaping owner.
- `app/server/services/`: credential-aware channel service registry.
- `lib/account/`: NSS-aware account and group resolution.
- `lib/transport/`: Noise handshake, channel binding, and encrypted frame transport.
- `lib/wire/`: transport-neutral framed connections and protobuf encoding/validation.
- `lib/auth/`: cryptographic auth protocol and staged accept/reject decision.
- `lib/establish/`: client composition and pending server establishment lifecycle.
- `lib/session/`: prepared/bound post-auth mux, explicit channel states, resource limits, and bounded callback/write workers.
- `lib/command/`: pure command framing, client/server state machines, chunking, and typed results.
- `lib/trust/`: path-independent OpenSSH-format parsers and pure matchers.
- `lib/strictfiles/`: caller-configurable secure-open primitives used by app file policy.
- `proto/`: authentication, session mux, and command protobuf schemas.

Package placement describes the current tree, not the intended final boundaries. See [`AGENTS.md`](AGENTS.md) for contributor guidance.

## Project Documents

- [`REVIEW.md`](REVIEW.md): comprehensive review of the current implementation and proposed architecture.
- [`TODO.md`](TODO.md): prioritized unchecked architecture/protocol checklist.
- [`AGENTS.md`](AGENTS.md): factual current-state notes plus explicit design intent for contributors.
- [`REFACTOR_REPORT.md`](REFACTOR_REPORT.md): command-service milestone changes, rationale, verification, and remaining gaps.
- [`PLAN.md`](PLAN.md): older planning context; where it conflicts with the review or current code, prefer `REVIEW.md`, `TODO.md`, and `AGENTS.md`.
