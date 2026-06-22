# mygosh

`mygosh` is an experimental, from-scratch SSH-like client/server written in Go. It is not compatible with the SSH wire protocol.

> **Security status:** this is a hobby project and protocol prototype, not a production-ready remote login service. Authentication, explicit authorization policy, bounded daemon admission, command execution, mux limits, process cleanup, trust-file subsets, and secure-file boundaries are implemented. PAM, process separation, resource isolation, and broader hardening remain open. [`REVIEW.md`](REVIEW.md) contains the original review evidence; [`TODO.md`](TODO.md) tracks current completion.

## What Exists Today

This section describes the current implementation as it is.

- A Cobra CLI with `server`/`serve` and `connect` commands.
- TCP dialing in `app/client` and a bounded multi-client daemon in `app/server`.
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
- An app-owned command client in `app/client/command`; `lib/command` retains transport-neutral schemas, codecs, contracts, and the server protocol engine.
- Bounded, descriptor-checked loading of OpenSSH Ed25519 private keys, `known_hosts`, and `authorized_keys`.
- Exact-host `known_hosts` verification with multiple accepted keys and key-specific revocation.
- Enforced `authorized_keys` constraints for `command=`, `no-pty`, and `restrict`.
- NSS-aware username, UID, GID, supplementary-group, home, and login-shell lookup through `lib/account`.
- Structured `slog` logging with optional console and JSON logfile output.

The server accepts multiple connections until shutdown, with configurable global and per-source-IP admission limits.

### Dependency clarification

`mygosh` does not use a Go SSH transport, authentication, or session implementation. It currently does use `golang.org/x/crypto/ssh` to parse OpenSSH `known_hosts` and `authorized_keys` files. Replacing or explicitly narrowing that parser dependency is future work.

## Current Connection Flow

The default app path currently performs:

1. TCP connect and bounded daemon admission.
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

- trust-file compatibility is deliberately narrow: certificates, hashed/wildcard/negated hosts, host-plus-port identities, and most `authorized_keys` options are rejected;
- command execution has no PAM session, cgroup, sandbox, or configurable resource-limit integration;
- authenticated post-auth runtimes still share the daemon process rather than running in disposable account workers;
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

Future functional goals include PAM account/session integration, disposable account workers, process resource isolation, and eventually port forwarding after destination-specific authorization is designed.

## Configuration

The server and client use separate configuration contracts. By default,
`server` loads `mygosh-server.toml` and `connect` loads
`mygosh-client.toml` from the process working directory. A missing file is an
error. Use the command-specific `--config` flag to select another path.

Server example:

```toml
[listen]
address = "localhost:42022"

[daemon]
max_connections = 32
max_connections_per_ip = 4
shutdown_timeout = "5s"

[identity]
host_key = "~/.mygosh/host_ed25519"

[authorization]
authorized_keys = [
  "~/.mygosh/authorized_keys",
  "~/.ssh/authorized_keys",
]

[authorization.permissions]
allow_shell = true
allow_exec = true
allow_pty = true
allowed_environment = ["TERM", "COLORTERM", "LANG", "LC_ALL", "LC_CTYPE"]
# forced_command = "/usr/local/bin/restricted-command"

[log]
level = "DEBUG"
json = false
file = "mygosh-server.log"
```

Client example:

```toml
[connection]
default_port = 42022

[identity]
private_key = "~/.mygosh/id_ed25519"

[trust]
known_hosts = "~/.mygosh/known_hosts"

[log]
level = "DEBUG"
json = false
file = "mygosh-client.log"
```

Current field behavior:

- `listen.address` is the server TCP listen endpoint.
- `daemon.max_connections` and `daemon.max_connections_per_ip` bound accepted connections from handshake through cleanup.
- `daemon.shutdown_timeout` bounds the final wait for active connection handlers after cancellation.
- `authorization.permissions` is required and deny-by-default. It controls shell, exec, PTY, environment names, and an optional forced command.
- `connection.default_port` is used when the client target omits a port.
- Identity and trust paths are owned by their respective command
  configuration.
- Unknown fields are rejected, so client-only settings cannot silently appear
  in a server file or vice versa.
- Handshake and authentication timeouts are not yet configurable.

Logging levels are `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`, `NONE`, or empty. CLI verbosity overrides the configured level:

```sh
mygosh server       # configured level
mygosh -v server    # INFO
mygosh -vv server   # DEBUG
```

When `log.file` is set, the process appends structured JSON logs to that path and sets its mode to `0600`.

Application audit records use an explicitly passed logger tagged
`stream=audit`. Library lifecycle diagnostics use the process-wide
`slog.Default()` logger installed by application composition and tagged
`stream=diagnostic`. The app owns handlers, destinations, formatting, and
logger shutdown.

## Required Key And Trust Files

The default configuration paths are:

| Role | Path | Purpose |
|---|---|---|
| Client | `~/.mygosh/id_ed25519` | Unencrypted OpenSSH Ed25519 client private key |
| Client | `~/.mygosh/known_hosts` | Expected server Ed25519 host key |
| Server | `~/.mygosh/host_ed25519` | Unencrypted OpenSSH Ed25519 host private key |
| Server account | `~/.mygosh/authorized_keys` | Allowed client Ed25519 keys |
| Server account | `~/.ssh/authorized_keys` | Additional allowed client Ed25519 keys |

The `~` for server authorization files is expanded against the requested account's resolved home directory.

Current trust-file support is a strict subset:

- `known_hosts` accepts exact plain hostnames or IP addresses and multiple Ed25519 keys per identity;
- a matching `@revoked` host/key entry always rejects that key;
- certificate authorities, hashed, wildcard, negated, and `[host]:port` identities are rejected;
- `authorized_keys` accepts bare Ed25519 keys plus `command=`, `no-pty`, and `restrict`;
- unsupported, duplicate, malformed, or contradictory authorization options reject the file;
- key constraints may only narrow configured server permissions.

Files are opened beneath app-selected anchors without following lower-path symlinks, are ownership/mode/type checked, and are bounded to 16 KiB for private keys or 8 MiB for trust files.

### Local demo key setup

The following creates separate host and client keys for a same-user local demo:

```sh
install -d -m 0700 ~/.mygosh
ssh-keygen -q -t ed25519 -N '' -f ~/.mygosh/host_ed25519
ssh-keygen -q -t ed25519 -N '' -f ~/.mygosh/id_ed25519
cp ~/.mygosh/id_ed25519.pub ~/.mygosh/authorized_keys
awk '{print "localhost " $1 " " $2}' \
  ~/.mygosh/host_ed25519.pub > ~/.mygosh/known_hosts
chmod 0600 ~/.mygosh/authorized_keys ~/.mygosh/known_hosts
```

## Run

Start the daemon:

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

The sample server configuration explicitly permits shell, exec, PTY, and `TERM`, `COLORTERM`, `LANG`, `LC_ALL`, and `LC_CTYPE`. Removing those settings narrows access; there is no hidden permissive policy.

For the current two-pane smoke test:

```sh
./run-tmux.sh
```

The helper starts the daemon, one interactive client, and a concurrent non-PTY command client in three tmux panes. After either client exits, reconnect without restarting the server to verify the daemon lifecycle.

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

When running process-lifecycle tests inside Docker, include `--init` so terminated grandchildren are reaped instead of remaining visible as container zombies.

## Repository Guide

- `app/`: current CLI application composition and networking.
- `app/client/command/`: app-owned command client state, terminal lifecycle, and remote-exit mapping.
- `app/config/`: strict command-specific client and server configuration.
- `app/logging/`: audit/diagnostic logger construction and file lifecycle.
- `app/root/`: diagnostic logger installation and shutdown hooks.
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
