# mygosh

`mygosh` is a from-scratch, minimal SSH-like client/server experiment in Go.
It is not SSH-compatible and does not use Go SSH libraries.

The current code has a concrete Noise-backed framed `transport.Transport` over TCP, separate auth/session protobuf frame schemas, a minimal authenticated session abstraction, and small file-backed trust stubs in `lib/trust`. The session layer now owns connection shutdown plus handshake/auth timeout enforcement during construction. The interactive PTY plumbing has been moved out of the core session path and is intentionally disabled while the post-auth session model is rebuilt on top of the new boundary.

The CLI is one Cobra binary with Viper-backed config loaded from `mygosh.toml` in the current working directory. Startup now builds a small application root in `app/root` that owns settings, the current Charm logger, and future app-scoped shutdown-managed services.

## Current Direction

The current repository baseline is:

- Noise handshake plus auth completes through `lib/session.Connect` / `lib/session.Accept`
- the concrete secure connection type is `lib/transport.Transport`
- protobuf framing above transport goes through `transport.SendProto` / `transport.ReceiveProto`
- auth protocol/state transitions live in `lib/auth`
- file-backed trust stubs live in `lib/trust`
- app-scoped wiring for settings and logging lives in `app/root`
- auth traffic uses `mygosh.auth.v1.AuthFrame`
- post-auth traffic uses `mygosh.session.v1.Envelope`
- session construction enforces built-in handshake/auth timeouts through an internal session runtime
- the default client loads its identity from `~/.mygosh/id_ed25519`
- the default server loads its host key from `~/.mygosh/host_ed25519`
- the default client verifies server host keys against `~/.mygosh/known_hosts`
- the default server authorizes client keys from `~/.mygosh/authorized_keys` and `~/.ssh/authorized_keys`
- the default CLI path authenticates and exits

The next project step is to build both a real post-auth session/channel abstraction and a clearer auth/authorization/permissions flow on top of that split. See `PLAN.md` for the near-term plan.

`PROCESS_SEPARATION.md` records longer-term guidance for process and privilege separation. It should inform boundaries, but the immediate priority is getting authentication and channel-open semantics correct.

## Current Auth And Trust Flow

The current default CLI path is intentionally small:

- the client loads an OpenSSH ed25519 private key from `~/.mygosh/id_ed25519`
- the server loads an OpenSSH ed25519 host key from `~/.mygosh/host_ed25519`
- the client verifies the presented server key against `~/.mygosh/known_hosts`
- the server authorizes the client's public key for the requested local username from `~/.mygosh/authorized_keys` and `~/.ssh/authorized_keys`

These are stubs, not a complete policy system:

- there is no TOFU or automatic host-key update behavior
- trust paths are hardcoded today
- auth succeeds and the CLI exits; post-auth channels are not implemented yet

## Config

```toml
[core]
port = 42022
shell = "/bin/bash"

[log]
level = "DEBUG"
json = false
```

`core.shell` is currently only used by the provisional demo PTY code under `app/`; it is not exercised by the default auth-only CLI path.

Handshake/auth timeout policy is currently internal to `lib/session` and is not exposed through `mygosh.toml`.

The trust file paths above are also currently hardcoded and are not configurable through `mygosh.toml`.

Log verbosity can be overridden from the CLI:

```sh
mygosh serve      # use mygosh.toml log.level, or none if unset
mygosh -v serve   # INFO and above
mygosh -vv serve  # DEBUG and above
```

The current logger is constructed explicitly by the application root and passed through the active client/server/session/auth/trust path. That is intentional groundwork for later raw-TTY log redirection and telemetry/export wiring.

## Run

Start the server:

```sh
go run ./bin serve
```

Start a client auth smoke test:

```sh
go run ./bin connect localhost:42022
```

Before that smoke test, the current default flow expects:

- `~/.mygosh/host_ed25519` for the server host private key
- `~/.mygosh/id_ed25519` for the client identity private key
- `~/.mygosh/known_hosts` with a matching entry for the server reference identity
- `~/.mygosh/authorized_keys` or `~/.ssh/authorized_keys` on the server side with the allowed client public key for the requested local username

The current `connect`/`serve` flow authenticates and exits.

Post-auth session/channel behavior is not implemented yet.

Remote command execution is also not implemented:

```sh
go run ./bin connect localhost:42022 "echo hello"
```

Or use tmux:

```sh
./run-tmux.sh
```

That helper currently exercises the same auth-only flow rather than an interactive terminal session.

## Build

```sh
go build ./bin
```

## Test

```sh
go test ./...
```
