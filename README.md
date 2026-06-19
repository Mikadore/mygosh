# mygosh

`mygosh` is a from-scratch, minimal SSH-like client/server experiment in Go.
It is not SSH-compatible and does not use Go SSH libraries.

The current code has a concrete Noise-backed framed `transport.Transport` over TCP, separate auth/session protobuf frame schemas, a role-agnostic authenticated session type with an initial post-auth channel/global-request multiplexer, and small file-backed trust stubs in `lib/trust`. The role-specific establishment layer composes handshake, authentication, timeout enforcement, and session construction around that session boundary. The interactive PTY plumbing has been moved out of the core session path and is intentionally disabled while the app-level flow is rebuilt on top of the newer session boundary.

The CLI is one Cobra binary with Viper-backed config loaded from `mygosh.toml` in the current working directory. Startup builds a small application root in `app/root` that owns settings, the application `slog` logger, and future app-scoped shutdown-managed services. Charm is used only as the logger's console presentation handler.

## Current Direction

The current repository baseline is:

- Noise handshake plus auth completes through `lib/establish.Connect` / `lib/establish.Accept`
- the concrete secure connection type is `lib/transport.Transport`
- protobuf framing above transport goes through `transport.SendProto` / `transport.ReceiveProto`
- auth protocol/state transitions live in `lib/auth`
- role-specific handshake/auth/session composition lives in `lib/establish`
- file-backed trust stubs live in `lib/trust`
- app-scoped wiring for settings and logging lives in `app/root`
- auth traffic uses `auth.AuthFrame`
- post-auth traffic uses `session.Envelope`
- `lib/session` contains an initial session/channel multiplexer with channel open, data, request, window-adjust, and disconnect handling
- `lib/session` stays role agnostic and implements the mygosh session protocol boundary
- the establishment path enforces built-in handshake/auth timeouts through `lib/session.Runtime`
- the default client loads its identity from `~/.mygosh/id_ed25519`
- the default server loads its host key from `~/.mygosh/host_ed25519`
- the default client verifies server host keys against `~/.mygosh/known_hosts`
- the default server authorizes client keys from `~/.mygosh/authorized_keys` and `~/.ssh/authorized_keys`
- the default CLI path authenticates, logs success, and exits without entering the post-auth session run loop

The next project step is to build both a real post-auth session/channel abstraction and a clearer auth/authorization/permissions flow on top of that split. See `PLAN.md` for the near-term plan.

Process separation and privilege-separation concerns should still inform boundaries, but there is no `PROCESS_SEPARATION.md` in this checkout and the immediate priority remains getting authentication and channel-open semantics correct.

## Current Auth And Trust Flow

The current default CLI path is intentionally small:

- the client loads an OpenSSH ed25519 private key from `~/.mygosh/id_ed25519`
- the server loads an OpenSSH ed25519 host key from `~/.mygosh/host_ed25519`
- the client verifies the presented server key against `~/.mygosh/known_hosts`
- the server authorizes the client's public key for the requested local username from `~/.mygosh/authorized_keys` and `~/.ssh/authorized_keys`

These are stubs, not a complete policy system:

- there is no TOFU or automatic host-key update behavior
- trust paths are hardcoded today
- auth succeeds and the CLI exits; post-auth channels exist in `lib/session` but are not wired into the default app flow yet

## Config

```toml
[core]
host = "localhost"
port = 42022
shell = "/bin/bash"

[log]
level = "DEBUG"
json = false
file = "mygosh.log"
```

`mygosh.toml` is currently expected to exist in the working directory; config defaults apply to missing fields inside that file, not to a missing file.

`core.shell` is currently only used by the provisional demo PTY code under `app/`; it is not exercised by the default auth-only CLI path.

Handshake/auth timeout policy is currently internal to the `lib/establish` path and shared `lib/session.Runtime`, and is not exposed through `mygosh.toml`.

The trust file paths above are also currently hardcoded and are not configurable through `mygosh.toml`.

Log verbosity can be overridden from the CLI:

```sh
mygosh serve      # use mygosh.toml log.level, or none if unset
mygosh -v serve   # INFO and above
mygosh -vv serve  # DEBUG and above
```

When `log.file` is set, logs are appended to that path as structured JSON with file permissions `0600`. The path is relative to the process working directory unless configured as an absolute path. Console logs continue to use Charm's text or JSON presentation according to `log.json`.

The application root owns the logging service and passes its `*slog.Logger` through the active client/server/session/auth/trust path. Console output can be enabled or disabled through the service without interrupting file logging, allowing a future interactive client to suppress console logs while its TTY is raw.

## Run

Start the server:

```sh
go run ./bin server
```

`serve` is accepted as an alias for `server`.

Start a client auth smoke test:

```sh
go run ./bin connect localhost:42022
```

Before that smoke test, the current default flow expects:

- `~/.mygosh/host_ed25519` for the server host private key
- `~/.mygosh/id_ed25519` for the client identity private key
- `~/.mygosh/known_hosts` with a matching entry for the server reference identity
- `~/.mygosh/authorized_keys` or `~/.ssh/authorized_keys` on the server side with the allowed client public key for the requested local username

The current `connect`/`server` flow authenticates and exits.

Post-auth session/channel behavior exists in the library layer but is not wired into the default CLI path yet.

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
