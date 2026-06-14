# mygosh

`mygosh` is a from-scratch, minimal SSH-like client/server experiment in Go.
It is not SSH-compatible and does not use Go SSH libraries.

The current code has a custom Noise-based transport over TCP, separate auth/session protobuf frame schemas, and a minimal authenticated session abstraction. The interactive PTY plumbing has been moved out of the core session path and is intentionally disabled while the post-auth session protocol is rebuilt on top of the new boundary.

The CLI is one Cobra binary with Viper-backed config loaded from `mygosh.toml` in the current working directory.

## Current Direction

The current repository baseline is:

- Noise handshake plus auth completes through `lib/session.Connect` / `lib/session.Accept`
- auth protocol/state transitions live in `lib/auth`
- auth traffic uses `mygosh.auth.v1.AuthFrame`
- post-auth traffic uses `mygosh.session.v1.Envelope`
- the default CLI path authenticates and exits

The next project step is to build the real post-auth session/channel-open path on top of that split. See `PLAN.md` for the near-term plan.

`PROCESS_SEPARATION.md` records longer-term guidance for process and privilege separation. It should inform boundaries, but the immediate priority is getting authentication and channel-open semantics correct.

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

Log verbosity can be overridden from the CLI:

```sh
mygosh serve      # use mygosh.toml log.level, or none if unset
mygosh -v serve   # INFO and above
mygosh -vv serve  # DEBUG and above
```

## Run

Start the server:

```sh
go run ./bin serve
```

Start a client auth smoke test:

```sh
go run ./bin connect localhost:42022
```

The current `connect`/`serve` flow authenticates and exits. The app layer still wires demo host/client keys for this smoke-test flow, but those values no longer live in `lib/auth` or `lib/session`.

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
