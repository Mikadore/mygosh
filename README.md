# mygosh

`mygosh` is a from-scratch, minimal SSH-like client/server experiment in Go.
It is not SSH-compatible and does not use Go SSH libraries.

The current code has a custom Noise-based transport over TCP, protobuf message envelopes, and an MVP authentication protocol that is being redesigned. The interactive PTY plumbing is provisional and may temporarily break during the next session/auth refactor as long as the repository remains buildable.

The CLI is one Cobra binary with Viper-backed config loaded from `mygosh.toml` in the current working directory.

## Current Direction

The next project step is to replace the MVP auth/session model with a proper authenticated, client/server-agnostic global session that can accept post-auth channel-open requests. See `PLAN.md` for the near-term plan.

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

Start an interactive client:

```sh
go run ./bin connect localhost:42022
```

Remote command execution is not implemented yet:

```sh
go run ./bin connect localhost:42022 "echo hello"
```

Or use tmux:

```sh
./run-tmux.sh
```

## Build

```sh
go build ./bin
```

## Test

```sh
go test ./...
```
