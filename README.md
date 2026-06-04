# mygosh

`mygosh` is a from-scratch, minimal SSH-like client/server experiment in Go.

The current transport is a tiny length-prefixed frame protocol over TCP. The CLI is one Cobra binary with Viper-backed config loaded from `mygosh.toml` in the current working directory.

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
go run ./cmd/mygosh serve
```

Send one frame:

```sh
go run ./cmd/mygosh connect localhost:42022 "hello world"
```

Start an interactive client:

```sh
go run ./cmd/mygosh connect localhost:42022
```

Or use tmux:

```sh
./run-tmux.sh
```

## Build

```sh
go build ./cmd/mygosh
```

## Test

```sh
go test ./...
```
