# AGENTS.md

Guidance for agents working in this repository.

## Project Intent

`mygosh` is a from-scratch, minimal SSH-like terminal transport in Go. It is not intended to be SSH-compatible, and it must not use Go SSH libraries. The priority is a correct interactive PTY over our own small protocol.

## Repository Layout

- `bin/`: binary entrypoint and Cobra command setup.
- `app/client/`: client application flow.
- `app/server/`: server application flow.
- `lib/wire/`: framing, Noise transport, message protocol.
- `lib/tty/`: local raw terminal and server PTY helpers.
- `lib/settings/`: config loading and validation.
- `lib/logging/`: global Charmbracelet logger setup.

## Development Rules

- Prefer small, composable layers over large all-in-one abstractions.
- Keep TCP ownership in `app/client` and `app/server`; do not hide sockets inside `NoiseStream`.
- Keep `NoiseStream` focused on encrypted packet send/receive.
- Keep message envelopes simple: one protobuf `oneof` envelope per frame.
- Keep terminal data contents raw bytes and return terminal bytes unchanged.
- Use protobuf for message serialization and protovalidate for schema validation where applicable.
- Use `github.com/rotisserie/eris` for wrapped errors.
- Use `github.com/charmbracelet/log` for logging.
- Do not target Windows.
- Do not add SSH channels, ControlMaster, reconnect, or auth unless the roadmap explicitly moves to that step.
- Do not implement `[command]` handling until the interactive shell path is stable.

## Testing

- Run all tests with:

  ```sh
  go test ./...
  ```

- Prefer focused tests in `lib/wire` for protocol behavior before changing app-level flows.
- Use `github.com/stretchr/testify/require` for new tests.
- For bidirectional protocol tests, prefer `net.Pipe` with deadlines over `bytes.Buffer`.
- Keep an explicit test that terminal data bytes are not transformed.

## Manual Smoke Test

- Use the tmux helper:

  ```sh
  ./run-tmux.sh
  ```

- Expected near-term manual behavior is one client connected to one server process.
- If terminal raw mode is involved, verify the terminal is restored after errors and normal exit.

## Current Design Biases

- First make direct PTY byte piping correct.
- Add batching only after direct piping works.
- Defer escape sequences like `~.` until the terminal loop is stable.
- Defer auth and reconnect/resume until the message layer and PTY loop are boring.
- When in doubt, choose the smallest change that improves the PTY path without closing off future auth/reconnect work.
