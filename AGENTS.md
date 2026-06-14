# AGENTS.md

Guidance for agents working in this repository.

## Project Intent

`mygosh` is a from-scratch, minimal SSH-like terminal transport in Go. It is not intended to be SSH-compatible, and it must not use Go SSH libraries.

The current roadmap is moving from a provisional PTY demo toward a proper authenticated, client/server-agnostic global session. A session starts when a client connects to a server, the peers complete Noise, and both sides authenticate. Channels are opened only after authentication.

## Repository Layout

- `bin/`: binary entrypoint and Cobra command setup.
- `app/client/`: client application flow and TCP dialing.
- `app/server/`: server application flow and TCP listening.
- `lib/transport/`: Noise transport and protobuf envelope transport.
- `lib/auth/`: authentication protocol, signed payloads, and auth transcript handling.
- `lib/session/`: authenticated global session model and post-auth protocol entry points.
- `lib/bincoder/`: small binary encoding helpers for framing and key formats.
- `lib/keys/`: key generation, parsing, serialization, and signing helpers.
- `lib/tty/`: local raw terminal and server PTY mechanics.
- `lib/settings/`: config loading and validation.
- `lib/logging/`: global Charmbracelet logger setup.

## Development Rules

- Prefer small, composable layers over large all-in-one abstractions.
- Keep TCP ownership in `app/client` and `app/server`; do not hide sockets inside `NoiseStream`.
- Keep `NoiseStream` focused on encrypted packet send/receive.
- Keep message envelopes simple: one protobuf `oneof` envelope per frame.
- Keep terminal data contents raw bytes and return terminal bytes unchanged.
- Use protobuf for message serialization and protovalidate for schema validation where applicable.
- Use deterministic protobuf serialization only for blobs or payloads that are signed.
- Use `github.com/rotisserie/eris` for wrapped errors.
- Use `github.com/charmbracelet/log` for logging.
- Do not target Windows.
- Do not add SSH compatibility, ControlMaster, or reconnect/resume unless the roadmap explicitly moves to that step.
- Prefer the smallest change that improves the authenticated session and channel-open path without closing off future process separation.

## Auth And Session Direction

- `lib/session/session.go` should model the global authenticated session itself, not PTY/client/server terminal behavior.
- Authentication protocol logic and auth state transitions should live in `lib/auth`.
- Session construction chooses and validates identities, keys, and trust policy, then calls into the auth machinery.
- Auth code should run the authentication protocol with the supplied identities and keys; it should not decide local policy, selected service, or requested channel type.
- Auth messages must not include which service or channel the client wants to run.
- Every auth initiation or request must have a corresponding reply, including rejection and error paths.
- Prefer deterministic protobuf serialization for signed auth payloads. If that fully covers signed payload generation, prefer deleting `lib/bincoder/struct.go` instead of maintaining two canonicalization schemes.

## Channel Direction

- Channels are opened after authentication.
- The current terminal behavior should become one future `session` channel variant.
- `StartShell` is the PTY-backed command path.
- `StartExec` is the non-PTY command path.
- It is acceptable for the current client/server terminal plumbing to move into `app` and remain unused or commented out during the refactor, as long as the repository remains compilable.
- Do not tie channel routing to `session_id`; reserve `session_id` for opaque audit/logging if it remains in the protocol.

## Process-Separation Biases

`PROCESS_SEPARATION.md` is guidance, not the immediate priority. Keep its boundaries in mind without forcing a process split now.

- Keep one receive owner per connection; do not let unrelated goroutines compete over `Transport.Receive`.
- Avoid spreading host-key access, authorization policy, account lookup, or PTY launch policy into `transport` or `auth`.
- Prefer plain data interfaces at trust boundaries so future helper/monitor processes remain possible.

## Testing

- Run all tests with:

  ```sh
  go test ./...
  ```

- Prefer focused tests in `lib/auth`, `lib/session`, and `lib/transport` for protocol behavior before changing app-level flows.
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

- First make authenticated session construction and post-auth channel opening correct.
- Keep the current PTY path provisional until it can sit behind the channel model.
- Add batching, escape sequences like `~.`, reconnect/resume, and broader execution policy only after the session/channel layer is boring.
- When in doubt, choose the smallest change that improves the session/channel path without closing off future auth, authorization, or process-separation work.
