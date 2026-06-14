# AGENTS.md

Guidance for agents working in this repository.

## Project Intent

`mygosh` is a from-scratch, minimal SSH-like terminal transport in Go. It is not intended to be SSH-compatible, and it must not use Go SSH libraries.

The current roadmap is moving from a provisional PTY demo toward a proper authenticated, client/server-agnostic global session. A session starts when a client connects to a server, the peers complete Noise, and both sides authenticate. Channels are opened only after authentication.

Today the repository has completed the auth/session split:

- auth uses its own protobuf `AuthFrame` schema in `lib/auth/authpb`
- session traffic uses its own protobuf `Envelope` schema in `lib/session/sessionpb`
- `lib/transport.Transport` is the concrete Noise-backed framed secure connection
- protobuf marshaling sits above transport in `transport.SendProto` / `transport.ReceiveProto`
- `lib/session` currently stops at authenticated session construction plus a minimal post-auth receive-loop stub
- `lib/session` owns an internal connection runtime for parent-context shutdown plus handshake/auth timeouts
- the default CLI flow authenticates and exits; interactive terminal behavior is not wired into the current session path

## Repository Layout

- `bin/`: binary entrypoint and Cobra command setup.
- `app/client/`: client application flow, TCP dialing, and provisional terminal demo code not used by the default CLI path.
- `app/server/`: server application flow, TCP listening, and provisional shell demo code not used by the default CLI path.
- `lib/transport/`: concrete Noise-backed framed transport plus protobuf send/receive helpers.
- `lib/auth/`: auth frame schema, authentication protocol/state machine, signed payloads, and auth transcript handling.
- `lib/session/`: authenticated global session model and minimal post-auth protocol boundary.
- `lib/bincoder/`: small binary encoding helpers for framing and key formats.
- `lib/keys/`: key generation, parsing, serialization, and signing helpers.
- `lib/tty/`: local raw terminal and server PTY mechanics.
- `lib/settings/`: config loading and validation.
- `lib/logging/`: global Charmbracelet logger setup.

## Development Rules

- Prefer small, composable layers over large all-in-one abstractions.
- Keep TCP ownership in `app/client` and `app/server`; do not move dialing/listening or TCP tuning into `lib/transport`.
- Keep `transport.Transport` focused on encrypted frame send/receive.
- Keep protobuf marshaling/validation above transport in helper functions rather than making it the transport identity.
- Keep auth and session wire schemas separate: one protobuf `oneof` auth frame type and one protobuf `oneof` session frame type.
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
- `lib/session.Connect` and `lib/session.Accept` are the authenticated session construction entry points today.
- `lib/session` may own internal connection-runtime details such as target handoff, cancellation, and handshake/auth timeout enforcement.
- Auth code should run the authentication protocol with the supplied identities and keys; it should not decide local policy, selected service, or requested channel type.
- Auth protocol messages live only in `mygosh.auth.v1.AuthFrame`; session protocol messages live only in `mygosh.session.v1.Envelope`.
- Auth messages must not include which service or channel the client wants to run.
- Every auth initiation or request must have a corresponding reply, including rejection and error paths.
- Signed auth payloads use deterministic protobuf serialization; do not reintroduce a second canonicalization scheme for auth blobs.
- `Session.Run` should be the post-auth receive owner. Do not add competing `ReceiveFrame` / `ReceiveProto` users around it.

## Channel Direction

- Channels are opened after authentication.
- The current terminal behavior should become one future `session` channel variant.
- `StartShell` is the PTY-backed command path.
- `StartExec` is the non-PTY command path.
- The old client/server terminal plumbing currently lives in `app` as demo-only code and is intentionally unused by the default CLI path.
- Do not tie channel routing to `session_id`; reserve `session_id` for opaque audit/logging if it remains in the protocol.

## Process-Separation Biases

`PROCESS_SEPARATION.md` is guidance, not the immediate priority. Keep its boundaries in mind without forcing a process split now.

- Keep one receive owner per connection; do not let unrelated goroutines compete over `ReceiveFrame` / `ReceiveProto`.
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

- Expected current manual behavior is one client connected to one server process, successful authentication, then clean exit.
- The default CLI path does not currently enter raw terminal mode. Only verify terminal restoration if you explicitly rewire the provisional demo PTY code.

## Current Design Biases

- Authenticated session construction is in place; the next priority is building the post-auth session/channel-open path on top of the new boundary.
- Keep the current PTY path provisional until it can sit behind the channel model.
- Add batching, escape sequences like `~.`, reconnect/resume, and broader execution policy only after the session/channel layer is boring.
- When in doubt, choose the smallest change that improves the session/channel path without closing off future auth, authorization, or process-separation work.
