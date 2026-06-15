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
- `lib/session` currently includes authenticated session construction plus an initial post-auth session/channel multiplexer
- `lib/session` owns an internal connection runtime for parent-context shutdown plus handshake/auth timeouts
- `lib/trust` holds the current file-backed trust stubs for private-key lookup, `known_hosts`, and `authorized_keys`
- the default CLI client loads `~/.mygosh/id_ed25519` and verifies the server against `~/.mygosh/known_hosts`
- the default CLI server loads `~/.mygosh/host_ed25519` and authorizes client keys from `~/.mygosh/authorized_keys` and `~/.ssh/authorized_keys`
- the default CLI flow authenticates and exits; interactive terminal behavior is not wired into the current session path

## Repository Layout

- `bin/`: binary entrypoint and Cobra command setup.
- `app/root/`: application root wiring for settings, logging, and future app-scoped services/shutdown hooks.
- `app/client/`: client application flow, TCP dialing, current file-backed identity/host-key verification wiring, and provisional terminal demo code not used by the default CLI path.
- `app/server/`: server application flow, TCP listening, current file-backed client authorization wiring, and provisional shell demo code not used by the default CLI path.
- `lib/transport/`: concrete Noise-backed framed transport plus protobuf send/receive helpers.
- `lib/auth/`: auth frame schema, authentication protocol/state machine, signed payloads, and auth transcript handling.
- `lib/session/`: authenticated global session model and minimal post-auth protocol boundary.
- `lib/bincoder/`: small binary encoding helpers for framing and key formats.
- `lib/keys/`: key generation, parsing, serialization, and signing helpers.
- `lib/trust/`: file-backed trust helpers and current stubs for `known_hosts`, `authorized_keys`, and OpenSSH private-key lookup.
- `lib/tty/`: local raw terminal and server PTY mechanics.
- `lib/settings/`: config loading and validation.
- `lib/logging/`: logger construction and small logging helpers used by the app root and library seams.

## Development Rules

- Prefer small, composable layers over large all-in-one abstractions.
- Keep app-scoped services such as settings, logging, and future telemetry rooted in `app/root`; avoid package-global service registries.
- Keep TCP ownership in `app/client` and `app/server`; do not move dialing/listening or TCP tuning into `lib/transport`.
- Keep `transport.Transport` focused on encrypted frame send/receive.
- Keep protobuf marshaling/validation above transport in helper functions rather than making it the transport identity.
- Keep auth and session wire schemas separate: one protobuf `oneof` auth frame type and one protobuf `oneof` session frame type.
- Keep file-backed trust lookup outside `lib/auth` and `lib/session`; prefer `lib/trust` plus app-level composition for deployment-specific policy.
- Keep terminal data contents raw bytes and return terminal bytes unchanged.
- Use protobuf for message serialization and protovalidate for schema validation where applicable.
- Use deterministic protobuf serialization only for blobs or payloads that are signed.
- Use `github.com/rotisserie/eris` for wrapped errors.
- Use `github.com/charmbracelet/log` for logging.
- Prefer passing explicit `*log.Logger` instances through app/session/auth/trust wiring over mutating a global default logger.
- Do not target Windows.
- Do not add SSH compatibility, ControlMaster, or reconnect/resume unless the roadmap explicitly moves to that step.
- Factor potential process separation and the security impact of changes into further development and architecture decisions, even when the immediate implementation stays in-process.
- Prefer the smallest change that improves the authenticated session and channel-open path without closing off future process separation.

## Auth And Session Direction

- `lib/session/session.go` should model the global authenticated session itself, not PTY/client/server terminal behavior.
- Authentication protocol logic and auth state transitions should live in `lib/auth`.
- Session construction chooses and validates identities, keys, and trust hooks, then calls into the auth machinery.
- `lib/session.Connect` and `lib/session.Accept` are the authenticated session construction entry points today.
- `lib/session` may own internal connection-runtime details such as target handoff, cancellation, and handshake/auth timeout enforcement.
- Auth code should run the authentication protocol with the supplied identities and keys; it should not decide local policy, `known_hosts` file paths, `authorized_keys` parsing, selected service, or requested channel type.
- Auth protocol messages live only in `mygosh.auth.v1.AuthFrame`; session protocol messages live only in `mygosh.session.v1.Envelope`.
- Auth messages must not include which service or channel the client wants to run.
- Every auth initiation or request must have a corresponding reply, including rejection and error paths.
- Signed auth payloads use deterministic protobuf serialization; do not reintroduce a second canonicalization scheme for auth blobs.
- `Session.Run` should be the post-auth receive owner. Do not add competing `ReceiveFrame` / `ReceiveProto` users around it.

## Trust Direction

- `lib/trust` should stay focused on trust data lookup and verification, not on transport or channel behavior.
- File-backed `known_hosts`, `authorized_keys`, and private-key loading are current stubs, not the final policy model.
- Host-key verification belongs behind the `HostKeyVerifier` seam.
- Client-key authorization belongs behind the `AuthorizeClient` seam.
- Local account resolution and broader permissions should remain separate from raw auth success.

## Channel Direction

- Channels are opened after authentication.
- The current terminal behavior should become one future `session` channel variant.
- Future PTY-backed and non-PTY command paths should stay behind the session/channel model rather than bypassing it.
- The old client/server terminal plumbing currently lives in `app` as demo-only code and is intentionally unused by the default CLI path.
- Do not introduce channel routing keyed to a future `session_id`; keep any such identifier, if added later, reserved for opaque audit/logging.

## Process-Separation Biases

The repository currently references `PROCESS_SEPARATION.md`, but that file is not present in this checkout. Treat process separation as an architectural constraint and design bias without forcing an immediate process split.

- Keep one receive owner per connection; do not let unrelated goroutines compete over `ReceiveFrame` / `ReceiveProto`.
- Avoid spreading host-key access, authorization policy, account lookup, or PTY launch policy into `transport` or `auth`.
- Prefer plain data interfaces at trust boundaries so future helper/monitor processes remain possible.

## Testing

- Run all tests with:

  ```sh
  go test ./...
  ```

- Prefer focused tests in `lib/auth`, `lib/session`, and `lib/transport` for protocol behavior before changing app-level flows.
- Prefer focused tests in `lib/trust` for file-backed trust behavior and trust-policy edge cases.
- Use `github.com/stretchr/testify/require` for new tests.
- For bidirectional protocol tests, prefer `net.Pipe` with deadlines over `bytes.Buffer`.
- Keep an explicit test that terminal data bytes are not transformed.

## Manual Smoke Test

- Use the tmux helper:

  ```sh
  ./run-tmux.sh
  ```

- Current auth-only smoke tests expect `~/.mygosh/id_ed25519`, `~/.mygosh/host_ed25519`, and `~/.mygosh/known_hosts`, plus a matching server-side `authorized_keys` entry.
- Expected current manual behavior is one client connected to one server process, successful authentication, then clean exit.
- The default CLI path does not currently enter raw terminal mode. Only verify terminal restoration if you explicitly rewire the provisional demo PTY code.

## Current Design Biases

- Authenticated session construction is in place; the next priority is building the post-auth session/channel-open path and a clearer auth/permissions flow on top of the new boundary.
- Keep the current PTY path provisional until it can sit behind the channel model.
- Add batching, escape sequences like `~.`, reconnect/resume, and broader execution policy only after the session/channel layer is boring.
- When in doubt, choose the smallest change that improves the session/channel path and trust-policy seams without closing off future auth, authorization, permissions, or process-separation work.
