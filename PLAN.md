# Next Step: Post-Auth Session Protocol And Channel Opens

## Current State

The auth/session cleanup step is complete enough to serve as the new baseline:

- Noise handshake is still owned by `app/client` and `app/server` through `lib/session.Connect` and `lib/session.Accept`.
- `lib/transport.Transport` is now the concrete Noise-backed framed connection.
- Protobuf encoding/validation above transport now goes through `transport.SendProto` / `transport.ReceiveProto`.
- Authentication protocol/state-machine code now lives in `lib/auth`.
- Auth traffic uses `mygosh.auth.v1.AuthFrame`.
- Session traffic uses `mygosh.session.v1.Envelope`.
- `ClientAuthRequest` no longer carries service/channel intent.
- Client auth now has an explicit final server reply through `ClientAuthResponse`.
- Signed auth payloads use deterministic protobuf serialization.
- `lib/bincoder/struct.go` has been removed.
- `lib/session` now models only the authenticated session boundary and a minimal post-auth receive-loop stub.
- `lib/session` owns an internal connection runtime that handles connection shutdown plus handshake/auth timeout budgets during construction.
- The old PTY demo plumbing lives under `app/` and is not part of the default authenticated session flow.
- The default CLI behavior is currently "connect, complete Noise, authenticate, log success, exit".

This means the next step is no longer "separate auth from session". That split has already happened. The next step is to build the first real post-auth session protocol on top of the new boundary.

## Goal

Implement the first post-auth session protocol path behind the minimal authenticated session abstraction.

A session should already exist after Noise + auth. After that point:

- one internal session event loop owns all post-auth `transport.ReceiveProto` calls
- local actions are initiated through explicit session methods
- remote protocol events are dispatched through narrow callbacks or typed handlers
- the first useful post-auth capability is opening a `session` channel for shell/exec behavior

The repository may continue to keep interactive PTY behavior provisional while this is introduced, but the protocol ownership model should be the real one.

## Wire And Ownership Constraints

- Keep auth and session wire schemas separate.
  - Auth stays in `mygosh.auth.v1.AuthFrame`.
  - Post-auth traffic stays in `mygosh.session.v1.Envelope`.
- Do not move service/channel intent back into auth.
- Keep TCP ownership in `app/client` and `app/server`.
- Keep `transport.Transport` focused on encrypted frame send/receive.
- Keep protobuf marshaling at the helper layer rather than rebuilding a wrapper transport abstraction.
- Keep one receive owner per connection.
- Do not expose raw transport receive loops as the primary public session API.
- Keep the session-owned connection runtime implementation-only; extend it only for lifecycle/liveness concerns, not protocol semantics.
- Do not add SSH compatibility, reconnect/resume, or broad execution policy in this step.

## Responsibility Split

- `lib/auth` owns auth frames, transcript hashing, signed auth payload generation, and auth state transitions.
- `lib/session` owns the authenticated session lifecycle, the single post-auth event loop, future channel routing, public local-action APIs, and the internal connection runtime used for construction-time cancellation/timeouts.
- `app/client` and `app/server` own deployment-specific choices such as keys, peer identity expectations, and authorization policy.
- PTY launch policy and shell execution policy should stay out of `lib/auth` and `lib/transport`.

Values that depend on deployment, peer, user, or local policy must still be supplied through callbacks, function parameters, interfaces, or config objects.

## Next Implementation Direction

Build the smallest real post-auth session layer that preserves the current boundary:

1. Keep `Session.Run` as the only post-auth receive owner and make it dispatch session envelopes instead of returning an immediate stub error.
2. Add explicit local-action APIs on `Session` for the first post-auth intent, starting with opening one `session` channel.
3. Route remote post-auth events through narrow typed callbacks or handler interfaces rather than exposing raw Go channels.
4. Model PTY/shell/exec behavior as requests and state on that future `session` channel, not as top-level session behavior.
5. Reuse or adapt the provisional demo PTY code in `app/` only after the session channel boundary exists.

## Explicit Non-Goals For This Step

- Do not rework auth back into `lib/session`.
- Do not add multi-key retry or multi-method authentication yet.
- Do not let multiple goroutines call `ReceiveFrame` / `ReceiveProto` on the same connection.
- Do not reintroduce hardcoded auth/session placeholders inside `lib/auth` or `lib/session`.
- Do not treat `session_id` as a routing key.

## Testing Direction

- Keep `go test ./...` as the required full test pass.
- Prefer focused protocol tests in `lib/session`, `lib/auth`, and `lib/transport`.
- Use `net.Pipe` with deadlines for bidirectional session tests.
- Preserve explicit tests that auth succeeds/fails correctly and that terminal data bytes remain unchanged when session data flow is reintroduced.
