# Next Step: Authenticated Session And Channel Opens

## Goal

Build a proper authenticated session model.

A session starts when a client connects to a server, completes the Noise handshake, and both sides mutually authenticate. After authentication, the session owns one internal protocol event loop. Either side can initiate local actions, such as opening a channel or sending a request, through explicit APIs. Remote events, such as peer-opened channels or received channel requests, are delivered through narrow handler callbacks. Actual channel implementations can be deferred or temporarily disabled while this model is introduced.

The current interactive terminal flow may break during the refactor. The repository should remain compilable.

## Known Inconsistencies To Fix

- `ClientAuthRequest` currently includes `service`; remove service/channel intent from authentication.
- Client auth currently has no final server reply; add explicit success and rejection replies.
- Current signed payloads mix custom `bincoder.Canonicalize` with deterministic protobuf; prefer deterministic protobuf for signed auth blobs.
- Remove all demo, hardcoded, or protocol-level fixed keys, names, identities, and placeholder values from auth/session logic.
- Every auth initiation or request should have a corresponding reply message, and replies may carry metadata needed by the next protocol phase.

## Responsibility Split

- `lib/auth` owns auth messages, signed payload construction, transcript handling, and auth protocol state transitions.
- `lib/session` owns global authenticated session lifecycle, the single protocol event loop, channel routing, and post-auth protocol entry points.
- `app/client` and `app/server` own TCP setup plus application-specific choices about keys, expected identities, and authorization policy.
- The auth machinery should authenticate with the identities and keys it is given. The session/application layer decides which keys to choose, which peer identity to expect, and what policy to apply.
- Values that vary by deployment, peer, user, local policy, or test case must be supplied by the implementor through callbacks, function parameters, interfaces, or config objects. Use the existing `HostKeyVerifier` shape as the model where applicable.
- Session/auth code must not synthesize demo host keys, demo client keys, usernames, reference identities, authorized principals, service names, session IDs, or command defaults as hidden protocol behavior.
- Current `lib/session/client.go` and `lib/session/server.go` terminal plumbing should move into `app` for now and may remain unused or commented out if needed to keep compilation simple.

This split should not become a large architecture exercise. Use `PROCESS_SEPARATION.md` as boundary guidance, but prioritize correct authentication and channel-open semantics over process separation.

## Auth Extensibility

Do not implement client-key retry, multi-key negotiation, or multi-method auth in this next step. However, avoid baking in assumptions that make those features awkward later.

- Model auth around supplied identity/key providers and verifier/authorizer callbacks instead of single hardcoded keypair fields wherever practical.
- Keep auth attempts explicit enough that a future client can try another key after a server rejection without rebuilding the whole session protocol.
- Keep server host-key choice separate from client-auth choice. Future server host-key support should look like selecting from configured keys compatible with the peer, not probing arbitrary alternatives.
- Signed auth payloads should bind the channel binding, transcript hashes, presented key or certificate, signature algorithm, username or principal, and any future attempt/challenge identifier.
- Service or channel intent must remain outside auth so future authentication methods can be reused for different post-auth channel types.

## Session Event Loop Model

Use one internal session event loop as the only place where the connection protocol is driven. Application code should not manually sequence receive/send operations such as "receive open request, send open confirm, receive data, send close". That shape leaks protocol machinery into callers and makes correctness harder once channel IDs, request replies, close/eof ordering, flow control, and concurrent traffic exist.

Preferred shape:

- `Session.Run(ctx, handler)` owns the transport reader/writer, protocol phase, channel table, dispatch, shutdown, and future flow-control bookkeeping.
- `Session.OpenChannel(ctx, typ, extra)` and similar methods expose local intentions.
- A narrow `Handler` interface receives remote events such as channel opens, global requests, and disconnects.
- Accepted channels get `io.Reader`/`io.Writer`-style abstractions plus explicit methods for channel requests, EOF, and close.

This is still client/server agnostic: both sides run the same session loop and use the same local-action APIs. Client/server behavior lives in the handlers and in application code that decides what to open or accept.

Do not expose raw Go channels as the primary public API. They can be useful internally, but `io.Reader`, `io.Writer`, `context.Context`, typed callbacks, and explicit methods give better backpressure, cancellation, and error propagation boundaries.

The tradeoff is that this adds more session framework upfront than a thin transport wrapper. The benefit is that protocol ordering, routing, shutdown, and future multiplexing are centralized from the start.

## Channel Direction

Channels are opened after authentication. The first useful channel family is a `session` channel for command execution.

- `StartShell` is the PTY-backed command path.
- `StartExec` is the non-PTY command path.
- The current TTY behavior is a subset of `StartShell`.
- PTY, exec, shell, environment, and window-change behavior should be modeled as requests and state transitions on a `session` channel, not as separate top-level sessions.
- Do not tie routing to `session_id`; reserve it for opaque audit/logging if retained.

Rule of thumb: expose imperative methods for local intentions like opening a channel, sending a request, writing data, EOF, and close. Use the internal event loop for remote events like peer-opened channel, received channel request, data arrival, window change, EOF, and close.

## Process-Separation Posture

Keep future helper/monitor boundaries in mind through plain data interfaces and clear responsibility boundaries.

Do not prioritize process separation over getting the authentication and channel-open model correct. The important near-term constraint is to avoid placing host-key access, authorization, account lookup, or PTY launch policy in packages that should stay protocol-focused.
