# Next Step: Session Abstraction And Auth/Permission Boundaries

## Current Baseline

The auth/session split is now real enough to plan from:

- Noise handshake still begins from `app/client` and `app/server`, but authenticated session construction happens through `lib/session.Connect` and `lib/session.Accept`.
- `lib/transport.Transport` is the concrete Noise-backed framed connection.
- Auth traffic uses `mygosh.auth.v1.AuthFrame`.
- Post-auth traffic uses `mygosh.session.v1.Envelope`.
- `lib/session` owns construction-time shutdown and handshake/auth timeout enforcement.
- `lib/session` still stops at authenticated session construction plus a minimal post-auth receive-loop stub.
- The default CLI currently completes Noise, authenticates, logs success, and exits.

The app layer also now uses minimal file-backed trust stubs:

- the client loads its identity from `~/.mygosh/id_ed25519`
- the server loads its host key from `~/.mygosh/host_ed25519`
- the client verifies the server against `~/.mygosh/known_hosts`
- the server authorizes client keys from `~/.mygosh/authorized_keys` and `~/.ssh/authorized_keys`

Those trust hooks are intentionally small. They are good seams, but they are not yet a complete authentication, authorization, or permissions model.

## Planning Goal

The next goal is not only to add real post-auth channels, but to shape the project so that:

- a session is a real long-lived abstraction rather than a one-shot auth result
- authentication stays separate from authorization and local permissions
- file-backed trust lookups remain outside the auth state machine
- the resulting boundaries still make sense if the repository later moves toward the process-separation direction described in `PROCESS_SEPARATION.md`

In practice, the next milestone should make both of these stories clearer:

1. what a post-auth session owns and how channels live inside it
2. how a verified remote identity turns into local policy and permissions

## Why These Two Problems Belong Together

Session abstraction and auth/permission abstraction should be planned together because they meet at the same point: the moment after authentication succeeds.

At that boundary, the system needs to answer two different questions:

- what protocol object now owns the connection and its post-auth messages
- what local authority, if any, does this authenticated identity actually have

If the session model is too thin, channel-open behavior will end up mixed with user/account policy.
If the auth model is too thin, session/channel code will end up deciding things that belong to trust policy, account mapping, or execution permissions.

The clean version is:

- `auth` proves identity
- trust and policy decide whether that identity is acceptable
- session owns the post-auth connection and channels
- later execution code consumes an already-decided permission/launch plan

That direction also lines up with `PROCESS_SEPARATION.md`, even if the repo does not introduce real helper processes yet.

## Constraints To Preserve

- Keep auth and session wire schemas separate.
- Do not move service or channel intent back into auth messages.
- Keep TCP ownership in `app/client` and `app/server`.
- Keep `transport.Transport` focused on encrypted frame send/receive.
- Keep one receive owner per connection.
- Keep `Session.Run` as the eventual post-auth receive owner.
- Keep `known_hosts`, `authorized_keys`, and private-key file lookup outside `lib/auth`.
- Avoid letting `lib/session` become the place that parses trust files or decides local account policy.
- Do not add SSH compatibility, reconnect/resume, or broad execution policy in this step.

## Design Directions And Tradeoffs

### 1. Session shape

Approach: keep one session object with an internal dispatcher and let channels be session-owned sub-objects.

Pros:

- preserves one receive owner per connection
- makes channel routing an internal session concern
- fits the process-separation direction well because the connection/session boundary stays explicit

Cons:

- asks for more up-front abstraction before the first useful channel feature ships

Approach: expose channels very early and let them look almost transport-backed.

Pros:

- can feel direct when building the first shell or exec path
- may get the first feature moving quickly

Cons:

- makes it easier to accidentally leak transport details into channel code
- makes it easier to violate single-owner receive discipline later

The better bias is to keep the session object real first, even if the first channel set is tiny.

### 2. Auth and authorization boundary

Approach: keep using minimal callbacks that only return success or failure.

Pros:

- small change surface
- easy to wire into the current app flow

Cons:

- weak for logging, audit, and policy evolution
- hard to carry richer decisions such as matched key source, resolved account, or permission set
- less friendly to future helper-process boundaries

Approach: move toward richer plain-data interfaces and result types.

Pros:

- clearer separation between proving identity and deciding permissions
- better support for account mapping, policy, and audit
- much closer to RPC/process-separation-ready boundaries

Cons:

- introduces more types earlier
- can feel heavier if the project still only supports one narrow execution path

The better bias is to keep the wire/auth machine simple, while allowing trust and policy decisions to become richer around it.

### 3. File-backed trust placement

Approach: keep file-backed lookup logic mostly in `app/client` and `app/server`.

Pros:

- keeps library packages small
- makes deployment choices obviously app-owned

Cons:

- duplicates policy and lookup logic
- makes testing and reuse weaker
- risks smearing trust semantics across app entrypoints

Approach: keep reusable file-backed trust helpers in `lib/trust`, but compose them from the app layer.

Pros:

- preserves the app-owned deployment choice while keeping parsing and lookup reusable
- keeps `auth` and `session` free of file-path knowledge
- matches the current `HostKeyVerifier` and `AuthorizeClient` seams well

Cons:

- requires discipline so `lib/trust` does not grow into an all-purpose policy layer

The current repo is already leaning in this direction, and it is the better one to continue.

### 4. Permissions modeling

Approach: treat successful client auth as enough to start work immediately.

Pros:

- simple for a demo

Cons:

- collapses authentication, authorization, and local execution policy into one step
- makes future PTY/exec permissions harder to reason about

Approach: treat authenticated identity as input to a separate permission decision.

Pros:

- leaves room for account resolution, allowed channel types, PTY policy, forced commands, and future environment/workdir rules
- lines up cleanly with later process separation

Cons:

- requires the repo to define a few more concepts before they are all fully enforced

This is the direction the next step should favor, even if the first permission model is still deliberately small.

## Near-Term Outcome To Aim For

The next milestone should leave the repository in a state where:

- an authenticated session is a real post-auth abstraction with clear ownership
- the first channel-open path exists behind that session boundary
- auth continues to prove identity only
- known-hosts verification, key authorization, and account/permission decisions remain outside the auth state machine
- the project can later swap in richer trust sources or helper processes without rewriting the session protocol boundary

That does not require finalizing every interface up front, but it does require choosing boundaries that do not push trust policy back into `auth` or channel behavior directly into app glue.

## Explicit Non-Goals For The Next Step

- Do not collapse auth back into `lib/session`.
- Do not let multiple goroutines call `ReceiveFrame` or `ReceiveProto` on the same connection.
- Do not add TOFU or automatic host-key update semantics yet.
- Do not broaden file-backed trust stubs into a full policy engine in one jump.
- Do not add multi-method auth, reconnect/resume, or SSH compatibility.
- Do not tie future channel routing to `session_id`.

## Testing Direction

- Keep `go test ./...` as the required full pass.
- Prefer focused tests in `lib/session`, `lib/auth`, `lib/trust`, and `lib/transport`.
- Add more end-to-end coverage around:
  - host-key verification success and failure
  - client-key authorization success and failure
  - session/channel receive ownership
  - post-auth channel-open behavior
- Prefer tests that exercise policy and ownership boundaries, not only parser correctness.
