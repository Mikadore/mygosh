# Process Separation Notes

This repository does not have process-level security separation today. The current goal is still a correct interactive PTY over a small custom protocol. This note is about how to keep building toward that goal without painting the codebase into a corner when we later want an OpenSSH-style split between:

- a network-facing connection worker
- a privileged policy/host-key helper
- an unprivileged session/PTY worker

The recommendations below are grounded in the current code, not in a hypothetical rewrite.

## Current Structure

Today, one TCP connection is handled end to end inside one process and one main call path:

- `app/server/server.go`
  - listens
  - accepts one connection
  - constructs demo host/client keys inline
  - calls `session.EstablishServer`
  - calls `session.NewShellServer(...).Run(ctx)`
- `lib/session/session.go`
  - runs Noise handshake
  - signs server auth with the host private key
  - verifies client signatures
  - authorizes the client inline through `AuthorizeClient`
  - returns an authenticated `*session.Session`
- `lib/session/server.go`
  - receives a single `OpenRequest`
  - starts a PTY directly with `exec.CommandContext`
  - launches goroutines to move PTY bytes to/from the transport

On the client side, `app/client/client.go` follows the same pattern: one process does dial, host key verification, session open, raw TTY handling, and PTY byte forwarding.

## Findings From The Current Code

### Good seams that already exist

- `session.EstablishClient` already accepts a `HostKeyVerifier`.
  - This is the right boundary for a future file-backed `known_hosts` implementation.
  - Keep file parsing and trust policy outside the auth state machine.
- `session.EstablishServer` already accepts an `AuthorizeClient` callback.
  - This is the right boundary for future `authorized_keys` and user-policy lookup.
  - It needs to become richer, but the basic direction is good.
- `transport.Transport` already serializes concurrent writes with `writeMu`.
  - That means multiple goroutines can safely send messages today.
- `lib/tty/vtty.go` already documents the future use of `pty.StartWithAttrs` and `SysProcAttr.Credential`.
  - That comment is exactly the right future direction for user switching and least-privilege PTY launch.

### Couplings that will make later separation harder if they spread

- `session.EstablishServer` currently mixes:
  - untrusted network input
  - host-key signing
  - client auth verification
  - authorization policy
  - session metadata assembly
- `ShellServer.Run` currently mixes:
  - protocol state (`OpenRequest`, `OpenOk`, `Close`, `Resize`)
  - process launch
  - PTY I/O
  - lifecycle coordination
- The same protobuf `Envelope` carries both auth messages and post-auth PTY messages.
  - This is fine if the connection phase stays explicit.
  - It becomes risky if later code lets different goroutines read directly from the same transport.
- `Transport.Receive` is not a router.
  - Even though `NoiseStream` serializes decrypts, multiple goroutines calling `Receive` would still race semantically over who consumes which frame.
  - A future multi-channel design must have one read owner per connection.
- The server currently authorizes a client and immediately launches the session in the same process that handled the untrusted socket.
- `OpenResponse.SessionId` is hard-coded to `"session-1"`.
  - That is useful as a placeholder.
  - It should not become the routing key for future channels.

### Constraints worth preserving

These match the current repository guidance and are compatible with later process separation:

- Keep TCP ownership in `app/client` and `app/server`.
- Keep `NoiseStream` limited to encrypted packet send/receive.
- Keep one protobuf envelope per frame.
- Keep terminal payloads as raw bytes.
- Keep the first interactive shell path small and boring.

## Recommended Direction

The main idea is: separate by responsibility now, so the same boundaries can later become process boundaries.

## 1. Make connection phases explicit

Treat one connection as a small state machine with phases:

1. `noise`
2. `auth`
3. `session-open`
4. `session-running`
5. `draining`
6. `closed`

Today those phases exist only implicitly across `Handshake*`, `Establish*`, `waitOpenOK`, and `receiveOpen`. Make them explicit in one connection manager before adding more protocol features.

Why this helps later:

- a privileged helper can expose "sign server auth" and "authorize client" only during `auth`
- a session worker can only be started after `auth`
- unexpected messages can be rejected at the connection manager instead of inside PTY code

## 2. Move to one receive loop per connection

Do not let per-channel goroutines call `Transport.Receive` directly.

Instead, structure the server and client around:

- one connection read loop that owns `Transport.Receive`
- one connection dispatcher that routes decoded envelopes
- one goroutine per active logical channel/session handler

Suggested rule:

- only the connection manager reads from the transport
- channel handlers receive typed events over Go channels
- channel handlers may call `Transport.Send` directly, or send through a connection-owned outbound queue

The current code is already close to this:

- server side has one receive goroutine after open
- client side has one receive goroutine after open

What should not happen next is "channel A calls `Receive`, channel B also calls `Receive`". That would make future multiplexing and future privsep IPC much harder.

## 3. Introduce a connection manager before introducing real channels

Even if the wire still supports exactly one interactive shell for a while, add an internal connection manager now.

Suggested responsibilities:

- own the transport
- own the connection context/cancel function
- enforce protocol phase
- assign opaque session IDs for logging/audit
- create and track logical channel handlers
- translate channel events into wire messages
- translate wire messages into channel events

This lets the code keep a single interactive channel today while making the eventual jump to multiple channels a local change inside the manager.

## 4. Keep auth decisions pure and RPC-friendly

Anything that may later move behind a privileged monitor should be expressed as a narrow interface over plain data.

Good future-facing shapes are:

```go
type ServerAuthSigner interface {
	PublicKey(context.Context) (keys.PublicKey, error)
	SignServerAuth(context.Context, ServerAuthRequest) (ServerAuthResult, error)
}

type ClientAuthorizer interface {
	AuthorizeClient(context.Context, ClientAuthContext) (AuthDecision, error)
}

type KnownHostsVerifier interface {
	Verify(context.Context, HostKeyCheck) error
}

type AccountResolver interface {
	Resolve(context.Context, string) (LocalAccount, error)
}
```

Important property: these APIs take and return data, not `net.Conn`, `*transport.Transport`, `*exec.Cmd`, or `*os.File`.

That means the same implementation can be:

- an in-process Go object today
- an RPC client to a privileged helper later

## 5. Split authentication identity from local execution identity

Right now the server auth callback receives:

- remote `Username`
- remote `Service`
- remote public key

That is enough for the demo, but it is not enough for future least-privilege execution. The server needs to distinguish:

- who the remote client claims to be
- what local account, if any, that maps to
- what that account is allowed to do
- what session attributes are permitted

Use separate types for those layers.

Suggested model:

```go
type ClientIdentity struct {
	RequestedUsername string
	Service           string
	PublicKey         keys.PublicKey
}

type LocalAccount struct {
	Username string
	UID      uint32
	GID      uint32
	Groups   []uint32
	HomeDir  string
	Shell    string
}

type SessionPermit struct {
	Account        LocalAccount
	AllowPTY       bool
	DefaultShell   string
	WorkingDir     string
	AllowedEnv     []string
	AuthorizedBy   string
}

type AuthDecision struct {
	Identity ClientIdentity
	Permit   SessionPermit
}
```

This keeps the untrusted client request separate from the trusted, locally resolved execution plan.

## 6. Keep authorized_keys lookup outside the auth state machine

When file-backed client authorization is added, avoid putting filesystem access directly inside `session.EstablishServer`.

Preferred layering:

1. `session.EstablishServer` verifies signatures and extracts a pure `ClientIdentity`
2. a `ClientAuthorizer` decides whether the key is allowed
3. an `AccountResolver` resolves the local account and session policy
4. the connection manager starts a session using the returned `SessionPermit`

This keeps the auth machine small and makes a future privileged monitor straightforward.

### Data model for `authorized_keys`

When adding parsing, preserve enough structure for future policy, even if the first implementation only enforces a subset.

Suggested parsed shape:

```go
type AuthorizedKeyEntry struct {
	PublicKey keys.PublicKey
	Comment   string
	Options   AuthorizedKeyOptions
	Source    string
}

type AuthorizedKeyOptions struct {
	FromPatterns []string
	PermitPTY    *bool
	ForceCommand string
}
```

Notes:

- Parse and retain options even if most are initially rejected or ignored.
- Do not let wire protocol code know where the key came from on disk.
- Do not let PTY launch code parse `authorized_keys`.

Also note that the current repo can parse OpenSSH private keys, but not OpenSSH public key lines yet. Add public-key-line parsing as a separate concern from authorization policy.

## 7. Keep known_hosts verification outside the client auth machine

The existing `HostKeyVerifier` hook is the right seam. Keep it.

Recommended next step:

- create a file-backed verifier that implements the existing callback shape
- keep `session.EstablishClient` unaware of file paths, TOFU policy, or host alias expansion

Suggested data shape:

```go
type HostKeyCheck struct {
	ReferenceIdentity string
	PresentedKey      keys.PublicKey
}
```

Then the file-backed verifier can later evolve independently to support:

- exact hostnames
- bracketed host:port forms
- aliases
- multiple keys per host
- future revocation rules

The important part for process separation is that the auth state machine continues to ask only, "is this host key acceptable for this reference identity?"

## 8. Build a session launch plan, not an `exec.Cmd` inline

`ShellServer.Run` currently does:

- `exec.CommandContext`
- environment construction
- PTY creation

For future separation, change the PTY side to accept a launch plan instead.

Suggested shape:

```go
type ShellLaunchPlan struct {
	SessionID string
	Account   LocalAccount
	ShellPath string
	Dir       string
	Env       []string
	Size      tty.Size
}
```

Then define a launcher interface:

```go
type SessionLauncher interface {
	LaunchShell(context.Context, ShellLaunchPlan) (RunningSession, error)
}
```

Where `RunningSession` exposes only what the protocol layer needs:

- read PTY output bytes
- write PTY input bytes
- resize
- wait for exit
- close

That gives three easy future implementations:

- direct in-process PTY launch
- post-auth helper process
- test double for protocol tests

## 9. Keep PTY policy and PTY mechanics separate

`lib/tty/vtty.go` is a good place for PTY mechanics. Keep it that way.

Do not move these decisions into the PTY package:

- whether the session is allowed to allocate a PTY
- which local account should run the shell
- which environment variables are allowed
- which directory should be used

Those belong in policy and session-launch planning, not in PTY helpers.

This separation matters because a future privileged monitor may approve a PTY launch, while an unprivileged worker actually performs it.

## 10. Keep wire protocol focused on intent, not local policy

The wire protocol should describe what the remote peer wants, not how the local machine enforces it.

Good wire inputs:

- requested terminal type
- requested rows/cols
- resize events
- channel close

Bad wire inputs for future design:

- local UID/GID
- direct shell path chosen by the client
- arbitrary server env injection
- permission flags that should be decided locally

The current `OpenRequest` is small and mostly on the right track. Keep it that way.

## 11. If channels are added later, separate routing IDs from audit IDs

`OpenResponse.SessionId` already exists, but it is currently just `"session-1"`.

Recommendation:

- keep `session_id` as an opaque audit/logging identifier
- add a separate numeric `channel_id` if/when real multiplexed channels are added

Why:

- audit IDs often want to survive reconnects, helpers, logs, and process boundaries
- routing IDs want to be small, local, and easy to index

Do not overload one field with both meanings.

## 12. Shape channel handlers around events, not raw protobuf

A future per-channel handler should not know about every envelope kind.

Prefer internal events such as:

```go
type ChannelEvent struct {
	Data   []byte
	Resize *tty.Size
	Close  *CloseEvent
}

type ChannelOutput struct {
	Data       []byte
	ExitStatus *int
	Close      *CloseEvent
	Err        *ProtocolError
}
```

Then the connection manager does all protobuf translation.

Benefits:

- channel handlers stay testable without a real transport
- a future session child can speak a small internal RPC/event protocol
- adding new wire message kinds does not leak everywhere

## 13. Centralize shutdown ownership

The current client and server session loops return on the first goroutine error and rely on deferred closes. That is acceptable for a one-session prototype, but future channel/process separation needs stricter ownership.

Recommended rule:

- the connection manager owns connection shutdown
- channel handlers own only their channel/session lifecycle
- helpers request shutdown through signals/events, not by closing the transport directly

In particular:

- channel handler exit should not directly imply transport close
- connection cancellation should fan out to all channel handlers
- transport close should happen once

Using `errgroup.Group` plus a connection-owned cancel function would fit this well.

## 14. Hide privileged decisions behind stable value objects

If we later introduce a monitor/helper process, the expensive refactor is not the `fork` or RPC code. The expensive refactor is untangling ad hoc access to:

- host private keys
- `authorized_keys`
- `known_hosts`
- passwd/group data
- shell path policy
- environment policy

So the key preparatory step is to define stable value objects now:

- `ClientIdentity`
- `AuthDecision`
- `LocalAccount`
- `SessionPermit`
- `ShellLaunchPlan`

If those become the lingua franca between layers, the later process split becomes mechanical.

## 15. A practical package direction

Without over-abstracting, a future layout could look like:

- `app/server`
  - listener and connection supervisor
- `lib/session`
  - connection manager
  - auth state machine
  - channel routing
- `lib/policy`
  - `ClientAuthorizer`
  - `KnownHostsVerifier`
  - shared decision types
- `lib/account`
  - local user/group lookup
- `lib/keys`
  - key parsing and key serialization
  - add OpenSSH public key line parsing here or in a tiny sibling package
- `lib/tty`
  - PTY mechanics only
- `lib/process`
  - session launcher abstractions

This keeps each piece small and lets the eventual monitor/helper boundary cut across clean interfaces.

## What To Avoid Next

- Do not add direct `os/user`, passwd, or `authorized_keys` reads inside `session.EstablishServer`.
- Do not let multiple goroutines call `Transport.Receive`.
- Do not let PTY/session handlers construct protobuf envelopes directly if a connection manager can do it.
- Do not let client-controlled fields directly become `exec.Cmd` settings other than tightly validated PTY/session intent.
- Do not spread host private key access beyond a dedicated signer/provider abstraction.
- Do not tie future channel routing to the current placeholder `session_id`.

## Suggested Incremental Plan

1. Extract richer auth/policy interfaces without changing behavior.
2. Add a connection manager that owns receive, dispatch, and shutdown.
3. Change the PTY side to consume a `ShellLaunchPlan` through a `SessionLauncher`.
4. Add file-backed `known_hosts` and `authorized_keys` implementations behind those interfaces.
5. Add local account resolution and session permits behind a resolver/policy layer.
6. Only then split the privileged operations into a helper process or monitor.

That order keeps the current PTY-first goal intact while making later process separation an implementation detail instead of a protocol rewrite.
