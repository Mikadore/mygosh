# Session Lifecycle and Worker Transition Plan

This plan is derived from `REVIEW.md`, `TODO.md`, and `WORKER_PLAN.md`.
It groups the remaining lifecycle, validation, authorization, and worker-split work into three implementation steps.

The intent is to get to a system with:

- one clear owner for each connection phase;
- deterministic shutdown and terminal error semantics;
- explicit session/channel lifetimes that compose with authorization leases;
- bounded peer-controlled resource usage;
- a credible path to running post-auth session logic in a dedicated worker process.

## Guiding principles

- Do not expose authentication success to the client until the server has a usable post-auth runtime.
- Keep exactly one receive owner and one serialized write owner for each post-auth connection.
- Treat channel admission, concrete service authorization, and launched-process ownership as distinct lifecycle stages.
- Make local shutdown completion independent of peer cooperation.
- Keep the monitor authoritative for authentication, authorization, credentials, limits, and final network close.
- Keep the worker disposable and scoped to one authenticated connection.

## Step 1: Establish clean ownership, activation, and shutdown semantics

### Goal

Create a single, coherent lifecycle model for a connection so the system can cleanly transition from raw socket to authenticated post-auth runtime, and later to a worker-backed runtime, without ambiguous close ownership.

### Main changes

1. Introduce an explicit connection-phase model.
   Define a small lifecycle model for:
   `accepted -> handshaking -> auth-pending -> post-auth-starting -> active -> closing -> closed`

2. Move pre-auth lifetime management out of the session package.
   The current handshake/auth timeout and connection-close machinery should no longer live inside the post-auth mux runtime.
   A neutral connection-lifecycle component, or `establish`-owned lifecycle object, should own:
   - raw socket ownership;
   - handshake timeout;
   - auth timeout;
   - ownership transfer to the post-auth runtime;
   - terminal error recording.

3. Make post-auth activation an explicit stage.
   Authentication success should not be sent merely because proof verification and account authorization succeeded.
   The server should first construct a usable post-auth runtime, validate that it is ready, and only then commit auth success.
   Even before the worker exists, this should be modeled as an explicit in-process readiness boundary.

4. Clarify close ownership and final error semantics.
   At any point, exactly one component should be the current close owner.
   Each successful phase transition transfers close ownership to the next owner.
   The system should define:
   - who closes on local cancellation;
   - who closes on protocol failure;
   - which error becomes the terminal connection result;
   - which best-effort cleanup errors are logged but not promoted.

5. Refactor the post-auth mux so the receive loop is never a work executor.
   The receive side should decode and dispatch only.
   It should not synchronously:
   - run service logic;
   - wait for handler replies;
   - block on writes;
   - perform best-effort disconnect writes indefinitely.

6. Introduce a dedicated serialized writer path.
   Outgoing frames should flow through one write owner with:
   - cancellation awareness;
   - bounded buffering;
   - bounded disconnect behavior;
   - clear fatal-write rules.

7. Define baseline session/channel lifetime semantics for authorization leases.
   Distinguish:
   - connection lifetime: authenticated connection exists;
   - channel admission lifetime: a session channel has been accepted;
   - launched-service lifetime: an actual shell/exec instance is running.
   This provides the contract that later auth/session leases must follow.

### Concrete deliverables

- A connection-lifecycle abstraction outside `lib/session`.
- `PendingServer.Accept` replaced or refactored so "auth accepted" means "post-auth runtime ready", not just "auth wire response sent".
- A post-auth mux architecture with a receive owner and a separate write owner.
- A documented terminal-state model covering local cancel, peer disconnect, protocol error, and successful close.
- Defined lease semantics for connection, admitted channel, and launched service.

### Exit criteria

- No component outside the current owner closes the connection in the normal path.
- Authentication success cannot be observed before post-auth readiness.
- Protocol-error disconnect is bounded best-effort, not an indefinite blocking path.
- Connection teardown converges on one terminal result.

### Verification focus

- cancellation during handshake, auth, and post-auth startup;
- auth timeout while app policy is still running;
- local shutdown while the peer is not reading;
- protocol error while writes are blocked;
- readiness failure after successful authorization but before auth success is committed.

## Step 2: Formalize channel state, resource limits, and request authorization

### Goal

Turn the post-auth side into a bounded, validated state machine with explicit authorization boundaries, so a session channel and its requests have well-defined semantics that can later be enforced by a worker.

### Main changes

1. Define an explicit channel state machine.
   Model channel progress explicitly, for example:
   `opening -> admitted -> open -> local-eof / remote-eof -> closing -> closed`
   plus a `failed` terminal state.

2. Validate every frame against channel and connection state.
   Reject or fail on invalid ordering such as:
   - data before open;
   - data after EOF where the protocol should forbid it;
   - requests after close;
   - duplicate open results;
   - duplicate close;
   - use of unknown or canceled request IDs.

3. Track peer channel identity explicitly.
   Maintain a set of active peer channel IDs and reject duplicate reuse while a channel is still live.
   The mux should not allow ambiguous peer-to-local addressing.

4. Clean up canceled waiters deterministically.
   Context cancellation for open/request/global waiters should remove them from internal state immediately, rather than leaving them behind until shutdown or a late reply.

5. Add hard connection-wide resource limits.
   Extend configuration beyond packet/window sizes to include limits for:
   - channels per connection;
   - pending opens;
   - outstanding channel requests;
   - outstanding global requests;
   - queued frames per channel;
   - queued bytes per channel and connection;
   - control payload sizes;
   - empty data frame budget or outright rejection.

6. Introduce a credential-aware service authorization model.
   The current "matching key implies unrestricted session/exec" behavior should be replaced with two layers:
   - connection-level permissions and constraints resolved before auth success;
   - concrete request authorization performed before PTY allocation, process start, or later forwarding/socket creation.

7. Split channel admission from launch authorization.
   Opening a `"session"` channel should not automatically grant the right to run any command.
   The server should admit the channel, then authorize the specific shell/exec request against immutable connection credentials and policy.

8. Define an authorized launch specification.
   Instead of letting service code reconstruct policy ad hoc, concrete requests should be translated into a plain-data launch spec that contains only already-authorized choices, such as:
   - shell vs exec;
   - command or forced command;
   - PTY allowed/required/denied;
   - allowed environment;
   - working directory or shell selection;
   - service-specific limits.

9. Define lease behavior around the new stages.
   The repository should have a clear rule for whether leases are:
   - acquired at channel admission;
   - upgraded or replaced at launch authorization;
   - closed on channel close, launch failure, process exit, or connection teardown.
   The important point is that leases should follow state transitions, not scattered callback timing.

### Concrete deliverables

- A documented and enforced mux/channel state machine.
- Configurable connection-wide and per-channel resource limits.
- Immediate cleanup of canceled waiters and abandoned operations.
- Immutable connection permissions on the authenticated connection.
- A service-facing authorized launch specification and request-authorization seam.

### Exit criteria

- Invalid frame ordering is rejected consistently.
- Peer channel ID reuse is impossible while a prior channel is live.
- Canceling a waiter does not leak internal pending state.
- A session channel may be admitted without yet authorizing a process launch.
- Concrete shell/exec decisions are authorized before resources are allocated.

### Verification focus

- duplicate peer channel IDs;
- data or requests in invalid states;
- cancellation of channel-open and request waits;
- exhaustion of channel, request, queue, and payload limits;
- session admission without launch;
- rejected concrete launch requests after a valid channel open.

## Step 3: Replace the demo process runtime and introduce the worker split

### Goal

Replace the PTY demo lifecycle with a real process runner, then place the full post-auth mux and service runtime behind a dedicated per-connection worker process with a validated startup contract.

### Main changes

1. Replace the current PTY demo runtime with a process owner abstraction.
   The process layer should own:
   - command creation;
   - PTY or pipe setup;
   - process group/session handling;
   - wait/reap behavior;
   - descriptor cleanup;
   - shutdown sequencing;
   - exit status and exit signal reporting.

2. Fix the current launch-order hazards.
   In particular:
   - no child may exist without an owner that is guaranteed to wait and clean it up;
   - no-reply state-changing requests must either be forbidden or handled safely;
   - process startup must not depend on a later callback to begin ownership;
   - stdin EOF should become intentional input half-close semantics, not unconditional process death.

3. Make channel completion locally enforceable.
   A process exit, local cancellation, or connection failure must drive the process and channel to terminal completion even if the peer never acknowledges close.
   Close acknowledgment can improve graceful behavior, but it cannot be required for local completion.

4. Own the full child process tree.
   The runner should:
   - launch the child in a deliberate process group/session;
   - send bounded graceful then forced termination on cancellation;
   - always reap exactly once;
   - ensure descendants do not survive connection teardown.

5. Replace the current single service demo with a narrower service boundary.
   The worker-facing service side should consume:
   - immutable connection credentials;
   - immutable connection permissions;
   - authorized launch specifications.
   It should not perform account lookup, key authorization, or deployment policy decisions.

6. Introduce the monitor/worker split over Unix `SOCK_SEQPACKET`.
   The monitor keeps:
   - the network connection;
   - Noise transport and cipher state;
   - authentication and authorization;
   - immutable credential creation;
   - worker spawning and supervision;
   - final network close.
   The worker owns:
   - post-auth mux;
   - session/service parsing;
   - command runtime;
   - local cleanup for its connection.

7. Define a versioned worker startup protocol.
   The monitor should send a bounded startup message containing plain data such as:
   - protocol version;
   - connection ID;
   - launch nonce;
   - connection-binding value;
   - authentication facts;
   - resolved account snapshot;
   - permissions and constraints;
   - session/service limits and timeouts.

8. Make worker validation mandatory before readiness.
   The worker should validate:
   - startup envelope/version/type;
   - required fields and bounds;
   - connection ID and launch nonce;
   - binding consistency;
   - UID/GID/group/home/shell coherence;
   - permissions and limit coherence;
   - expected socket type and descriptor set;
   - its effective process identity.

9. Make readiness explicit and gate auth success on it.
   The intended order is:
   - authenticate and authorize;
   - spawn worker;
   - send startup snapshot;
   - worker validates and constructs runtime;
   - worker sends readiness ack;
   - monitor commits auth success;
   - monitor activates bidirectional frame relay.

10. Use process arguments only for a narrow bootstrap contract.
   Passing the inherited FD number, worker mode, and perhaps a non-secret connection label via argv is acceptable.
   The full startup snapshot should not be passed as base64 positional arguments.
   The real startup contract should remain on the private socket so it stays bounded, versioned, and off the process list.

11. Add bounded relay semantics.
   The monitor should run one relay direction for network->worker and one for worker->network, with connection-fatal behavior on:
   - worker exit;
   - malformed or oversized IPC records;
   - transport failure;
   - monitor shutdown;
   - protocol phase violation.

### Concrete deliverables

- A process runner with PTY/non-PTY, explicit process-group ownership, bounded shutdown, and reliable reaping.
- A worker mode of the existing executable.
- A seqpacket-based monitor/worker protocol with startup, readiness, activation, and frame relay.
- Worker startup validation and identity checks.
- Auth success gated on worker readiness.

### Exit criteria

- A process cannot outlive its owning session teardown without deliberate policy.
- Local process and channel completion does not depend on peer close acknowledgment.
- The worker cannot become active for the wrong connection.
- The monitor never exposes auth success if worker startup fails.
- The worker receives no host keys, trust-file authority, or account-resolution authority.

### Verification focus

- no-reply exec requests;
- early close during startup;
- hung or malicious peers that never read or never reply to close;
- worker crash before readiness;
- worker crash after activation;
- descriptor mix-ups and malformed startup data;
- descendant-process cleanup on connection teardown.

## Recommended implementation order within the three steps

1. Finish Step 1 before attempting the worker split.
   The worker design depends on clean ownership transfer and a real post-auth readiness boundary.

2. Finish Step 2 before broadening service behavior.
   The worker should inherit a bounded, validated mux and an authorization model that already distinguishes session admission from concrete launch.

3. Start Step 3 by replacing the process runner first, then introduce the worker transport.
   The process owner is the service boundary the worker will ultimately host.

## Non-goals for this plan

- SSH wire compatibility.
- Immediate forwarding support on top of the current mux.
- Passing live Noise state across processes.
- Giving the worker authority to resolve accounts, load trust files, or choose its own permissions.
