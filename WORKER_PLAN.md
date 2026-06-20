# Post-Authentication Session Worker

## Purpose

Move post-authentication connection handling into a dedicated worker process while keeping the long-lived server process responsible for network security and authorization.

The initial split is intended to reduce the consequences of defects in session framing, channel handling, terminal management, and process execution. It is not intended to redesign the network protocol or immediately isolate every pre-authentication operation.

This document describes the desired security boundary and operating model. It is intentionally not a file-by-file implementation plan.

## Security Model

The server monitor remains the trusted authority. It owns:

- accepted network connections;
- Noise handshake and cipher state;
- server authentication keys;
- client authentication and connection authorization;
- account and trust-source resolution;
- creation of immutable connection credentials;
- worker creation, privilege selection, supervision, and reaping;
- final network-connection closure.

The session worker is disposable and scoped to one authenticated connection. It owns:

- the post-authentication connection multiplexer;
- channel and service protocol handling;
- terminal and command-session runtime;
- peer-controlled post-authentication parsing;
- local cleanup for the work delegated to it.

The worker must not receive:

- host private keys;
- trust-file access authority;
- account-resolution authority;
- the client network descriptor;
- Noise cipher state;
- authority to choose its own UID, GID, groups, or connection permissions.

A compromised worker may disrupt its own connection and misuse authority explicitly granted to that connection. It should not be able to impersonate the server, alter authorization decisions, inspect other connections, or retain privileged server state.

## Connection Shape

The monitor keeps the encrypted network transport for the complete connection lifetime. After authentication and authorization, it starts a worker and relays decrypted protocol frames over a private IPC channel:

```text
client
  ↕ encrypted network transport
monitor
  ↕ bounded cleartext frame relay
session worker
```

The worker sees framed post-authentication protocol messages, not raw TCP bytes. The monitor does not normally need to interpret those messages; it enforces the connection phase, frame limits, relay lifecycle, and worker ownership.

This avoids transferring live Noise state between processes. Passing only the network descriptor would not be sufficient because encryption keys, nonces, and cipher counters are process-local state.

## IPC Transport

Use an anonymous Unix-domain `SOCK_SEQPACKET` socket pair for monitor/worker communication.

Sequenced-packet sockets fit the existing message-oriented protocol:

- each send produces one record;
- record boundaries are preserved by the kernel;
- one record cannot be interleaved with another writer's record;
- oversized records can be detected through truncation flags;
- stream-framing desynchronization is avoided;
- descriptors and credentials can later be attached to explicit control records.

The IPC implementation must still enforce:

- a fixed maximum packet size;
- rejection of zero-length or otherwise invalid packets;
- serialized writes;
- deadlines or bounded waits where required;
- fatal handling of truncated payload or ancillary data;
- rejection of unexpected ancillary data;
- close-on-exec behavior for every descriptor;
- clear distinction between control records and relayed session frames.

Ordinary session frames should not carry ancillary data. Descriptor passing or per-message credentials should be enabled only for explicit control operations that require them.

## Worker Startup Contract

The worker is started through a dedicated internal mode of the same executable. Using one executable does not weaken process isolation: the worker still has its own address space, process credentials, descriptors, and lifecycle.

The worker entrypoint must be narrow. It should not perform ordinary application startup such as:

- loading the main configuration file;
- opening configured log files;
- loading keys or trust files;
- creating network listeners;
- performing account lookup;
- selecting deployment policy.

It receives only the descriptors and startup data deliberately supplied by the monitor. Direct invocation without the expected inherited resources must fail closed.

The worker startup path should remain separable enough that it could later move into a dedicated executable without changing the IPC protocol.

## Startup Data

The monitor sends a bounded, versioned startup message containing the complete information required to run the authorized connection. It should contain plain data rather than in-process interfaces or objects.

The startup snapshot includes, as applicable:

- IPC protocol version;
- monitor-generated connection identifier;
- worker launch nonce;
- binding to the authenticated network connection;
- authentication method and client-key identity;
- requested and resolved account identity;
- UID, primary GID, supplementary groups, home directory, and login shell;
- matched policy or audit source;
- connection-level permissions and constraints;
- selected service configuration;
- session protocol limits and timeouts.

Derived values should either be omitted or independently recomputed. Mutable values must be copied when accepted into worker state.

The startup format should support deliberate evolution. Unknown security-significant behavior must not become enabled merely because a newer sender supplied an unfamiliar field or flag.

## Independent Worker Validation

The monitor is authoritative, but the worker must validate its input before constructing protocol or process state. This protects against programming errors, descriptor mix-ups, version skew, malformed IPC, and accidental privilege mismatches.

### Envelope and bounds

The worker verifies:

- supported IPC version and message type;
- presence of all required fields;
- total message and individual field limits;
- bounded string, slice, group, environment, and permission counts;
- exactly one startup message;
- absence of session traffic before startup completion;
- acceptable handling of unknown fields.

### Connection and launch binding

The worker verifies:

- a non-empty connection identifier;
- a fresh monitor-generated launch nonce;
- a binding value associated with the authenticated connection;
- consistency between startup, readiness, and activation messages;
- that messages received after startup belong to the same connection.

The worker does not receive or reconstruct Noise state. A digest or exporter-derived binding is sufficient to prevent accidental association with another connection.

### Credential consistency

The worker verifies:

- a supported authentication method;
- a valid public key and a recomputed matching fingerprint;
- non-empty, bounded requested and resolved usernames;
- valid UID and primary GID values;
- bounded and unique supplementary groups;
- an absolute, normalized home directory;
- an absolute login shell when supplied;
- presence of required audit or policy-source information;
- internal consistency between account, permission, and launch data.

The worker cannot independently prove that authentication or trust-file matching occurred. It validates that the monitor's decision is coherent, bound to this launch, and safe to enforce.

### Permissions and limits

The worker verifies:

- only recognized permission flags are present;
- service permissions and constraints do not conflict;
- disabled capabilities have no active subordinate constraints;
- forced-command and command-selection rules are coherent;
- environment requests are bounded and allowlisted;
- monitor-provided resource limits do not exceed worker-compiled hard maxima;
- the worker cannot be instructed to launch as an identity different from its credential snapshot.

Configuration may tighten compiled limits but must not disable mandatory safety bounds.

### Process state and descriptors

Before processing session frames, the worker verifies:

- its effective UID, GID, and supplementary groups match the supplied account snapshot;
- it is not unexpectedly privileged;
- required descriptors exist and have the expected Unix socket type;
- the IPC endpoint is connected;
- unintended inherited descriptors have been closed;
- inherited environment is replaced or filtered;
- unsafe dynamic-loader and execution variables are absent;
- shell and working-directory values are absolute and policy-derived.

Any mismatch terminates the worker before it acknowledges readiness.

## Startup and Activation Sequence

Authentication success must not be exposed to the client until a usable worker exists.

The intended sequence is:

1. the monitor completes cryptographic authentication and connection authorization;
2. the monitor creates the IPC socket pair and starts a worker under the authorized process credentials;
3. the monitor sends the startup snapshot;
4. the worker validates startup data, descriptors, process credentials, and hard limits;
5. the worker constructs its session runtime without processing peer frames;
6. the worker returns a readiness acknowledgment containing the connection identifier and launch nonce;
7. the monitor commits authentication success to the client;
8. the monitor activates frame relay to the worker;
9. the worker begins post-authentication protocol processing.

The state transition must prevent:

- a worker from receiving frames before validation;
- a worker from becoming active for the wrong connection;
- an authentication success response when worker startup failed;
- repeated startup or activation;
- post-authentication frames from being delivered to an obsolete process.

The monitor may use a strictly bounded queue during the transition. It must not allow unbounded client input while waiting for worker readiness.

## Relay Behavior

The monitor runs one relay in each direction:

- decrypt one network frame and send one IPC record;
- receive one IPC record and encrypt one network frame.

Relay termination is connection-fatal. Conditions include:

- client disconnect;
- Noise encryption, decryption, or network write failure;
- malformed or oversized IPC packet;
- worker exit or crash;
- IPC closure or timeout;
- monitor shutdown;
- protocol phase violation.

Cancellation must stop both relay directions, close the relevant endpoints, terminate the worker when necessary, and converge on one terminal connection result.

The monitor remains the final owner of the network connection. The worker owns only its IPC endpoint and local session runtime.

## Worker Privileges

Prefer launching the worker directly with the resolved account's UID, primary GID, and supplementary groups. The worker should verify the applied identity before acknowledging readiness.

Starting under the final identity is preferable to retaining privilege and changing identity later because it reduces the amount of worker code that executes with server authority.

Additional restrictions may be introduced after the initial split:

- process and descriptor limits;
- memory and CPU limits;
- filesystem restrictions;
- namespace isolation;
- restricted system-call policy;
- independent process group or cgroup ownership.

These restrictions should be based on trusted monitor policy, never directly on peer input.

## Session Authorization and Leases

In-process authorization objects and closeable lease objects cannot be transferred directly to the worker.

The initial worker model may use a complete immutable permission snapshot when session authorization is a non-blocking no-op. The boundary must nevertheless leave room for monitor-owned request authorization:

```text
worker → monitor: authorize/open session request
monitor → worker: decision and lease identifier
worker → monitor: close lease
```

This RPC becomes necessary for PAM session lifecycle, monitor-owned resources, or authorization decisions that must remain privileged.

The monitor owns the authoritative lease. It closes the lease when:

- the channel completes;
- the worker reports closure;
- the worker exits unexpectedly;
- the client disconnects;
- the server shuts down.

Lease closure must be idempotent and must not depend on successful peer acknowledgment.

## Process and Session Lifecycle

The worker split must include basic lifecycle correctness rather than treating it as later polish:

- bounded worker startup;
- readiness and activation acknowledgments;
- worker process reaping;
- cancellation propagation;
- connection close on worker failure;
- worker termination on monitor or client shutdown;
- no orphaned workers;
- no inherited listener, key, trust, or unrelated connection descriptors;
- bounded graceful shutdown followed by forced termination;
- clear logging of monitor, relay, worker, and peer termination causes.

The session worker should ultimately own the full lifetime of commands it starts, including PTYs, pipes, child process groups, waits, signals, and descriptor cleanup.

## Logging and Audit

The monitor should produce authoritative connection and authorization audit events. The worker may emit connection-scoped operational events over stderr or a dedicated IPC channel.

Logging must not grant the worker access to arbitrary monitor-configured filesystem paths. Worker messages should be tagged by the monitor with trusted connection and process identifiers rather than relying solely on worker-supplied metadata.

Peer-visible errors remain generic. Detailed worker startup, credential, process, and policy failures stay in server-side logs.

## Expected Security Benefit

The split contains defects in:

- post-authentication protobuf and channel parsing;
- session state handling;
- terminal request handling;
- command and PTY runtime;
- service-specific logic;
- most peer-controlled activity after authentication.

A compromised worker should be limited to the authenticated account and permissions of one connection.

The split does not isolate:

- Noise and encrypted framing;
- authentication message parsing;
- host-key use;
- account and trust-file resolution;
- connection authorization;
- vulnerabilities in the long-lived monitor before worker startup.

Separating authentication into its own disposable process remains a possible later hardening step. That design should keep host-key and credential-minting authority in a minimal monitor rather than giving an auth parser unrestricted authority.

## Delivery Strategy

Perform only the boundary work needed to make the process split coherent, then establish an end-to-end worker path early.

Useful prerequisites are:

- the existing transport-neutral framed-connection interface;
- the existing protocol encoding outside the Noise transport package;
- a versioned plain-data startup and credential representation;
- removal of concrete in-process authorization dependencies from session startup;
- a dedicated worker entrypoint;
- explicit monitor and worker ownership rules.

The first complete slice should preserve the existing authenticated PTY demonstration while moving post-authentication handling into the worker.

After that concrete shape exists, continue hardening:

- connection-wide mux limits;
- process-group termination and reaping;
- non-PTY execution and explicit shell requests;
- PAM session lifecycle;
- request-specific authorization RPC;
- daemon accept-loop concurrency and admission control;
- broader monitor minimization;
- optional auth-worker separation.

## Non-Goals for the Initial Split

- exporting or reconstructing live Noise cipher state;
- giving the worker the client network descriptor;
- redesigning the external wire protocol;
- implementing PAM or complete native NSS support;
- adding port forwarding;
- creating a generic plugin framework;
- solving every process sandboxing concern in the first worker version;
- splitting every server responsibility into a separate process immediately.

The initial goal is a credible, testable post-authentication security boundary with clear ownership and failure behavior.

## Verification Expectations

Testing should cover:

- successful authenticated worker startup and PTY operation;
- worker readiness before authentication success;
- malformed, oversized, truncated, repeated, and out-of-order IPC records;
- credential and connection-binding mismatch;
- incorrect UID, GID, supplementary groups, or inherited descriptors;
- worker startup timeout and crash;
- client disconnect during startup and active relay;
- monitor shutdown;
- relay failure in either direction;
- worker termination and child reaping;
- generic peer-visible rejection;
- idempotent lease and connection cleanup;
- exact preservation of terminal payload bytes.

The process boundary should be tested with real subprocesses and inherited socket-pair descriptors, not only in-memory adapters.
