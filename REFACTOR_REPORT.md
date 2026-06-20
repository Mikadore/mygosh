# Command Service Refactor Report

## Summary

This milestone replaced the unused generic PTY/exec payload package with a complete command channel protocol and connected it to authentication, authorization, Unix process execution, and the CLI.

The result supports:

- interactive account shells;
- shell `-c` command execution;
- optional PTY allocation for shell or exec;
- separate non-PTY stdout and stderr;
- merged PTY output;
- stdin protocol half-close;
- terminal resize;
- allowlisted environment forwarding;
- exit status, signal, and generic runtime-failure reporting;
- cancellable local terminal input;
- explicit Unix credentials and bounded process-group cleanup.

`REVIEW.md` was deliberately not changed. It remains the historical review evidence. `TODO.md` is the living completion checklist.

## Package And Dependency Changes

The old generic command payload package was removed:

```text
lib/service/
proto/service/
```

It was replaced by:

```text
proto/command/command.proto
lib/command/
lib/command/commandpb/
app/commandchannel/
app/server/command/
app/server/process/
```

The dependency direction is now:

```text
lib/command
    pure protocol and state machines

session.Channel + lib/command
    -> app/commandchannel

app/server/command
    -> lib/command
    -> app/server/authz
    -> app/server/process
```

`lib/command` does not import session, accounts, authorization policy, TTY, filesystem, or process packages. This keeps the wire protocol independent of Unix and deployment policy and preserves the intended path to a future worker process.

## Command Wire Protocol

The new protobuf protocol uses directional envelopes carried entirely as session channel data.

Client frames are:

- `Start`;
- `Stdin`;
- `StdinEof`;
- `WindowChange`.

Server frames are:

- `StartResult`;
- `Stdout`;
- `Stderr`;
- `Exit`.

The protocol enforces:

- protocol version 1;
- exactly one shell or exec target;
- `Start` as the first client frame;
- no output before start acceptance;
- resize only for an accepted PTY command;
- no stdin after `StdinEof`;
- one terminal exit result;
- raw byte and per-stream ordering preservation;
- generic peer-visible start rejection and runtime failure;
- dynamic output and stdin chunking to the underlying frame limit.

The command protocol never uses session requests. The session adapter is the only package that understands both protocols.

## Command Client And CLI

`lib/command.Client` owns:

- one receive loop;
- one serialized writer;
- start acceptance;
- stdin, EOF, and resize operations;
- output dispatch;
- typed start-rejection, exit-status, exit-signal, runtime, and protocol errors.

The CLI now implements:

```text
mygosh connect host
mygosh connect host command args...
mygosh connect -t host command...
mygosh connect -T host
mygosh connect --env NAME --env NAME=value host
```

Behavior includes:

- default PTY selection for an interactive shell when local stdin is a terminal;
- forced or disabled PTY selection;
- raw mode only for a real local terminal;
- resize forwarding;
- PTY output to stdout;
- non-PTY stderr preservation;
- terminal restoration on every return path;
- remote status propagation;
- conventional `128 + signal` exit handling, with `255` for unknown signals or protocol/runtime failures.

The previous blocking stdin pattern was replaced with `lib/tty.PollReader`. It duplicates the input descriptor and polls it alongside a private cancellation pipe. Command completion closes the duplicate, joins the forwarding goroutine, and leaves the original stdin descriptor available to the restored local shell.

## Server Service And Authorization

Production server composition now registers `app/server/command.Service` in the credential-aware service registry.

Channel admission:

1. accepts only channel type `"command"`;
2. requires an empty open payload;
3. runs connection-level `AuthorizeChannel`;
4. starts `command.Serve` from the channel open callback;
5. rejects all session channel requests.

Start handling:

1. decodes and validates the command request;
2. converts it to `authz.LaunchRequest`;
3. calls `AuthorizeLaunch`;
4. converts the immutable `AuthorizedLaunchSpec` to a plain process specification;
5. starts the process owner;
6. sends start acceptance only after successful process start and wait ownership;
7. forwards input, output, resize, and exit state.

Permission terminology changed from `AllowSession` to `AllowCommand`. The default remains deny-by-default. Current production composition installs an explicit demo policy allowing:

- command channels;
- shell;
- exec;
- PTY;
- `TERM`;
- `COLORTERM`;
- `LANG`;
- `LC_ALL`;
- `LC_CTYPE`.

This policy is intentionally app-owned. The command protocol does not know about accounts, trust files, forced commands, or environment policy.

## Unix Process Ownership

`app/server/process.Runner` consumes an already-authorized plain-data specification containing:

- absolute executable;
- argv;
- working directory;
- trusted and requested environment;
- UID, GID, and supplementary groups;
- optional PTY settings;
- bounded termination grace.

Shell requests use the account login shell with login-shell `argv[0]`. Exec requests use the account shell with `-c`. Forced-command replacement remains an authorization decision made before the runner sees the specification.

Trusted `HOME`, `USER`, `LOGNAME`, `SHELL`, and `PATH` cannot be replaced by peer-requested environment values.

Credential handling is explicit:

- a privileged runner applies UID, GID, and groups directly;
- an unprivileged runner may launch only its current identity;
- supplementary groups must match exactly;
- unprivileged launches use `NoSetGroups`;
- mismatches fail before process creation.

PTY commands use a new session and controlling terminal. Non-PTY commands use a dedicated process group and independent pipes.

The runner:

- installs the wait owner immediately after successful start;
- calls `Wait` exactly once;
- exposes a stable repeatable wait result;
- closes stdin on cancellation;
- signals the complete process group;
- waits a bounded grace period;
- sends `SIGKILL` if necessary;
- cleans residual descendants after the group leader exits;
- does not depend on peer close acknowledgment.

PTY protocol EOF intentionally stops accepting further input without closing the bidirectional PTY descriptor or killing the process.

## Session Mux Adjustment

Testing exposed an ordering issue in the session close path: a received channel close could discard data frames that had already been queued for the application. That could erase the final command rejection or exit frame.

The channel close path now preserves already-queued data and returns EOF only after those frames are consumed. A regression test verifies that terminal channel data survives a following close.

This change is required for the command guarantee that the terminal result is observable before channel closure.

## Test Coverage Added

Pure command protocol tests cover:

- shell and exec starts;
- PTY and non-PTY modes;
- malformed and out-of-order frames;
- duplicate start and EOF behavior;
- stdin after EOF;
- resize validation;
- generic start rejection;
- typed exit status, signal, and runtime failure;
- exact raw terminal-byte preservation;
- dynamic frame chunking;
- blocked send cancellation;
- output before start acceptance.

Session-adapter tests cover:

- complete command exchange over `session.Channel`;
- no use of session requests;
- generic rejection on one command channel without closing the connection;
- independent subsequent command channels.

Real process tests cover:

- shell `-c` execution;
- stdout/stderr separation;
- PTY merged output and resize;
- stdin EOF;
- environment handling;
- explicit identity mismatch rejection;
- exit status and signal;
- cancellation of a process group;
- cleanup of background descendants after leader exit;
- stable exactly-once wait results.

CLI and TTY tests cover:

- shell/exec and PTY selection;
- environment option parsing;
- remote status and signal mapping;
- cancellation of polled input without closing original stdin.

## Verification Performed

The following completed successfully:

```sh
go test ./...
go test -race ./...
go vet ./...
```

Manual and end-to-end verification also covered:

- authenticated non-PTY exec with expected stdout;
- propagation of remote exit status 37;
- `./run-tmux.sh` authentication and interactive PTY shell;
- interactive command output;
- clean client and server status 0 after shell exit.

## Checklist Impact

The following `TODO.md` items are now complete:

- P1 — no no-reply process-start lifecycle exists;
- P2 — command completion is locally enforceable and bounded;
- P3 — process groups and descendants are terminated and reaped;
- D1 — terminal input forwarding is cancellable and joined;
- D2 — real shell and exec semantics are implemented.

B1 remains open. This milestone added substantial adversarial and end-to-end coverage, but repository-wide fuzzing, vulnerability scanning, and deterministic release-gate automation remain incomplete.

R2 and L1 also remain open. The command packages now follow the intended dependency direction and the generic service protocol was removed, but broader package-boundary and naming cleanup is still outstanding.

## Remaining Gaps

This refactor does not complete:

- a bounded multi-connection daemon;
- complete OpenSSH trust-file semantics;
- PAM account or session integration;
- configurable production command policy;
- cgroup, sandbox, or command resource-limit integration;
- endpoint/host/audit identity separation;
- port forwarding;
- reconnect or resume;
- the monitor/worker process split;
- SSH wire compatibility.

The command protocol, authorization adapter, and process specification are deliberately plain and narrow so they can move behind the deferred worker boundary without redesigning command semantics.
