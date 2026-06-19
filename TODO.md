# v0.1 Interactive Session TODO

The repository now has one working provisional PTY session over the
authenticated session/channel layer. Keep the next work deliberately narrow:
one interactive channel, no reconnect, no SSH compatibility, and no broad
remote execution policy.

## Release Blockers

- Replace the provisional execution privilege behavior with an explicit policy.
  - The demo currently uses the authorized account UID, GID, supplementary
    groups, home, and a small environment.
  - Cross-user execution currently succeeds only when the server process
    already has permission to assume those credentials.
  - Add a policy-driven privileged launcher or equivalent privilege separation
    before treating cross-user/root service mode as production-ready.

- Wire `lib/strictfiles` into all trust-file reads.
  - Protect host and client private keys, `known_hosts`, and `authorized_keys`
    against unsafe ownership, permissions, symlinks, and path replacement.
  - Validate directory components such as `.mygosh` and `.ssh`.
  - Support checking files owned by the resolved target account rather than
    assuming the process effective UID.
  - Apply hard read-size limits through the checked descriptor.
  - Tighten `known_hosts` marker behavior, especially revoked and unsupported
    marker entries.

- Fix transport send-state handling.
  - Reject oversized plaintext before Noise encryption advances its nonce.
  - Treat encryption/write failures as fatal to the transport so the peers
    cannot continue with desynchronized state.

- Harden session/channel resource and protocol handling.
  - Reject or safely handle empty channel-data frames.
  - Add limits for open channels, queued frames/bytes, and pending requests.
  - Detect duplicate peer channel IDs.
  - Remove canceled channel opens and requests from pending state.
  - Ensure an accepted channel cannot send data before its open-success reply.
  - Keep the receive loop non-blocking by handing work to bounded channel-owned
    runtimes or queues.

- Build a real PTY process owner.
  - Own the `exec.Cmd`, PTY descriptor, process group, wait result, and cleanup.
  - Reap every child exactly once.
  - Terminate the process group on channel close or connection loss, with a
    bounded graceful wait followed by forced termination.
  - Send exit status, EOF, and channel close in a defined order.
  - Validate and synchronize resize requests.

## Implemented Interactive Demo Wiring

- The demo defines constants and validated protobuf payloads for:
  - the `session` channel;
  - PTY allocation;
  - shell start;
  - window changes;
  - exit status.

- The client:
  - start `Session.Run` and wait until it is ready;
  - open one `session` channel;
  - request a PTY using the local terminal type and dimensions;
  - requests an explicit command, defaulting to client `core.shell`;
  - enter raw mode and copy terminal bytes unchanged in both directions;
  - forward resize events;
  - receive exit status and always restore the local terminal.

- The server:
  - accept only the v0.1 `session` channel and valid request ordering;
  - uses the account returned by client-key authorization;
  - launches `core.shell -c <command>` behind a channel-owned PTY runtime;
  - bridge PTY bytes without transformation;
  - close the process and channel cleanly on EOF, disconnect, or cancellation.

## App And Lifecycle Work

- Load and validate long-lived server key material before opening the listener.
- Replace the one-connection server with a bounded accept loop and scoped
  per-connection goroutines.
- Close listeners, connections, sessions, PTYs, and child processes during
  graceful shutdown.
- Disable console logging while the client terminal is in raw mode while
  retaining configured logfile output.
- Use a container-specific listen address; the current localhost setting is
  unsuitable for a Docker-published port.

## Protocol And Policy Cleanup

- Add practical size and character limits for usernames, reference identities,
  terminal names, commands, payloads, and peer-visible error messages.
- Return generic authentication failures to peers while keeping detailed
  reasons in server logs.
- Validate that successful authorization returns a complete and internally
  consistent local account.
- Require non-zero PTY rows and columns and constrain terminal-name input.
- Keep authentication, account authorization, execution permissions, and
  channel behavior as separate decisions.

## Tests And Release Checks

- Make `go test -race ./...` a release gate.
- Add malicious-session tests for duplicate IDs, empty-frame flooding, queue
  limits, invalid ordering, cancellation cleanup, and post-close traffic.
- Add `lib/tty` tests for resize behavior, restoration, child reaping, process
  termination, and exit status.
- Add end-to-end tests covering authentication, PTY allocation, byte-preserving
  terminal I/O, resize forwarding, shell exit, and disconnect cleanup.
- Run `govulncheck ./...` as a release check.
- Upgrade the declared and container Go version from 1.26.2 to at least 1.26.4
  to include current standard-library security fixes.

## Deferred Until After v0.1

- Multiple simultaneous channel types.
- Environment and agent forwarding.
- Reconnect or session resume.
- Escape sequences such as `~.`.
- Cross-user/root service mode without privilege separation.
