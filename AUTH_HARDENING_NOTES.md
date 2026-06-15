# Auth Hardening Notes

These notes capture the next steps for making the current file-backed authentication and authorization path more robust.

## Main direction

Keep the current `lib/auth` boundary focused on proving key ownership and extracting a `ClientIdentity`.

Build the richer policy and account-selection work around that boundary instead of pushing filesystem and local-account concerns into the auth state machine.

## Recommended next steps

1. Split authentication identity from local execution identity.
   `auth` should prove "this client controls this key".
   A separate authorization layer should decide whether that key is allowed.
   A separate account-resolution layer should decide which local account and session policy that identity maps to.

2. Replace flat authorized-key matching with richer parsed entries.
   Preserve `PublicKey`, `Comment`, `Source`, and parsed options so the project can later enforce things like `from=...`, forced commands, PTY policy, and expirations without redesigning the parser.

3. Add filesystem trust checks before honoring `authorized_keys` and private-key files.
   Validate file ownership, permissions, and parent-directory safety.
   Be deliberate about symlinks and other path redirections.

4. Make username and account-selection rules explicit.
   Decide whether the requested username is authoritative, whether aliases are allowed, and whether keys identify accounts directly or only authorize a requested account.

5. Replace the current client host-key stub with a real trust store.
   The current `~/.mygosh/host_ed25519` lookup is only a temporary stand-in.
   The long-term client path should verify a presented host key against a file-backed `known_hosts` policy or another explicit trust mechanism.

6. Return structured authorization results instead of only `error` or success.
   A richer result can carry the matched key source, resolved local account, policy decisions, and rejection codes for logging and future RPC/process-separation boundaries.

7. Improve audit logging around auth decisions.
   Keep logs free of private material, but record enough detail to understand which key matched, which source file supplied it, which account was resolved, and why a request was rejected.

8. Support key rotation and multiple trust sources cleanly.
   Plan for multiple files, precedence rules, deduplication, and future revocation support.

9. Add caching only as an optimization.
   Keep file-backed lookup logic correct without caching first.
   If reload cost becomes noticeable, cache parsed entries by path and file metadata instead of coupling correctness to the cache.

10. Expand from parser tests to policy tests.
    Add coverage for wrong-user/right-key, right-user/wrong-key, missing files, bad permissions, disallowed options, host-key rotation, and multi-file resolution.

## Highest-value near-term work

1. Introduce richer `AuthorizedKeyEntry`, `ClientAuthorizer`, and account-resolution types without changing wire behavior.
2. Add a real file-backed host-key verifier for the client side.
3. Move local-user and filesystem policy out of the app stub path and behind small plain-data interfaces.
