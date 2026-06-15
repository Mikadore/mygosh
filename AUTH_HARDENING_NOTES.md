# Auth Hardening Notes

These notes capture the next steps for making the current file-backed authentication and authorization path more robust.

## Main direction

Keep the current `lib/auth` boundary focused on proving key ownership and extracting a `ClientIdentity`.

Build the richer policy and account-selection work around that boundary instead of pushing filesystem and local-account concerns into the auth state machine.

Model trust, account lookup, key lookup, and signing as runtime-wired services, but avoid package-global singleton registries such as `auth.UserDB` or `trust.Keystore`. The application should construct one set of trust services at startup and pass narrow interfaces into `session` and `auth`. This keeps dependencies explicit, makes tests straightforward, and leaves room for later IPC-backed helpers or privilege-separated daemon processes.

Prefer service objects that describe privilege and policy boundaries over one large keystore object:

- client-side identity/key selection
- client-side host-key verification
- server-side host-key selection
- server-side account resolution
- server-side client authorization
- signing with a selected key

The long-term auth path should treat signing as a capability, not as direct access to private key bytes. File-backed implementations can hold `keys.Keypair` internally today, but `auth` should eventually depend on a small signer interface that exposes the public key and signs a supplied payload. A future agent or daemon can then satisfy the same interface without exporting private material.

## Recommended next steps

1. Split authentication identity from local execution identity.
   `auth` should prove "this client controls this key".
   A separate authorization layer should decide whether that key is allowed.
   A separate account-resolution layer should decide which local account and session policy that identity maps to.

2. Introduce explicit provider interfaces at the auth/session boundary.
   Keep constructors in `app/client`, `app/server`, or a small app wiring package.
   Pass dependencies through config structs rather than reading package globals from deep protocol code.
   Use `context.Context` on provider methods so cancellation, deadlines, audit metadata, and future IPC calls have a natural path.

3. Split key identity from signing capability.
   Replace direct `keys.Keypair` dependencies in auth configs with a signer-style interface that can return its public key and sign deterministic payloads.
   Keep local file-backed signers as the first implementation.
   Do not require daemon-backed or agent-backed signing yet, but do not make private key bytes part of the auth protocol boundary.

4. Replace flat authorized-key matching with richer parsed entries.
   Preserve `PublicKey`, `Comment`, `Source`, and parsed options so the project can later enforce things like `from=...`, forced commands, PTY policy, and expirations without redesigning the parser.

5. Add filesystem trust checks before honoring `authorized_keys` and private-key files.
   Validate file ownership, permissions, and parent-directory safety.
   Be deliberate about symlinks and other path redirections.

6. Make username and account-selection rules explicit.
   Decide whether the requested username is authoritative, whether aliases are allowed, and whether keys identify accounts directly or only authorize a requested account.

7. Replace the current client host-key stub with a real trust store.
   The current `~/.mygosh/host_ed25519` lookup is only a temporary stand-in.
   The long-term client path should verify a presented host key against a file-backed `known_hosts` policy or another explicit trust mechanism.

8. Return structured authorization results instead of only `error` or success.
   A richer result can carry the matched key source, resolved local account, policy decisions, and rejection codes for logging and future RPC/process-separation boundaries.

9. Improve audit logging around auth decisions.
   Keep logs free of private material, but record enough detail to understand which key matched, which source file supplied it, which account was resolved, and why a request was rejected.

10. Support key rotation and multiple trust sources cleanly.
   Plan for multiple files, precedence rules, deduplication, and future revocation support.

11. Add caching only as an optimization.
   Keep file-backed lookup logic correct without caching first.
   If reload cost becomes noticeable, cache parsed entries by path and file metadata instead of coupling correctness to the cache.

12. Expand from parser tests to policy tests.
    Add coverage for wrong-user/right-key, right-user/wrong-key, missing files, bad permissions, disallowed options, host-key rotation, and multi-file resolution.

## Service Wiring Direction

Use explicit construction and dependency injection instead of hidden registries. The intended shape is:

```go
type Signer interface {
	PublicKey() keys.PublicKey
	Sign(ctx context.Context, payload []byte) (keys.Signature, error)
}

type HostKeyProvider interface {
	HostSigner(ctx context.Context, referenceIdentity string) (Signer, error)
}

type ClientIdentityProvider interface {
	ClientSigner(ctx context.Context, username string) (Signer, error)
}

type AccountResolver interface {
	Lookup(ctx context.Context, username string) (Account, error)
}

type ClientAuthorizer interface {
	Authorize(ctx context.Context, req ClientAuthorizationRequest) (ClientAuthorizationResult, error)
}

type HostKeyVerifier interface {
	VerifyHostKey(ctx context.Context, req HostKeyVerificationRequest) error
}
```

These are sketches, not final names. Keep interfaces small and define them near the package that consumes them when possible. Concrete file-backed implementations belong in `lib/trust`; app-level wiring decides which implementation is used.

If a dependency graph eventually becomes tedious to wire by hand, consider a small app container or dependency-injection library only at the application edge. Do not put a runtime service locator inside `lib/auth`, `lib/session`, or `lib/trust`.

## Process-Separation Direction

Design provider methods as if they may later cross a process boundary:

- pass `context.Context`
- return plain request/result structs
- avoid exposing private key bytes outside the implementation that owns them
- preserve structured rejection reasons for logging and future RPC replies
- keep filesystem policy, user lookup, and signing authority in replaceable implementations

The first implementation can remain simple and file-backed. The architectural goal is not daemonization now; it is keeping the boundary plain enough that daemonization later does not require rewriting the auth state machine.

## Highest-value near-term work

1. Introduce a signer abstraction and use it from auth instead of calling `keys.Keypair.Sign` directly.
2. Introduce richer `AuthorizedKeyEntry`, `ClientAuthorizer`, and account-resolution types without changing wire behavior.
3. Add a real file-backed host-key verifier for the client side.
4. Move local-user, key lookup, signing, and filesystem policy out of the app stub path and behind small plain-data interfaces.
