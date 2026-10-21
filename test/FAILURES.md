# Better Auth behavior expectations

Recorded before replacing the OAuth adapter and E2E harness for #1274.

- A changed, missing, replayed, or foreign-session callback state fails before token exchange; legitimate pending state remains usable after a foreign attempt.
- PKCE S256 and exact callback binding survive the native callback. Client authentication uses exactly one standard secret method. No secret goes to authorization URLs.
- Linking requires an existing application session. Different-email linking follows explicit application policy; linking never replaces that user's identity or signs in another user.
- The standard userinfo `id` is stable and equals `sub`. Missing identity/email fails without fabricated profile data. Unverified email remains unverified.
- Native Better Auth stores protected OAuth tokens and accepts token responses without optional OFAuth extensions. Identity, Better Auth account row ID, and selected provider account ID remain distinct.
- Independent Better Auth instances can refresh one stable credential concurrently. Lost responses and failed persistence permit retry after restart without an OFAuth table or distributed lock.
- Renewal after refresh-token revocation fails while the application session remains valid. The revocation request succeeds. Account resources enforce explicit selection and reject foreign accounts.
- A stale refresh completing after relinking/unlinking must not overwrite changed registration. Framework behavior must be measured and a failure blocks certification rather than prompting another credential manager.
- The mock issuer is an adapter simulation only. Actual OFAuth routing, provider callbacks, authority, billing, and revocation require the actual issuer integration run.
- Each run produces a repeatable redacted JSON report identifying framework version and simulated behavior. Reports must contain no tokens, secrets, codes, verifiers, cookies, or real identity data.

## Packed-consumer protection verification

Record these expectations before updating the process fixture and evidence:

- Both independent Node processes import `ofauthAccountProtection` from the installed package and configure it alongside native Generic OAuth. A source-only or unprotected child process cannot certify the shipped protection.
- Concurrent protected refreshes must both succeed while leaving the original encrypted stable refresh credential unchanged. A lost response followed by a new process must still renew the saved connection.
- Every native token route (`getAccessToken`, `refreshToken`, and `accountInfo`) must reject an old refresh after relinking, retain the replacement registration, and allow its next renewal.
- Each clean consumer installs the new packed archive plus matching exact `better-auth` and `@better-auth/core` versions. Its artifact records package and fixture digests, dependency provenance, process coverage, and simulation limits.
