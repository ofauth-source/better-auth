# Better Auth behavior expectations

Recorded before replacing the OAuth adapter and E2E harness for #1274.

- A changed, missing, replayed, or foreign-session callback state fails before token exchange; legitimate pending state remains usable after a foreign attempt.
- PKCE S256 and exact callback binding survive the native callback. Client authentication uses exactly one standard secret method. No secret goes to authorization URLs.
- Linking requires an existing application session. Different-email linking follows explicit application policy; linking never replaces that user's identity or signs in another user.
- The standard userinfo `id` is stable and equals `sub`. Missing identity/email fails without fabricated profile data. Unverified email remains unverified.
- Native Better Auth stores protected OAuth tokens and accepts token responses without optional OFAuth extensions. Identity, Better Auth account row ID, and selected provider account ID remain distinct.
- Independent Better Auth instances can refresh one stable credential concurrently. Lost responses and failed persistence permit retry after restart without an OFAuth table or distributed lock.
- Refresh revocation fails while the application session remains valid. Account resources enforce explicit selection and reject foreign accounts.
- A stale refresh completing after relinking/unlinking must not overwrite changed registration. Framework behavior must be measured and a failure blocks certification rather than prompting another credential manager.
- The mock issuer is an adapter simulation only. Actual OFAuth routing, provider callbacks, authority, billing, and revocation require the actual issuer integration run.
- Each run produces a repeatable redacted JSON report identifying framework version and simulated behavior. Reports must contain no tokens, secrets, codes, verifiers, cookies, or real identity data.
