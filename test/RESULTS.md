# Better Auth verification for #1274

The packed `@ofauth/better-auth` archive passes all seven public-interface scenarios on Better Auth **1.7.3** and **1.7.12**. Each consumer installs the matching exact `@better-auth/core` version. The npm registry reports 1.7.12 as the current version of both packages at verification on 2026-10-21.

## Packed consumers

Runtime source: `ofauth-source/better-auth` at `d54892f77c1d0be36f8bd8e448f6b19f7edcf213`. This review changes fixtures and evidence, with no runtime source changes. The reports in `test/evidence/better-auth-1.7.3.json` and `test/evidence/better-auth-1.7.12.json` identify the archive digest, runtime source digests, executed fixture digests, exact dependencies, and results.

`pnpm check` and packaging pass. Two fresh projects outside the checkout install the archive and pass TypeScript checking and all seven scenarios. Both independent Node processes import `ofauthAccountProtection` from the installed package alongside native Generic OAuth. They share ordinary Better Auth PostgreSQL storage.

The scenarios cover both confidential-client methods, signed-in different-email linking, encrypted token storage, identity policy, session-bound state and replay, explicit account selection, concurrent refresh, lost response and process restart, storage failure and retry, and revocation. Token responses omit the optional `authorization_id` extension. Concurrent renewals leave the original encrypted stable refresh credential unchanged.

The registration-change scenario runs against `getAccessToken`, `refreshToken`, and `accountInfo`. For each route, a refresh starts before a new linking callback replaces the credential. The old result returns 400. After the old credential is revoked, the replacement still renews successfully. These are three route checks within one of the seven scenarios.

The final matrix runs sequentially against a dedicated PostgreSQL 17.10 database. Every run uses a unique temporary schema. Cleanup removes that schema in `afterAll`, including failed runs. The fixture does not clear existing application tables.

## Actual OFAuth routes

Package fixture results simulate the OAuth issuer and provider state. They do not certify OFAuth routing, authority, billing, provider login, or staging delivery.

`test/evidence/ofauth-core-better-auth-1.7.3.json` retains the historical five-scenario actual mounted Core run at monorepo revision `1f5b12f499a523a1e38f2eb776ea592bd92593ef`.

`test/evidence/ofauth-core-followup.json` extracts the twelve passing Better Auth scenarios from the existing monorepo follow-up report at `6bf7c740`. That report uses actual mounted Core HTTP handlers and PostgreSQL, with the preset source from the monorepo. It covers registration-change rejection for all three token routes and unchanged encrypted refresh persistence. The package review did not rerun that issuer suite. The report records the original source hashes and its simulation limits.

Both issuer runs use synthetic provider connections. Neither proves staging HTTPS callbacks, actual provider login or delivery, deployed Hyperdrive behavior, billing settlement, or installation from public package registries. No package was published.

## Persistence protection

`ofauth()` includes `ofauthAccountProtection()`. Applications that configure Generic OAuth directly must add that plugin separately. See [Protect a saved connection](../ACCOUNT-UPDATES.md).

The plugin scopes an adapter to the native token update and compares the saved account identity and refresh credential in the same database write. It preserves the encrypted stable refresh token. Concurrent renewals of an unchanged registration can both succeed, while an old result cannot overwrite a replacement. Better Auth still owns callbacks, token encryption, persistence, refresh, and existing database hooks.

Select the saved Better Auth database row with `accountId: account.id`. The provider identity in `account.accountId` and the selected linked provider account have different purposes. Signed-cookie account selection is rejected for OFAuth token requests. The tested Generic OAuth callback uses a provider-specific redirect URI; explicit-endpoint configuration does not validate the returned `iss` value through Better Auth's discovery-only issuer setting. This report does not claim that check was exercised.

## Reproduce

Build before the repository test because the independent Node fixture imports the package's built entry point:

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm check
pnpm build
POSTGRES_URL="$YOUR_ISOLATED_TEST_DATABASE_URL" pnpm test
pnpm pack --out /tmp/ofauth-better-auth-1274.tgz
```

Create a fresh project outside the checkout for each framework version. Install the archive, matching exact `better-auth` and `@better-auth/core`, `pg`, Vitest, TypeScript, and the Node and PostgreSQL types. Copy `test/oauth.e2e.test.ts` and `test/app-instance.mjs`. Replace the test's `../src/index` import with `@ofauth/better-auth`. Run `pnpm check` and `pnpm test`. Each run writes `test-results/oauth.e2e.json`.

The process fixture accepts isolated actual issuer origins through `OFAUTH_API_URL` and `OFAUTH_AUTH_URL`, plus registered confidential-client credentials. It requires a dedicated migrated Better Auth schema through `OFAUTH_TEST_SCHEMA`. Its default test issuer is simulated by the E2E harness.
