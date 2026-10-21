# Better Auth verification for #1274

Package base: `ofauth-source/better-auth` `main` at `7dacef28792e58bd5f57a82c729bfc2bc3686b56`.
Task branch: `feat/1274-standard-oauth`. The monorepo copy is coordinated from `seb-lewis/ofauth-mono` issue #1274.

## Results

`pnpm check`, `pnpm build`, and `pnpm pack` pass. Two clean consumers install the archive instead of importing source. Both consumers pass TypeScript checking and six of seven public-interface E2E scenarios with PostgreSQL 16.13, Node 22.23.1, pnpm 11.5.0, and Vitest 4.1.12.

- Better Auth **1.7.3**: six pass, one fails.
- Better Auth **1.7.12**, current npm version at verification: six pass, one fails.

Passing cases cover Basic and form client authentication, signed-in different-email linking, encrypted OAuth storage, default identity policy, callback state isolation and replay, explicit account selection, two independent Node processes refreshing concurrently, lost response and process restart, failed storage and retry, and revoked refresh with the application session retained. Token responses omit `authorization_id`.

The failed case is `keeps a replacement registration when an old refresh completes after relinking`:

1. Link OFAuth to an existing app user and expire the access token.
2. Start native `/get-access-token`, pausing the issuer's refresh response.
3. Complete a fresh `/link-social` callback for the same OFAuth identity.
4. Revoke the old credential, release its in-flight response, and expire the saved access token.
5. Native renewal returns **400**, where **200** from the replacement registration is required.

The test remains a normal failure. No skip, expected-failure marker, refresh lock, or custom exchange hides the result. Artifacts contain status assertions rather than token values.

## Actual OFAuth route verification

The coordinated monorepo implementation passes five existing public-interface E2E scenarios using `createCoreApiApp`, Better Auth 1.7.3, native Generic OAuth, and a PostgreSQL database created by the complete current migration journal. The preset uses real authorization, consent, token, userinfo, account discovery, credential revocation, and authorization disconnect handlers. The redacted request trace and source hash are in `test/evidence/ofauth-core-better-auth-1.7.3.json`.

The scenarios cover zero-account sign-in, existing-user linking and account theft rejection, independent framework instances refreshing the same stable credential concurrently, retry after an unpersisted committed refresh response, a new framework instance reading ordinary persisted credentials, narrowed issuance, independent credential revocation, complete authorization disconnect, and approved Live identity-only authorization. This run imports the monorepo preset source; the separate packed-consumer runs above validate the published artifact shape. Independent OS processes and a lost socket response are tested against the simulated issuer in those package runs. These are distinct results.

Provider sessions are synthetic. This evidence does not certify staging HTTPS callbacks, actual provider login or delivery, or billing settlement. The registration-change race remains a publication blocker.

## Framework persistence finding

In the tested packages, `getValidAccessToken` calls `internalAdapter.updateAccount(account.id, updatedData)` after refresh. `updateAccount` passes only the row ID to `updateWithHooks`. The account update hook receives the new partial account and endpoint context. It cannot add an atomic comparison against the original refresh credential or registration version. A custom adapter can execute a conditional update, but the native refresh caller supplies no original token or registration version for that comparison. Reading again in a hook leaves another race between the read and write.

Sources: [Generic OAuth](https://better-auth.com/docs/plugins/generic-oauth), [database hooks](https://better-auth.com/docs/concepts/database#database-hooks), [adapter update interface](https://better-auth.com/docs/guides/create-a-db-adapter). Installed source reviewed: `dist/api/routes/account.mjs`, `dist/db/internal-adapter.mjs`, and `dist/db/with-hooks.mjs` in both tested framework versions.

A supported framework fix or independently validated ordinary application persistence policy is required before publication. The preset cannot safely fix this with configuration alone.

## Reproduce

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm check
POSTGRES_URL=postgres://ofauth:ofauth@localhost:61700/ofauth pnpm test
pnpm build
pnpm pack --out /tmp/ofauth-better-auth-1274.tgz
```

For each framework version, create a clean project outside this repository, install the archive, Better Auth at the exact version, `pg`, `vitest`, and TypeScript. Copy `test/oauth.e2e.test.ts` and `test/app-instance.mjs`. Change the test import from `../src/index` to `@ofauth/better-auth`, then run the same test command. Each run writes `test-results/oauth.e2e.json`.

`test/app-instance.mjs` also accepts actual isolated OFAuth origins through `OFAUTH_API_URL` and `OFAUTH_AUTH_URL`, plus registered confidential client credentials. It contains no mock issuer. It requires a migrated dedicated Better Auth PostgreSQL schema through `OFAUTH_TEST_SCHEMA` and emits its local HTTP port.

The E2E suite's issuer simulates owner consent and provider state. These runs do **not** certify actual OFAuth routes, authority or billing, staging provider login, HTTPS callback delivery, webhook delivery, or public package installation. The actual issuer test and the registration-change gate must pass before the coordinated greenfield release. No package was published.
