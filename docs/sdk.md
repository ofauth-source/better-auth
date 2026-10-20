# Use the SDK

The server helper uses Better Auth's tokens for the signed-in user.

## Set up the shared lock

Supply `withAccountLock(accountId, work)` using your database or shared lock service. Run one `work()` call per account at a time across all servers. Hold the lock until `work()` finishes, including saving tokens. Release it on failure. All token refresh paths must use this lock, including background jobs and Better Auth's token endpoints.

## Choose an account

List shared creator accounts:

```ts
const page = await access.listLinkedAccounts({ headers: request.headers })
```

Follow `next_cursor` while `has_more` is true. Use the chosen `id` as `linkedAccountId`. You can omit it if only one creator is connected.

For users with several OFAuth logins, also pass `accountId` (the Better Auth account row ID). Create clients per request and keep tokens on the server.

## Handle errors

Check `OFAuthAccessError.code` and `.recoveryAction`. SDK errors use `OFAuthAPIError`, with `needsReauthorization`, `needsReconnect`, and `retryAfter`.

Ask signed-out users to sign in. Use `authClient.linkSocial` to link OFAuth or renew consent. Reconnect a creator to restore that creator's session.

## Provider options

- `scopes`: creator permissions. Sign-in adds `identity:read`.
- `offlineAccess: false`: skip refresh tokens.
- `disableSignUp: true`: existing app users only.
- `apiURL` and `authURL`: custom hosts. Match `apiURL` on the server helper.

With `genericOAuth`, add `ofauthProvider(options)` from `@ofauth/better-auth` to its `config` array.

To link accounts with different email addresses, enable Better Auth's `account.accountLinking.allowDifferentEmails`.
