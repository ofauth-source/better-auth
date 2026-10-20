# Use the SDK

The server helper uses Better Auth's stored tokens. It checks that the OFAuth account belongs to the signed-in app user.

## Set up the shared lock

Pass `withAccountLock(accountId, work)` to `createOFAuthAccess`. Your app supplies this function using its database or shared lock service.

Allow only one `work()` call at a time for each Better Auth account, across all your servers. Hold the lock until the call finishes, including saving new tokens. Release it if the call fails. A lock held only in memory cannot cover several servers.

Use the same lock for any other code that refreshes OFAuth tokens, including background jobs and Better Auth's token endpoints.

## Choose an account

List the creator accounts the person shared:

```ts
const page = await access.listLinkedAccounts({ headers: request.headers })
```

Follow `next_cursor` while `has_more` is true. Pass the chosen account's `id` as `linkedAccountId` when creating a client.

You can leave out `linkedAccountId` when there is just one connected creator. With several creators, the helper asks you to choose. A client keeps its choice even if the list changes.

If the app user has several OFAuth logins, also pass `accountId`. This is the Better Auth account row ID, separate from the creator's `linkedAccountId`.

Create clients for each signed-in request. Keep tokens and client secrets on your server.

## Handle errors

If the app user is signed out, ask them to sign in. If OFAuth is not linked, or access needs to be renewed, use `authClient.linkSocial`.

`OFAuthAccessError` has a `code` and `recoveryAction`. SDK API errors use `OFAuthAPIError`, which also provides `needsReauthorization`, `needsReconnect`, and `retryAfter`.

Reconnecting a creator fixes that creator's session. Asking for consent again renews your app's access. Neither step needs to delete the app user's login.

## Provider options

- `scopes`: the creator permissions to request. Sign-in always adds `identity:read`.
- `offlineAccess: false`: sign in without asking for a refresh token.
- `disableSignUp: true`: allow existing app users only.
- `apiURL` and `authURL`: use custom API and sign-in hosts. Set the same `apiURL` on the server helper.

If you already use Better Auth's `genericOAuth`, add `ofauthProvider(options)` to its `config` array. Both provider exports come from `@ofauth/better-auth`.

To link accounts with different email addresses, enable Better Auth's `account.accountLinking.allowDifferentEmails`.
