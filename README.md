# OFAuth for Better Auth

A small configuration preset for Better Auth's [Generic OAuth plugin](https://better-auth.com/docs/plugins/generic-oauth). Better Auth owns callback validation, token storage, and refresh. Keep your client secret and access tokens on your backend.

This greenfield V3 change is **not ready to publish**. The registration-change race in `test/oauth.e2e.test.ts` is a release gate: a refresh that started before relinking must not overwrite the new registration. See `test/FAILURES.md`. Local fixture tests do not certify the OFAuth issuer or staging provider callbacks.

## Configure signed-in account linking

Register your exact callback, such as `https://your-app.example/api/auth/callback/ofauth`, in OFAuth. Match Better Auth's `baseURL`, `basePath`, and trusted origins. Each Sandbox, Test, or Live client uses the same OAuth shape; its client ID selects the environment.

You can configure the stock plugin directly without this package:

```ts
import { betterAuth } from "better-auth"
import { genericOAuth } from "better-auth/plugins/generic-oauth"

export const auth = betterAuth({
  database, // Your ordinary Better Auth database adapter.
  baseURL: process.env.APP_ORIGIN!,
  account: {
    encryptOAuthTokens: true,
    accountLinking: {
      enabled: true,
      allowDifferentEmails: true,
    },
  },
  plugins: [genericOAuth({ config: [{
    providerId: "ofauth",
    clientId: process.env.OFAUTH_CLIENT_ID!,
    clientSecret: process.env.OFAUTH_CLIENT_SECRET!,
    authorizationUrl: "https://link.ofauth.com/v3/authorize",
    tokenUrl: "https://api.ofauth.com/v3/link/token",
    userInfoUrl: "https://api.ofauth.com/v3/link/userinfo",
    tokenEndpointAuth: { method: "client_secret_basic" },
    scopes: ["identity:read", "profile:read"],
    pkce: true,
  }] })],
})
```

`allowDifferentEmails: true` is a deliberate policy for linking from an existing signed-in session. Omit it if the OFAuth profile must match the application's email. Preserve your other authentication and account-linking policies. Do not mark OFAuth as a blanket trusted provider. Better Auth also checks provider email verification; the harness verifies rejection of an unverified or absent email. OFAuth must never invent an email or verified status. Guest API delegation remains available through raw OAuth without a profile-based adapter.

The equivalent preset is `plugins: [ofauth({ clientId, clientSecret, scopes: ["profile:read"] })]`, imported from `@ofauth/better-auth`. `ofauthProvider(options)` returns the same standard configuration for an existing Generic OAuth plugin. Options include `apiURL`, `authURL`, `disableSignUp`, and `tokenEndpointAuthMethod: "client_secret_basic" | "client_secret_post"`. The preset always requests `identity:read` and PKCE. Explicit endpoints are the supported configuration; OIDC and discovery are not claimed.

From the application's signed-in browser session:

```ts
await authClient.linkSocial({
  provider: "ofauth",
  callbackURL: "/settings/accounts",
})
```

Better Auth binds state to that initiating session and persists the tokens on callback. OFAuth's stable profile `id`/`sub`, the Better Auth account row ID, and a linked provider account ID have separate purposes. Linking retains the existing application user's identity.

## Obtain a token and choose a provider account

Use Better Auth's supported server token API with the current application's session headers and a Better Auth account row belonging to that user:

```ts
const accounts = await auth.api.listUserAccounts({ headers: request.headers })
const account = accounts.find(account => account.providerId === "ofauth")
if (!account) throw new Error("Connect OFAuth first")

const getAccessToken = async () => {
  const token = await auth.api.getAccessToken({
    headers: request.headers,
    body: { accountId: account.id },
  })
  return token.accessToken
}

const page = await fetch("https://api.ofauth.com/v3/linked-accounts", {
  headers: { authorization: `Bearer ${await getAccessToken()}` },
  redirect: "error",
})
if (!page.ok) throw new Error(`Account discovery failed (${page.status})`)
const linkedAccounts = await page.json()
```

Follow pagination and ask the application user to select a granted linked account. Store that selection against your own customer. If several OFAuth identities are linked, choose their Better Auth account row explicitly too. Session cookies stay on the application's backend; only the Bearer token goes to OFAuth.

```ts
const response = await fetch("https://api.ofauth.com/v3/access/profile", {
  headers: {
    authorization: `Bearer ${await getAccessToken()}`,
    "X-Linked-Account-Id": selectedLinkedAccountId,
  },
  redirect: "error",
})
```

Supply the same `getAccessToken` function to a resource SDK's token getter. The SDK must not also refresh or persist Better Auth's credentials. OFAuth returns `expires_in: 900` and a stable client-bound refresh token; Better Auth handles expiry and renewal. Concurrent renewal, a lost response, and temporary persistence failure do not require an OFAuth lock, attempt table, or renewed consent. The credential expires after 90 days without successful authenticated refresh, and earlier revocation still applies.

## Reconnect and disconnect

A provider-session failure needs targeted reconnect for the affected linked account. Start `POST /v3/linked-accounts/{id}/reconnect`, validate the return, and re-read that account. Reconnect repairs provider connectivity; it does not renew OAuth or expand approval. Never automatically replay an interrupted write.

`invalid_token` means obtain a current token through Better Auth. A rejected refresh grant requires a new authorization journey while preserving the app session. Permission and account-selection errors require the corresponding grant or selection; quota and transient errors follow their retry rules. A timeout cannot prove a provider write failed.

To end the whole authorization, call `DELETE /v3/authorization` with the current Bearer token. This ends all credentials for that authorization. To revoke one credential, use RFC 7009 at `/v3/link/revoke` with confidential client authentication and the stored refresh token. Revoking one credential leaves independent credentials intact. Unlinking a local Better Auth account alone does not revoke OFAuth's authorization; perform the OFAuth disconnect before removing the local link. Keep any background-job references to the old registration invalid after a registration change.

## Validate and package

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm check
POSTGRES_URL=postgres://ofauth:ofauth@localhost:61700/ofauth pnpm test
pnpm build
pnpm pack
```

The harness runs real Better Auth and PostgreSQL against a simulated OAuth issuer. It exercises both standard secret methods, signed-in linking policy, protected persistence, session/state isolation, simultaneous refresh, lost-response and storage-failure recovery, explicit account selection, and revocation. It deliberately fails if a stale refresh overwrites a new registration. `test-results/oauth.e2e.json` is the repeatable redacted result artifact. It omits OAuth secrets from assertions and disables framework logging.

Tested versions: Better Auth 1.7.3 (workspace pin) and 1.7.12 (current npm version at verification). Clean consumers of the packed archive pass six scenarios and fail the registration-change race on both versions. Install the packed archive in a clean consumer before release. Actual OFAuth routes, HTTPS callbacks, real provider login, and package publication remain separate release checks. Do not publish while the registration race or actual issuer acceptance is unresolved.
