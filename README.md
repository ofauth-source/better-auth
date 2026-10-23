# OFAuth for Better Auth

A small configuration preset for Better Auth's [Generic OAuth plugin](https://better-auth.com/docs/plugins/generic-oauth). Better Auth owns callback validation, token storage, and refresh. Keep your client secret and access tokens on your backend.

The preset protects native token persistence when a connection changes during refresh. Packed consumers pass the registration-change checks on Better Auth 1.7.3 and 1.7.12. Local fixture tests do not certify the OFAuth issuer or staging provider callbacks. See `test/RESULTS.md` for the separate evidence and release limits.

There are two kinds of OFAuth client. **Developer apps** onboard other people's accounts and sign users in with an OFAuth identity (`identity:read`). **Operator private apps** act on your own Operator workspace. They register themselves and can only use Operator Access scopes. Use `ofauth({ mode: "operator", ... })` for those; see [Operator private apps](#operator-private-apps).

## Configure signed-in account linking

Register your exact callback, such as `https://your-app.example/api/auth/callback/ofauth`, in OFAuth. Match Better Auth's `baseURL`, `basePath`, and trusted origins. Each Sandbox, Test, or Live client uses the same OAuth shape; its client ID selects the environment.

Install matching versions of `better-auth` and `@better-auth/core`. Configure native Generic OAuth with the account-protection plugin:

```ts
import { betterAuth } from "better-auth"
import { genericOAuth } from "better-auth/plugins/generic-oauth"
import { ofauthAccountProtection } from "@ofauth/better-auth"

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
  }] }), ofauthAccountProtection()],
})
```

`allowDifferentEmails: true` is a deliberate policy for linking from an existing signed-in session. Omit it if the OFAuth profile must match the application's email. Preserve your other authentication and account-linking policies. Do not mark OFAuth as a blanket trusted provider. Better Auth also checks provider email verification; the harness verifies rejection of an unverified or absent email. OFAuth must never invent an email or verified status. Guest API delegation remains available through raw OAuth without a profile-based adapter.

The equivalent preset is `plugins: [ofauth({ clientId, clientSecret, scopes: ["profile:read"] })]`, imported from `@ofauth/better-auth`. `ofauthProvider(options)` returns the same standard configuration for an existing Generic OAuth plugin; add `ofauthAccountProtection()` alongside that plugin. The preset already includes the protection. It keeps Better Auth as the credential owner and makes native token updates conditional on the saved connection. See [Protect a saved connection](./ACCOUNT-UPDATES.md). Options include `apiURL`, `authURL`, `disableSignUp`, and `tokenEndpointAuthMethod: "client_secret_basic" | "client_secret_post"`. The developer preset always requests `identity:read` and PKCE. Explicit endpoints are the supported configuration; OIDC and discovery are not claimed.

From the application's signed-in browser session:

```ts
await authClient.linkSocial({
  provider: "ofauth",
  callbackURL: "/settings/accounts",
})
```

Better Auth binds state to that initiating session and persists the tokens on callback. OFAuth's stable profile `id`/`sub`, the Better Auth account row ID, and a linked provider account ID have separate purposes. Linking retains the existing application user's identity.

## Operator private apps

An Operator private app registers itself with RFC 7591 and may only request `access:read`, `access:write`, `access:destructive`, and `connections:manage`. It cannot request `identity:read`, so `/v3/link/userinfo` is unavailable and its tokens carry no email. The developer preset cannot complete for it. Use Operator mode:

```ts
import { betterAuth } from "better-auth"
import { ofauth, ofauthOperatorRegistration } from "@ofauth/better-auth"

const scopes = ["access:read", "connections:manage"] as const

// Optional: register this installation on first start and keep the credentials in your own storage.
const { clientId, clientSecret } = await ofauthOperatorRegistration({
  clientName: "My CRM",
  redirectURI: `${process.env.APP_ORIGIN}/api/auth/callback/ofauth`,
  reconnectReturnURI: `${process.env.APP_ORIGIN}/accounts/reconnected`, // Optional: your own reconnect return route.
  scopes: [...scopes],
  load: () => loadOFAuthCredentials(), // Return null to register.
  save: credentials => saveOFAuthCredentials(credentials), // Return the stored winner after a concurrent start.
})

export const auth = betterAuth({
  database,
  baseURL: process.env.APP_ORIGIN!,
  account: { encryptOAuthTokens: true, accountLinking: { enabled: true } },
  plugins: [ofauth({ mode: "operator", clientId, clientSecret, scopes: [...scopes] })],
})
```

Then link from the signed-in session with `authClient.linkSocial({ provider: "ofauth", callbackURL: "/settings/accounts" })`, exactly as above.

Operator mode:

- Requests only Operator scopes. `access:read` is always included; any other value, including `identity:read`, throws at configuration time. Register every scope you later request.
- Never calls userinfo. After the code exchange it calls `GET /v3/authorization` and uses that authorization `id` as the Better Auth `accountId`. It returns no name, email, or image and never claims a verified email.
- Links only from an existing session. Sign-up is disabled, and sign-in through OFAuth fails because no email is returned.
- Includes `ofauthAccountProtection()`, so token persistence is protected exactly as in developer mode.

Better Auth refuses to link a provider unless it reports a verified email or is listed in `accountLinking.trustedProviders`, and compares emails unless `allowDifferentEmails` is set. An Operator authorization has no email to verify or compare. Do not add a blanket `trustedProviders: ["ofauth"]`. Operator mode includes `ofauthOperatorLinking()`, which applies to the OFAuth callback request only. For that request it marks `ofauth` trusted and accepts the absent email. The application's configuration and every other request are unchanged. This is safe because:

- The verified-email rule protects implicit linking, where a provider email decides which local user receives an account. Here the callback state is bound to the signed-in session that started `linkSocial`, and Better Auth rejects a callback completed in another session. The account is attached only to that user.
- The non-linking callback path still requires an email before it can find or create a user. Operator mode never returns one, and also disables sign-up.
- `accountLinking.enabled: false`, `user.validateUserInfo`, and the existing "already linked to a different user" check still apply.

When configuring Generic OAuth yourself, add both plugins:

```ts
plugins: [
  genericOAuth({ config: [ofauthOperatorProvider({ clientId, clientSecret, scopes })] }),
  ofauthAccountProtection(),
  ofauthOperatorLinking(),
]
```

`ofauthOperatorRegistration()` reads `/.well-known/oauth-authorization-server/v3/link`, checks the issuer and registration endpoint, registers one exact callback with confidential `client_secret_basic` (or `tokenEndpointAuthMethod: "client_secret_post"`), and validates the response before calling `save`. An optional `reconnectReturnURI` is registered as `ofauth_reconnect_return_uri`: OFAuth accepts it only as a reconnect `redirect_uri`, never as an OAuth redirect. Registration fails if OFAuth does not echo it. Credentials registered without it keep working; to add or change it, return nothing from `load` so the installation registers again. It returns stored credentials without contacting OFAuth when `load` returns them. Registration grants nothing until a workspace member approves it. An unused registration expires after 24 hours: record `issuedAt`, mark the registration as used when the first OFAuth account is created (for example in `databaseHooks.account.create.after`), and return null from `load` for an unused one older than 24 hours. Keep the client secret private and never ship it in a public client.

Operator private apps do not include Realtime, Vault+, events, or webhooks. See the [Operator private apps guide](https://docs.ofauth.com/v3/guides/operator-apps).

## Obtain a token and choose a provider account

Use Better Auth's supported server token API with the current application's session headers and a Better Auth account row belonging to that user. Pass its database row ID as `accountId`; the provider identity in `account.accountId` is different. OFAuth token routes reject signed-cookie selection:

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

Do not use the Better Auth callback as the reconnect `redirect_uri`: Better Auth would reject the return (`?state=…&reconnect=completed`) as an unknown OAuth state. Mount your own return route and register it. A Developer app adds it to its integration's redirect URIs in the dashboard. An Operator private app passes `reconnectReturnURI` to `ofauthOperatorRegistration()`.

`invalid_token` means obtain a current token through Better Auth. A rejected refresh grant requires a new authorization journey while preserving the app session. Permission and account-selection errors require the corresponding grant or selection; quota and transient errors follow their retry rules. A timeout cannot prove a provider write failed.

To end the whole authorization, call `DELETE /v3/authorization` with the current Bearer token. This ends all credentials for that authorization. To revoke one credential, use RFC 7009 at `/v3/link/revoke` with confidential client authentication and the stored refresh token. Revoking one credential leaves independent credentials intact. Unlinking a local Better Auth account alone does not revoke OFAuth's authorization; perform the OFAuth disconnect before removing the local link. Keep any background-job references to the old registration invalid after a registration change.

## Validate and package

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm check
pnpm build
POSTGRES_URL="$YOUR_ISOLATED_TEST_DATABASE_URL" pnpm test
pnpm pack
```

The harness runs real Better Auth and PostgreSQL against a simulated OAuth issuer. It exercises both standard secret methods, signed-in linking policy, protected persistence, session/state isolation, simultaneous refresh, lost-response and storage-failure recovery, explicit account selection, and revocation. It deliberately fails if a stale refresh overwrites a new registration. `test-results/oauth.e2e.json` is the repeatable redacted result artifact. It omits OAuth secrets from assertions and disables framework logging.

Operator scenarios use a simulated Operator client that rejects non-Operator scopes and serves `GET /v3/authorization`, RFC 8414 metadata, and RFC 7591 registration. They cover requested scopes, linking without email or userinfo under the default linking policy, refused sign-in and sign-up, disabled linking, account protection after relinking, and self-registration. They pass from source on Better Auth 1.7.3 and 1.7.12; packed-consumer evidence for Operator mode is not yet recorded in `test/RESULTS.md`.

Tested versions: Better Auth 1.7.3 and 1.7.12, each with the matching `@better-auth/core` version. Fresh consumers of the packed archive pass all seven scenarios on both versions. Two independent Node processes use the installed protection plugin. The registration-change scenario exercises all three native token routes. Actual mounted OFAuth route evidence is recorded separately in `test/RESULTS.md`; those runs use synthetic provider connections. Staging HTTPS callbacks, real provider login, delivery, and public package installation remain release checks. No package was published.
