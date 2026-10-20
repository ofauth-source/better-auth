# OFAuth for Better Auth

Sign in with OFAuth, link OFAuth to an existing app user, and use a typed SDK client for the creator accounts they share. The login identifies the **person's OFAuth account**. Creator accounts remain separate and can change without changing that identity.

`ofauth` configures [Better Auth's Generic OAuth integration](https://better-auth.com/docs/plugins/generic-oauth). Better Auth owns OAuth, account linking, sessions, and token persistence. The package's server entry points connect that machinery to the OFAuth SDK and verified webhooks.

## Release status

This package is unpublished. Its server and webhook helpers require `@ofauth/onlyfans-sdk` 4.0.0 or later in the 4.x series. SDK 4.0.0 is not yet available on npm. The helpers have been tested against its current source build. Login-only apps do not need the SDK.

The OFAuth deployment must support `identity:read` and `GET /v3/link/userinfo`. Hosted availability has not been verified.

For local evaluation, build and pack this package, then install its archive in your app:

```sh
pnpm add /path/to/ofauth-better-auth-0.1.0.tgz better-auth
# For SDK and webhook helpers, also install the SDK 4 archive:
pnpm add /path/to/ofauth-onlyfans-sdk-4.0.0.tgz
```

After both npm releases:

```sh
pnpm add @ofauth/better-auth better-auth
# Optional, for creator access and webhooks:
pnpm add @ofauth/onlyfans-sdk@^4.0.0
```

## Configure Better Auth

Requires Better Auth 1.7.3 or later in the 1.x series. Register `https://your-app.example/api/auth/callback/ofauth` as an exact OFAuth redirect URI. Adjust the prefix for a custom Better Auth `basePath`.

```ts
import { betterAuth } from "better-auth"
import { ofauth } from "@ofauth/better-auth"

export const auth = betterAuth({
	// Keep your existing database, session, and authentication options.
	plugins: [
		ofauth({
			clientId: process.env.OFAUTH_CLIENT_ID!,
			clientSecret: process.env.OFAUTH_CLIENT_SECRET!,
			purpose: "Sign in to Example",
		}),
	],
})
```

Keep the client secret on your server. Live requires an approved purpose matching `purpose`. Omit `purpose` for Test clients. The client ID selects Test or Live; Sandbox credentials cannot identify a person. Test authorization follows OFAuth's developer membership and trial requirements.

Browser authorization uses `https://auth.ofauth.com/link/authorize`. Token exchange and refresh use `https://api.ofauth.com/v3/link/token`. Identity comes from `/v3/link/userinfo`. For a custom deployment, set `authURL` and `apiURL` to the corresponding HTTPS origins. No `resource` parameter is sent.

The default scopes are `identity:read` and `offline_access`. Set `offlineAccess: false` for login without refresh tokens. Add creator scopes only when your app needs them:

```ts
ofauth({
	clientId: process.env.OFAUTH_CLIENT_ID!,
	clientSecret: process.env.OFAUTH_CLIENT_SECRET!,
	purpose: "Read the creator profiles you share",
	scopes: ["profile:read"],
})
```

If your app already registers `genericOAuth`, put `ofauthProvider(options)` in its `config` array instead of adding another generic OAuth plugin. Both exports come from `@ofauth/better-auth`.

## Sign in or link an account

Use your existing Better Auth client. No client plugin is required:

```ts
await authClient.signIn.social({ provider: "ofauth", callbackURL: "/dashboard" })

// For an existing signed-in app user:
await authClient.linkSocial({ provider: "ofauth", callbackURL: "/settings/accounts" })
```

Sign-in alone needs no creator grant. Set `disableSignUp: true` to restrict sign-in to existing app users. Better Auth keeps its configured signup and account-linking policies.

To link different app and OFAuth email addresses, explicitly enable Better Auth's `account.accountLinking.allowDifferentEmails`. The provider does not add OFAuth to `trustedProviders` or treat an unverified OFAuth email as verified.

Keep the server scope set consistent across sign-in and re-consent. Re-consent can replace existing creator grants.

## Get a typed SDK client

Create the bridge once alongside your Better Auth instance:

```ts
import { createOFAuthAccess } from "@ofauth/better-auth/server"
import { auth } from "./auth"
import { withAccountLock } from "./account-lock"

export const ofauthAccess = createOFAuthAccess({ auth, withAccountLock })
```

`withAccountLock(accountId, work)` is app-supplied infrastructure. It must serialize `work()` for each Better Auth account row across every app instance. Keep the lock valid until the callback settles, including token persistence, and release it on failure. An in-memory mutex does not coordinate multiple servers.

In an authenticated server route:

```ts
const client = await ofauthAccess.client({
	headers: request.headers,
	linkedAccountId: selectedCreatorId,
})
const profile = await client.access.profile.get()
```

`profile` has the SDK's response type. There is no provider-row lookup, bearer-token copying, SDK `TokenManager`, or second token store in your app code. Native SDK errors, recovery actions, pagination, and retry rules are preserved.

To populate a creator selector:

```ts
const page = await ofauthAccess.listLinkedAccounts({ headers: request.headers })
```

Follow `next_cursor` while `has_more` is true. Omit `linkedAccountId` only when exactly one connected creator is available. The bridge scans SDK account discovery and rejects an ambiguous choice before an account-specific request. A created client keeps its chosen account across refreshes and list-order changes. If access to that creator is removed, the API returns a recovery error instead of selecting another creator.

Pass `accountId` when selecting among several OFAuth identities linked to the app user. This is the **Better Auth account row ID**. `linkedAccountId` is the **creator connection ID**. The bridge checks ownership and binds the SDK client to the selected Better Auth row.

The SDK's access-token provider delegates to Better Auth under the shared lock. After an `invalid_token` response, it reuses a newer stored token or asks Better Auth to refresh. The package never retries a failed token exchange itself. Session cookies stay inside the app; bearer tokens stay on the configured API origin; redirects are not followed. Unsigned HTTPS upload requests can use the SDK's upload destinations.

For custom deployments, use the same `apiURL` in the provider and bridge. Create SDK clients per authenticated request rather than caching a user's request headers across sessions. Route other refresh-capable OFAuth paths through the same lock, including background work and exposed Better Auth token/account-info endpoints. The provider does not intercept those endpoints.

## Recover account access

The bridge preserves Better Auth's signed-out errors. Handle a `401` by asking the person to sign in to your app.

`OFAuthAccessError` from `@ofauth/better-auth/server` has `code` and `recoveryAction` fields:

| Code | Action |
| --- | --- |
| `ofauth_account_not_linked` | Start Better Auth's `linkSocial` flow. |
| `ofauth_account_selection_required` | Select a Better Auth account row explicitly. |
| `linked_account_selection_required` | Show the shared creator accounts and select one. |
| `no_connected_linked_account` | List the creator accounts and connect or reconnect one. |
| `ofauth_token_unavailable` | Request consent again through `linkSocial`. |

For API failures, use `OFAuthAPIError` from `@ofauth/onlyfans-sdk` and its `recoveryAction`, `needsReauthorization`, `needsReconnect`, and `retryAfter` fields. A creator reconnect repairs its provider session; re-consent repairs the app's OFAuth authorization. Preserve the app user's identity and session in both cases.

Better Auth hides the underlying token exchange failure. `ofauth_token_unavailable` can also follow a transient failure and does not prove revocation. Re-consent avoids replaying a refresh token that may already have rotated remotely.

## Handle webhooks

Webhook deliveries use a destination signing secret, not an app user's session cookie. They identify an OFAuth authorization. Record its association with the person's OFAuth subject through the provider's metadata callback:

```ts
import { authorizationBindings } from "./ofauth-data"

ofauth({
	clientId: process.env.OFAUTH_CLIENT_ID!,
	clientSecret: process.env.OFAUTH_CLIENT_SECRET!,
	purpose: "Read the creator profiles you share",
	scopes: ["profile:read"],
	onAuthorization: async ({ authorizationId, ofauthAccountId }) => {
		await authorizationBindings.upsert({ authorizationId, ofauthAccountId })
	},
})
```

`authorizationBindings` is an app-owned metadata store. Upsert this pair idempotently; it contains no credentials. The callback runs after OFAuth profile validation and before Better Auth finishes sign-in or linking. A failed metadata write aborts that flow. The callback does not certify that Better Auth has linked the account yet.

Export the webhook handler from a Fetch-compatible route, such as a Next.js `POST` route:

```ts
import { createOFAuthWebhookHandler } from "@ofauth/better-auth/webhooks"
import { auth } from "./auth"
import { authorizationBindings, webhookEvents, accountAccess } from "./ofauth-data"

export const POST = createOFAuthWebhookHandler({
	auth,
	secret: process.env.OFAUTH_WEBHOOK_SECRET!,
	resolveAccount: async (event) => {
		return await authorizationBindings.getSubject(event.authorizationId)
	},
	processEvent: (event, work) => webhookEvents.run(event, work),
	handlers: {
		"authorization.revoked": async ({ account, event }) => {
			await accountAccess.requireConsent(account.userId, event.authorizationId)
		},
		"linked_account.expired": async ({ account, event }) => {
			await accountAccess.requireReconnect(account.userId, event.linkedAccountId)
		},
	},
})
```

The imports from `./ofauth-data` are app-owned storage operations. `getSubject` returns the OFAuth subject or `null`, not a Better Auth user ID. The helper resolves exactly one OFAuth provider row and passes only its `id`, `userId`, `accountId`, and `providerId` to the typed handler. Tokens are never included.

`webhookEvents.run(event, work)` must durably deduplicate `eventId`, serialize each event stream, and enforce the stream's `order`. Use the authorization and linked-account identifiers to distinguish streams. Commit processing only after `work()` succeeds; thrown work must remain retryable. Run business updates and the event checkpoint in the same app transaction. Keep authorization-binding metadata available for late revocation deliveries.

The helper uses the SDK to verify the raw body, signature, and timestamp before any account lookup. It returns `401` for failed verification, `400` for a malformed envelope, `503` while a binding/account is missing or ambiguous, `500` when processing fails, and `204` after processing succeeds. Unhandled event types return `204`. A delivery arriving before the Better Auth account exists can therefore retry. Route framework requests to the handler before parsing their body.

Webhook handlers update your app's access/recovery state. They do not unlink the Better Auth account, sign out the app user, or change stored OAuth tokens.

## Verify

```sh
pnpm install --frozen-lockfile
# Install the SDK 4 peer from npm or a local SDK archive before the full checks.
pnpm check
pnpm test
pnpm build
pnpm pack
```

The HTTP scenarios exercise Better Auth, typed SDK operations, creator selection, refresh coordination, and signed webhook handling. Their report is `test-results/oauth.e2e.json`. The local OAuth fixture checks compatibility; it does not prove hosted availability. The package archive contains only the package manifest, README, and built public entry points.
