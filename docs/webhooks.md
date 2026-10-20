# Handle webhooks

The helper checks signatures and finds the matching Better Auth account. Your app stores account mappings and handled events.

## Save the account mapping

Add `onAuthorization` to your provider setup:

```ts
ofauth({
	clientId: process.env.OFAUTH_CLIENT_ID!,
	clientSecret: process.env.OFAUTH_CLIENT_SECRET!,
	scopes: ["profile:read"],
	onAuthorization: async ({ authorizationId, ofauthAccountId }) => {
		await authorizationBindings.upsert({ authorizationId, ofauthAccountId })
	},
})
```

Your app's `authorizationBindings` store saves these IDs, including repeat saves. Keep them for late webhooks.

## Add a route

Export `POST` in Next.js, or pass a `Request` from another Fetch-based server. Pass the original request before reading its body.

```ts
import { createOFAuthWebhookHandler } from "@ofauth/better-auth/webhooks"
import { auth } from "./auth"
import { authorizationBindings, webhookEvents, accountAccess } from "./ofauth-data"

export const POST = createOFAuthWebhookHandler({
	auth,
	secret: process.env.OFAUTH_WEBHOOK_SECRET!,
	resolveAccount: (event) => authorizationBindings.getSubject(event.authorizationId),
	processEvent: (event, work) => webhookEvents.run(event, work),
	handlers: {
		"authorization.revoked": async ({ account, event }) => {
			await accountAccess.requireConsent(account.userId, event.authorizationId)
		},
	},
})
```

Implement these stores in your app:

- `getSubject`: return the saved OFAuth account ID, or `null`.
- `webhookEvents.run`: skip saved `eventId` values and process events in `order`. Keep streams separate by authorization and linked-account IDs. Save the app update and event record in one database transaction, only after `work()` succeeds.
- `accountAccess`: record when users need to grant consent again.

Add a `linked_account.expired` handler to request a creator reconnect.

Successful and unhandled events return `204`. Missing mappings return `503`; failed handlers return `500`, so OFAuth can retry.
