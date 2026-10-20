# Handle webhooks

The helper checks each webhook's signature before finding the matching Better Auth account. Your app stores the account mapping and tracks which events it has handled.

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

`authorizationBindings` is your app's store for this pair of IDs. It holds no tokens. Save the pair even if it already exists, and keep it for late webhooks.

## Add a route

For a Next.js route, export the helper as `POST`. Other Fetch-based servers can pass a `Request` to the same handler.

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
		"linked_account.expired": async ({ account, event }) => {
			await accountAccess.requireReconnect(account.userId, event.linkedAccountId)
		},
	},
})
```

The services from `./ofauth-data` belong to your app:

- `getSubject` returns the saved OFAuth account ID, or `null` if the mapping is missing.
- `webhookEvents.run` stores `eventId` so retries do not run the same update twice. It must handle each account's events in `order` and commit only after `work()` succeeds. Save the app update and event record in one database transaction.
- `accountAccess` records what the user needs to do next, such as grant access again or reconnect a creator.

Keep event streams separate using their authorization and linked-account IDs. Pass the original request to the helper before reading or parsing its body.

The helper passes the event and the matched account's `id`, `userId`, `accountId`, and `providerId` to your handler. It never passes tokens or deletes the app user's session.

Successful and unhandled events return `204`. Invalid signatures return `401`. Bad event data returns `400`. Missing account mappings return `503`, and failed handlers return `500`, so deliveries can retry.
