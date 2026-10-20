# Handle webhooks

Add `webhooks` to your Better Auth plugin config. The plugin checks signatures and finds the matching account.

## Set up

```ts
import { ofauth } from "@ofauth/better-auth"
import { authorizationBindings, webhookEvents, accountAccess } from "./ofauth-data"

// Inside betterAuth({ plugins: [...] })
ofauth({
	clientId: process.env.OFAUTH_CLIENT_ID!,
	clientSecret: process.env.OFAUTH_CLIENT_SECRET!,
	scopes: ["profile:read"],
	onAuthorization: async ({ authorizationId, ofauthAccountId }) => {
		await authorizationBindings.upsert({ authorizationId, ofauthAccountId })
	},
	webhooks: {
		secret: process.env.OFAUTH_WEBHOOK_SECRET!,
		resolveAccount: (event) => authorizationBindings.getSubject(event.authorizationId),
		processEvent: (event, work) => webhookEvents.run(event, work),
		handlers: {
			"authorization.revoked": async ({ account, event }) => {
				await accountAccess.requireConsent(account.userId, event.authorizationId)
			},
		},
	},
})
```

Set your OFAuth webhook URL to `https://your-app.example/api/auth/ofauth/webhooks`. It uses your existing Better Auth route. If you changed Better Auth's base path, use that path instead of `/api/auth`.

Implement these stores in your app:

- `authorizationBindings`: save the IDs from `onAuthorization`, including repeat saves. Keep them for late webhooks.
- `getSubject`: return the saved OFAuth account ID, or `null`.
- `webhookEvents.run`: skip saved `eventId` values and process events in `order`. Keep streams separate by authorization and linked-account IDs. Save the app update and event record in one database transaction, only after `work()` succeeds.
- `accountAccess`: record when users need to grant consent again.

Add a `linked_account.expired` handler to request a creator reconnect.

Successful and unhandled events return `204`. Missing mappings return `503`; failed handlers return `500`, so OFAuth can retry.
