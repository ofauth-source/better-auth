# OFAuth for Better Auth

Add OFAuth sign-in and account linking to your Better Auth app. People can also share creator accounts with your app.

## Install

Requires Better Auth **1.7.3 or later**.

```sh
pnpm add @ofauth/better-auth better-auth
```

For creator access and webhooks, also install the SDK. The minimum SDK version is **4.0.0**.

```sh
pnpm add @ofauth/onlyfans-sdk@^4.0.0
```

## Set up

Register your callback URL in the [OFAuth dashboard](https://app.ofauth.com), such as `https://your-app.example/api/auth/callback/ofauth`.

Add the plugin to your existing Better Auth setup. Keep your client secret on the server.

```ts
import { betterAuth } from "better-auth"
import { ofauth } from "@ofauth/better-auth"

export const auth = betterAuth({
	// Keep your existing database and session settings.
	plugins: [ofauth({
		clientId: process.env.OFAUTH_CLIENT_ID!,
		clientSecret: process.env.OFAUTH_CLIENT_SECRET!,
		scopes: ["profile:read"],
	})],
})
```

Leave out `scopes` if you only need sign-in. Better Auth handles sign-in, account linking, sessions, and tokens.

## Sign in or link an account

Use your existing Better Auth client:

```ts
await authClient.signIn.social({ provider: "ofauth", callbackURL: "/dashboard" })

// Link OFAuth to someone already signed in to your app.
await authClient.linkSocial({ provider: "ofauth", callbackURL: "/settings/accounts" })
```

The login identifies the person's OFAuth account. The creator accounts they share can change without changing their login.

## Use a creator account

In a signed-in server route, get an SDK client for the chosen creator:

```ts
import { createOFAuthAccess } from "@ofauth/better-auth/server"
import { auth } from "./auth"
import { withAccountLock } from "./account-lock"

const access = createOFAuthAccess({ auth, withAccountLock })
const client = await access.client({
	headers: request.headers,
	linkedAccountId: selectedCreatorId,
})
const profile = await client.access.profile.get()
```

`withAccountLock` is your app's shared lock. See [SDK setup](docs/sdk.md) for the lock, account selection, and error handling.

## Handle webhooks

Add [`webhooks` to the plugin config](docs/webhooks.md) to handle access changes at `/api/auth/ofauth/webhooks`.
