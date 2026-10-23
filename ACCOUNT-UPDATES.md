# Protect a saved connection

The `ofauth()` preset includes `ofauthAccountProtection()` in both developer and Operator mode. When you configure Generic OAuth directly with `ofauthProvider()`, `ofauthOperatorProvider()`, or explicit endpoints, add the protection plugin to your Better Auth plugins:

```ts
import { genericOAuth } from "better-auth/plugins/generic-oauth"
import { ofauthAccountProtection, ofauthProvider } from "@ofauth/better-auth"

const plugins = [
  genericOAuth({ config: [ofauthProvider(options)] }),
  ofauthAccountProtection(),
]
```

Install matching versions of `better-auth` and `@better-auth/core`. Select the saved Better Auth account with `accountId` for `getAccessToken`, `refreshToken`, and `accountInfo`. OFAuth token requests reject signed-cookie account selection.

Better Auth still checks the application session, exchanges codes, encrypts tokens, and renews access. The protection only changes the database update used by its native token routes:

1. Remember the account row read by Better Auth for this request.
2. Keep the stored stable refresh credential unchanged during renewal.
3. Save renewed access only while that same account and refresh credential remain registered.
4. Reject an old result after a callback replaces the connection or the user removes it.

The condition runs in the same database update as the write. Two independent renewals of an unchanged registration can both succeed. No refresh lock, attempt journal, extra table, or registration field is required. Existing Better Auth database hooks still run.

A rejected old request must be retried using the current saved account. Provider reconnection remains separate from OAuth renewal. Direct Generic OAuth configuration without this protection retains the framework's stale-update risk on the tested versions.
