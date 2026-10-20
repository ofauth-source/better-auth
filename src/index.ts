import { genericOAuth, type GenericOAuthConfig } from "better-auth/plugins/generic-oauth"
import { origin } from "./origin"
import { ofauthWebhookEndpoint, type OFAuthWebhookOptions } from "./webhooks"

export type { OFAuthWebhookAccount, OFAuthWebhookHandlers, OFAuthWebhookOptions } from "./webhooks"

export type OFAuthOptions = {
	clientId: string
	clientSecret: string
	/** Additional creator permissions. Sign-in always requests identity:read. */
	scopes?: string[]
	/** Request refresh tokens. Defaults to true. */
	offlineAccess?: boolean
	/** Defaults to https://api.ofauth.com. */
	apiURL?: string
	/** Defaults to https://auth.ofauth.com. */
	authURL?: string
	disableSignUp?: boolean
	/** Store authorization-to-person metadata for verified webhook routing. Contains no tokens. */
	onAuthorization?: (authorization: { authorizationId: string; ofauthAccountId: string }) => void | Promise<void>
	/** Receive signed webhooks at /api/auth/ofauth/webhooks. */
	webhooks?: OFAuthWebhookOptions
}

/** Use inside genericOAuth({ config: [ofauthProvider(options), ...] }). */
export function ofauthProvider(options: Omit<OFAuthOptions, "webhooks">): GenericOAuthConfig<"ofauth"> {
	if (!options.clientId.trim() || !options.clientSecret.trim()) throw new Error("OFAuth client credentials are required")
	if (!/^ofext_(test|live)_[A-Za-z0-9_-]{32}$/.test(options.clientId)) throw new Error("OFAuth sign-in requires Test or Live client credentials")
	const apiURL = origin(options.apiURL ?? "https://api.ofauth.com")
	const authURL = origin(options.authURL ?? "https://auth.ofauth.com")
	const scopes = [...new Set(["identity:read", ...(options.offlineAccess === false ? [] : ["offline_access"]), ...(options.scopes ?? [])])]
	return {
		providerId: "ofauth",
		name: "OFAuth",
		clientId: options.clientId,
		clientSecret: options.clientSecret,
		authorizationUrl: `${authURL}/link/authorize`,
		tokenUrl: `${apiURL}/v3/link/token`,
		tokenEndpointAuth: { method: "client_secret_basic" },
		pkce: true,
		scopes,
		disableSignUp: options.disableSignUp,
		getUserInfo: async (tokens) => {
			if (!tokens.accessToken) return null
			const response = await fetch(`${apiURL}/v3/link/userinfo`, {
				headers: { authorization: `Bearer ${tokens.accessToken}` },
				redirect: "manual",
				signal: AbortSignal.timeout(10_000),
			})
			if (!response.ok) throw new Error(`OFAuth user info failed (${response.status})`)
			const profile: unknown = await response.json()
			if (!profile || typeof profile !== "object" ||
				!("sub" in profile) || typeof profile.sub !== "string" || !profile.sub ||
				!("email" in profile) || typeof profile.email !== "string" || !profile.email ||
				!("name" in profile) || typeof profile.name !== "string" ||
				!("email_verified" in profile) || typeof profile.email_verified !== "boolean" ||
				!("picture" in profile) || (profile.picture !== null && typeof profile.picture !== "string")) {
				throw new Error("OFAuth returned invalid user info")
			}
			if (options.onAuthorization) {
				const authorizationId = tokens.raw?.authorization_id
				if (typeof authorizationId !== "string" || !authorizationId) throw new Error("OFAuth returned no authorization ID")
				await options.onAuthorization({ authorizationId, ofauthAccountId: profile.sub })
			}
			return { id: profile.sub, name: profile.name, email: profile.email,
				emailVerified: profile.email_verified, image: profile.picture ?? undefined }
		},
	}
}

/** Registers OFAuth for authClient.signIn.social and authClient.linkSocial. */
export const ofauth = (options: OFAuthOptions): Omit<ReturnType<typeof genericOAuth<"ofauth">>, "id"> & {
	id: "ofauth"
	endpoints: { ofauthWebhooks: ReturnType<typeof ofauthWebhookEndpoint> } | {}
} => ({
	...genericOAuth({ config: [ofauthProvider(options)] }),
	id: "ofauth" as const,
	endpoints: options.webhooks ? { ofauthWebhooks: ofauthWebhookEndpoint(options.webhooks) } : {},
})
