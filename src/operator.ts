import type { BetterAuthPlugin } from "better-auth"
import { createAuthMiddleware } from "better-auth/api"
import type { GenericOAuthConfig } from "better-auth/plugins/generic-oauth"
import { origin } from "./origin"

/** The only scopes an Operator private app can register or request. */
export const OFAUTH_OPERATOR_SCOPES = ["access:read", "access:write", "access:destructive", "connections:manage"] as const
export type OFAuthOperatorScope = (typeof OFAUTH_OPERATOR_SCOPES)[number]

export type OFAuthOperatorOptions = {
	clientId: string
	clientSecret: string
	/** Additional Operator Access scopes. `access:read` is always requested. */
	scopes?: OFAuthOperatorScope[]
	/** Defaults to https://api.ofauth.com. */
	apiURL?: string
	/** Defaults to https://link.ofauth.com. */
	authURL?: string
	/** Defaults to client_secret_basic. */
	tokenEndpointAuthMethod?: "client_secret_basic" | "client_secret_post"
}

/** Validates and normalizes requested Operator scopes; `access:read` is always included. */
export function operatorScopes(scopes: readonly string[] = []): OFAuthOperatorScope[] {
	const invalid = scopes.filter(scope => !(OFAUTH_OPERATOR_SCOPES as readonly string[]).includes(scope))
	if (invalid.length) throw new Error(`OFAuth Operator apps only support ${OFAUTH_OPERATOR_SCOPES.join(", ")} (received ${invalid.join(", ")})`)
	return [...new Set(["access:read", ...scopes])] as OFAuthOperatorScope[]
}

/**
 * Generic OAuth configuration for an Operator private app. Operator tokens carry
 * no profile or email, so the provider identity is the OFAuth authorization ID
 * from GET /v3/authorization. Sign-up is always disabled: link from a session.
 */
export function ofauthOperatorProvider(options: OFAuthOperatorOptions): GenericOAuthConfig<"ofauth"> {
	if (!options.clientId?.trim() || !options.clientSecret?.trim()) throw new Error("OFAuth client credentials are required")
	const apiURL = origin(options.apiURL ?? "https://api.ofauth.com")
	const authURL = origin(options.authURL ?? "https://link.ofauth.com")
	return {
		providerId: "ofauth",
		name: "OFAuth",
		clientId: options.clientId,
		clientSecret: options.clientSecret,
		authorizationUrl: `${authURL}/v3/authorize`,
		tokenUrl: `${apiURL}/v3/link/token`,
		tokenEndpointAuth: { method: options.tokenEndpointAuthMethod ?? "client_secret_basic" },
		pkce: true,
		scopes: operatorScopes(options.scopes),
		disableSignUp: true,
		disableImplicitSignUp: true,
		getUserInfo: async (tokens) => {
			if (!tokens.accessToken) return null
			const response = await fetch(`${apiURL}/v3/authorization`, {
				headers: { authorization: `Bearer ${tokens.accessToken}`, accept: "application/json" },
				redirect: "error",
			})
			if (!response.ok) return null
			const authorization = await response.json() as { id?: unknown }
			if (typeof authorization.id !== "string" || !authorization.id) return null
			// Never invent an email or verified status for an Operator authorization.
			return { id: authorization.id, emailVerified: false }
		},
	}
}

/**
 * Lets Better Auth link an Operator authorization, which has no email, to the
 * signed-in user that started `linkSocial`. Applies only to the OFAuth callback
 * request: it marks `ofauth` trusted and accepts the absent email for that one
 * request. Sign-in through this callback still fails because the provider
 * returns no email, and the provider disables sign-up.
 */
export const ofauthOperatorLinking = (): BetterAuthPlugin => ({
	id: "ofauth-operator-linking",
	hooks: {
		before: [{
			matcher: (context: { path?: string; params?: Record<string, unknown> }) => context.path === "/callback/:id" && context.params?.id === "ofauth",
			handler: createAuthMiddleware(async (context) => ({ context: { context: {
				trustedProviders: [...new Set([...context.context.trustedProviders, "ofauth"])],
				options: { account: { accountLinking: { allowDifferentEmails: true } } },
			} } })),
		}],
	},
})
