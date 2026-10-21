import { genericOAuth, type GenericOAuthConfig } from "better-auth/plugins/generic-oauth"
import { origin } from "./origin"

export type OFAuthOptions = {
	clientId: string
	clientSecret: string
	/** Additional account permissions. Identity is always requested. */
	scopes?: string[]
	/** Defaults to https://api.ofauth.com. */
	apiURL?: string
	/** Defaults to https://link.ofauth.com. */
	authURL?: string
	disableSignUp?: boolean
	/** Defaults to client_secret_basic. */
	tokenEndpointAuthMethod?: "client_secret_basic" | "client_secret_post"
}

/** Standard configuration for genericOAuth({ config: [ofauthProvider(options)] }). */
export function ofauthProvider(options: OFAuthOptions): GenericOAuthConfig<"ofauth"> {
	if (!options.clientId.trim() || !options.clientSecret.trim()) throw new Error("OFAuth client credentials are required")
	const apiURL = origin(options.apiURL ?? "https://api.ofauth.com")
	const authURL = origin(options.authURL ?? "https://link.ofauth.com")
	return {
		providerId: "ofauth",
		name: "OFAuth",
		clientId: options.clientId,
		clientSecret: options.clientSecret,
		authorizationUrl: `${authURL}/v3/authorize`,
		tokenUrl: `${apiURL}/v3/link/token`,
		userInfoUrl: `${apiURL}/v3/link/userinfo`,
		tokenEndpointAuth: { method: options.tokenEndpointAuthMethod ?? "client_secret_basic" },
		pkce: true,
		scopes: [...new Set(["identity:read", ...(options.scopes ?? [])])],
		disableSignUp: options.disableSignUp,
	}
}

/** Better Auth owns callback validation, token storage, and refresh. */
export const ofauth = (options: OFAuthOptions): ReturnType<typeof genericOAuth<"ofauth">> => genericOAuth({ config: [ofauthProvider(options)] })
