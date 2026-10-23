import { operatorScopes, type OFAuthOperatorScope } from "./operator"
import { origin } from "./origin"

export type OFAuthOperatorCredentials = {
	clientId: string
	clientSecret: string
	/** When OFAuth issued the registration. An unused registration expires after 24 hours. */
	issuedAt: Date
}

export type OFAuthOperatorRegistrationOptions = {
	/** Shown to the workspace member on the consent screen. */
	clientName: string
	/** The exact Better Auth callback, e.g. https://app.example/api/auth/callback/ofauth. */
	redirectURI: string
	/**
	 * Optional return URL for linked-account reconnect, e.g. https://app.example/accounts/reconnected.
	 * Better Auth owns `redirectURI` and rejects a reconnect return there as an unknown OAuth state.
	 * Registered as `ofauth_reconnect_return_uri`; OFAuth accepts it only for reconnect, never as an OAuth redirect.
	 * Changing it needs a new registration: return nothing from `load` for credentials registered without it.
	 */
	reconnectReturnURI?: string
	/** Must include every scope later passed to the Operator provider. `access:read` is always included. */
	scopes?: OFAuthOperatorScope[]
	/** Defaults to https://api.ofauth.com. */
	apiURL?: string
	/** Defaults to client_secret_basic. */
	tokenEndpointAuthMethod?: "client_secret_basic" | "client_secret_post"
	/** Return stored credentials for this callback, or nothing to register. */
	load: () => Promise<OFAuthOperatorCredentials | null | undefined>
	/** Persist new credentials privately. Return the stored winner if another instance registered first. */
	save: (credentials: OFAuthOperatorCredentials) => Promise<OFAuthOperatorCredentials | void>
}

const isLoopback = (url: URL) => ["127.0.0.1", "[::1]", "localhost"].includes(url.hostname)
const returnURL = (value: string, name: string) => {
	const url = new URL(value)
	if (url.hash || url.username || url.password ||
		(url.protocol !== "https:" && !(url.protocol === "http:" && isLoopback(url)))) {
		throw new Error(`The OFAuth ${name} must be an HTTPS URL (HTTP is allowed on loopback for development)`)
	}
	return url
}

/**
 * RFC 7591 self-registration for an Operator private app. Registration grants
 * nothing until a workspace member approves it in the browser. Storage stays
 * with the application through `load` and `save`.
 */
export async function ofauthOperatorRegistration(options: OFAuthOperatorRegistrationOptions): Promise<OFAuthOperatorCredentials> {
	const stored = await options.load()
	if (stored) return stored
	const apiURL = origin(options.apiURL ?? "https://api.ofauth.com")
	const redirect = returnURL(options.redirectURI, "callback")
	const reconnect = options.reconnectReturnURI === undefined ? undefined : returnURL(options.reconnectReturnURI, "reconnect return URL")
	const scopes = operatorScopes(options.scopes)
	const method = options.tokenEndpointAuthMethod ?? "client_secret_basic"
	const issuer = `${apiURL}/v3/link`

	const metadataResponse = await fetch(`${apiURL}/.well-known/oauth-authorization-server/v3/link`, {
		redirect: "error",
		signal: AbortSignal.timeout(10_000),
	})
	if (!metadataResponse.ok) throw new Error(`OFAuth discovery failed (${metadataResponse.status})`)
	const metadata = await metadataResponse.json() as { issuer?: unknown; registration_endpoint?: unknown }
	if (metadata.issuer !== issuer || metadata.registration_endpoint !== `${issuer}/register`) {
		throw new Error("OFAuth discovery does not advertise the expected registration endpoint")
	}

	const response = await fetch(metadata.registration_endpoint, {
		method: "POST",
		redirect: "error",
		signal: AbortSignal.timeout(10_000),
		headers: { "content-type": "application/json" },
		body: JSON.stringify({
			client_name: options.clientName,
			redirect_uris: [redirect.href],
			...(reconnect ? { ofauth_reconnect_return_uri: reconnect.href } : {}),
			token_endpoint_auth_method: method,
			grant_types: ["authorization_code", "refresh_token"],
			response_types: ["code"],
			application_type: "web",
			scope: scopes.join(" "),
		}),
	})
	if (response.status !== 201) throw new Error(`OFAuth registration failed (${response.status})`)
	const registration = await response.json() as {
		client_id?: unknown
		client_secret?: unknown
		client_id_issued_at?: unknown
		redirect_uris?: unknown
		ofauth_reconnect_return_uri?: unknown
		token_endpoint_auth_method?: unknown
		scope?: unknown
	}
	const granted = typeof registration.scope === "string" ? registration.scope.split(" ") : []
	if (typeof registration.client_id !== "string" || !registration.client_id ||
		typeof registration.client_secret !== "string" || registration.client_secret.length < 32 ||
		!Array.isArray(registration.redirect_uris) || registration.redirect_uris.length !== 1 || registration.redirect_uris[0] !== redirect.href ||
		registration.token_endpoint_auth_method !== method || !scopes.every(scope => granted.includes(scope))) {
		throw new Error("OFAuth registration response is invalid")
	}
	// A server that ignores the extension would leave reconnect returns on the Better Auth callback.
	if (reconnect && registration.ofauth_reconnect_return_uri !== reconnect.href) {
		throw new Error("OFAuth did not register the reconnect return URL")
	}
	const credentials: OFAuthOperatorCredentials = {
		clientId: registration.client_id,
		clientSecret: registration.client_secret,
		issuedAt: typeof registration.client_id_issued_at === "number" ? new Date(registration.client_id_issued_at * 1000) : new Date(),
	}
	return (await options.save(credentials)) ?? credentials
}
