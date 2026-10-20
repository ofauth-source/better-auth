import type { Auth } from "better-auth"
import { OFAuthClient, OFAuthError, type AccessTokenRequest, type LinkedAccountsListParams, type RecoveryAction } from "@ofauth/onlyfans-sdk"
import { origin } from "./origin"

export class OFAuthAccessError extends OFAuthError {
	constructor(public readonly code: string, public readonly recoveryAction: RecoveryAction) {
		super(`OFAuth account access failed: ${code}`)
		this.name = "OFAuthAccessError"
	}
}

export type OFAuthAccessOptions = {
	auth: { api: Pick<Auth["api"], "listUserAccounts" | "getAccessToken" | "refreshToken"> }
	/** Coordinate every app instance until Better Auth finishes persisting the tokens. */
	withAccountLock: <T>(accountId: string, work: () => Promise<T>) => Promise<T>
	/** Use the same API origin as the provider. */
	apiURL?: string
}

export type OFAuthAccountSelection = {
	/** Authenticated app request headers. Never forwarded to OFAuth. */
	headers: Headers
	/** Better Auth account row ID. Required when several OFAuth identities are linked. */
	accountId?: string
}

export type OFAuthCreatorSelection = OFAuthAccountSelection & {
	/** Creator connection ID. Omit only when exactly one connected creator is available. */
	linkedAccountId?: string
}

/** Server-only SDK bridge. Better Auth is the sole token and refresh owner. */
export function createOFAuthAccess(options: OFAuthAccessOptions) {
	const apiURL = origin(options.apiURL ?? "https://api.ofauth.com")
	if (typeof options.withAccountLock !== "function") throw new Error("OFAuth account access requires withAccountLock")

	async function resolveAccount(selection: OFAuthAccountSelection) {
		const accounts = (await options.auth.api.listUserAccounts({ headers: selection.headers }))
			.filter((account) => account.providerId === "ofauth" && (selection.accountId === undefined || account.id === selection.accountId))
		if (!accounts.length) throw new OFAuthAccessError("ofauth_account_not_linked", "restart_authorization")
		if (accounts.length > 1) throw new OFAuthAccessError("ofauth_account_selection_required", "select_ofauth_account")
		return accounts[0].id
	}

	async function getAccessToken(selection: OFAuthAccountSelection & { accountId: string }, request?: AccessTokenRequest): Promise<string> {
		return options.withAccountLock(selection.accountId, async () => {
			try {
				const input = { headers: selection.headers, body: { accountId: selection.accountId } }
				let token: { accessToken?: string; accessTokenExpiresAt?: Date } = await options.auth.api.getAccessToken(input)
				// Another instance may have already replaced the rejected token.
				if (request?.forceRefresh && (!request.rejectedAccessToken || token.accessToken === request.rejectedAccessToken)) {
					token = await options.auth.api.refreshToken(input)
				}
				if (!token.accessToken || (token.accessTokenExpiresAt && new Date(token.accessTokenExpiresAt).getTime() <= Date.now())) {
					throw new OFAuthAccessError("ofauth_token_unavailable", "restart_authorization")
				}
				return token.accessToken
			} catch (error) {
				if (error && typeof error === "object" && "body" in error && error.body && typeof error.body === "object" &&
					"code" in error.body && error.body.code === "ACCOUNT_NOT_FOUND") {
					throw new OFAuthAccessError("ofauth_account_not_linked", "restart_authorization")
				}
				if (error && typeof error === "object" && "body" in error && error.body && typeof error.body === "object" &&
					"code" in error.body && ["FAILED_TO_GET_ACCESS_TOKEN", "FAILED_TO_REFRESH_ACCESS_TOKEN"].includes(String(error.body.code))) {
					// The exchange may have rotated remotely before failing. Never retry it here.
					throw new OFAuthAccessError("ofauth_token_unavailable", "restart_authorization")
				}
				throw error
			}
		})
	}

	const sdk = async (selection: OFAuthCreatorSelection) => {
		const bound = { headers: new Headers(selection.headers), accountId: await resolveAccount(selection) }
		return new OFAuthClient({
		baseUrl: apiURL,
		linkedAccountId: selection.linkedAccountId,
		accessToken: { getAccessToken: (request) => getAccessToken(bound, request) },
		fetch: (input, init) => {
			const request = new Request(input, init)
			const url = new URL(request.url)
			if ((request.headers.has("authorization") && url.origin !== apiURL) || (url.protocol !== "https:" && url.origin !== apiURL)) {
				throw new OFAuthError("OFAuth credentials must stay on the configured API origin")
			}
			const headers = new Headers(request.headers)
			headers.delete("cookie")
			return fetch(request, { headers, redirect: "manual", credentials: "omit" })
		},
		})
	}

	async function client(selection: OFAuthCreatorSelection): Promise<OFAuthClient> {
		const value = await sdk(selection)
		if (selection.linkedAccountId !== undefined) {
			await value.linkedAccounts.get({ id: selection.linkedAccountId })
			return value
		}
		let selected: string | undefined
		for await (const account of value.linkedAccounts.iterate()) {
			if (account.status !== "connected") continue
			if (selected !== undefined) throw new OFAuthAccessError("linked_account_selection_required", "select_linked_account")
			selected = account.id
		}
		if (!selected) throw new OFAuthAccessError("no_connected_linked_account", "list_linked_accounts")
		return value.withLinkedAccount(selected)
	}

	const listLinkedAccounts = async (selection: OFAuthAccountSelection, params?: LinkedAccountsListParams) => (await sdk(selection)).linkedAccounts.list(params)
	return { client, listLinkedAccounts }
}
