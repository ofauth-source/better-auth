// Failure cases: state tampering/replay, PKCE or Basic-auth mismatch, missing identity
// consent, mismatched user-info shape, changing creator selections changing login
// identity, linking another user's account, and refresh losing resource/auth params.
// Packaged access must coordinate rotation and report a rejected refresh without retrying or losing the app session.
// Webhook failures: altered or stale signatures, malformed signed envelopes, delivery
// before account creation, duplicate/out-of-order events, retry after handler failure,
// wrong provider mapping, and disclosing tokens or deleting the person's app session.
import { createHash, createHmac } from "node:crypto"
import { createServer, type Server } from "node:http"
import { afterAll, beforeAll, describe, expect, it } from "vitest"
import { betterAuth } from "better-auth"
import { ofauth, type OFAuthOptions } from "../src/index"
import { createOFAuthAccess } from "../src/server"
import { createOFAuthWebhookHandler } from "../src/webhooks"
import { createTestEvent } from "@ofauth/onlyfans-sdk/testing"

const appOrigin = "http://localhost:3000"
const clientId = `ofext_test_${"t".repeat(32)}`
const liveClientId = `ofext_live_${"l".repeat(32)}`
const clientSecret = "test_secret"
let issuer: string
let server: Server
let person = "person-one"
let creators = ["creator-one", "creator-two"]
let refreshes = 0
let refreshAttempts = 0
const codes = new Map<string, { challenge: string; redirectURI: string; scopes: string[]; person: string }>()
const accessTokens = new Map<string, string>()
const refreshTokens = new Map<string, string>()

beforeAll(async () => {
	server = createServer(async (request, response) => {
		const url = new URL(request.url!, issuer)
		const json = (body: unknown, status = 200) => {
			response.writeHead(status, { "content-type": "application/json" })
			response.end(JSON.stringify(body))
		}
		if (url.pathname === "/link/authorize") {
			expect(url.searchParams.has("resource")).toBe(false)
			expect(url.searchParams.get("code_challenge_method")).toBe("S256")
			expect(url.searchParams.has("purpose")).toBe(false)
			expect(url.searchParams.has("client_secret")).toBe(false)
			const code = crypto.randomUUID()
			const redirectURI = url.searchParams.get("redirect_uri")!
			codes.set(code, {
				challenge: url.searchParams.get("code_challenge")!, redirectURI,
				scopes: url.searchParams.get("scope")!.split(" "), person,
			})
			const callback = new URL(redirectURI)
			callback.searchParams.set("code", code)
			callback.searchParams.set("state", url.searchParams.get("state")!)
			response.writeHead(302, { location: callback.href })
			response.end()
			return
		}
		if (url.pathname === "/v3/link/token") {
			const chunks: Buffer[] = []
			for await (const chunk of request) chunks.push(Buffer.from(chunk))
			const form = new URLSearchParams(Buffer.concat(chunks).toString())
			if (![clientId, liveClientId].some((id) => request.headers.authorization === `Basic ${Buffer.from(`${id}:${clientSecret}`).toString("base64")}`) ||
				form.has("resource")) return json({ error: "invalid_client" }, 401)
			let subject: string
			if (form.get("grant_type") === "refresh_token") {
				refreshAttempts++
				const refreshToken = form.get("refresh_token")!
				if (!refreshTokens.has(refreshToken)) return json({ error: "invalid_grant" }, 400)
				subject = refreshTokens.get(refreshToken)!
				refreshTokens.delete(refreshToken)
				refreshes++
			} else {
				const code = form.get("code")!
				const pending = codes.get(code)
				codes.delete(code)
				if (!pending || pending.redirectURI !== form.get("redirect_uri") ||
					createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url") !== pending.challenge) {
					return json({ error: "invalid_grant" }, 400)
				}
				expect(pending.scopes).toContain("identity:read")
				subject = pending.person
			}
			const accessToken = crypto.randomUUID()
			const refreshToken = crypto.randomUUID()
			accessTokens.set(accessToken, subject)
			refreshTokens.set(refreshToken, subject)
			return json({ access_token: accessToken, refresh_token: refreshToken, authorization_id: `authz_${subject}`, token_type: "Bearer", expires_in: 600,
				scope: "identity:read offline_access profile:read" })
		}
		const subject = accessTokens.get(request.headers.authorization?.slice(7) ?? "")
		if (!subject) return json({ error: "invalid_token" }, 401)
		if (url.pathname === "/v3/link/userinfo") return json({
			sub: subject, name: subject, email: `${subject}@example.com`, email_verified: true, picture: null,
		})
		const shared = creators.map((id) => ({ id, provider: "onlyfans", provider_account_id: id, username: null, display_name: null,
			status: "connected", scopes: ["profile:read", "messages:write"], granted_at: new Date().toISOString() }))
		if (url.pathname === "/v3/linked-accounts") return json({ data: shared, has_more: false, next_cursor: null })
		if (url.pathname.startsWith("/v3/linked-accounts/")) {
			const account = shared.find(({ id }) => id === url.pathname.split("/").at(-1))
			return account ? json(account) : json({ error: "linked_account_not_found", recovery: { action: "list_linked_accounts" } }, 404)
		}
		if (url.pathname === "/v3/access/chats/42/messages") {
			const linkedAccountId = request.headers["x-linked-account-id"]
			if (typeof linkedAccountId !== "string" || !creators.includes(linkedAccountId)) {
				return json({ error: "linked_account_not_found", recovery: { action: "list_linked_accounts" } }, 404)
			}
			writes.push(linkedAccountId)
			return json({ id: 123, text: "Hello" })
		}
		json({ error: "not_found" }, 404)
	})
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
	const address = server.address()
	if (!address || typeof address === "string") throw new Error("Missing fixture port")
	issuer = `http://127.0.0.1:${address.port}`
})

afterAll(async () => {
	await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
})

const writes: string[] = []
const createApp = (options: { clientId?: string; scopes?: string[]; allowDifferentEmails?: boolean; onAuthorization?: OFAuthOptions["onAuthorization"] } = {}) => betterAuth({
	baseURL: appOrigin,
	secret: "ofauth-integration-test-secret-at-least-32-characters",
	emailAndPassword: { enabled: true },
	account: { accountLinking: { enabled: true, allowDifferentEmails: options.allowDifferentEmails } },
	plugins: [ofauth({ clientId: options.clientId ?? clientId, clientSecret, apiURL: issuer, authURL: issuer, scopes: options.scopes ?? ["profile:read"], onAuthorization: options.onAuthorization })],
})

function cookieHeader(response: Response): string {
	return response.headers.getSetCookie().map((cookie) => cookie.split(";", 1)[0]).join("; ")
}

async function authorize(auth: ReturnType<typeof createApp>, path = "/sign-in/social", cookie = "") {
	const start = await auth.handler(new Request(`${appOrigin}/api/auth${path}`, {
		method: "POST", headers: { "content-type": "application/json", origin: appOrigin, cookie },
		body: JSON.stringify({ provider: "ofauth", callbackURL: "/done" }),
	}))
	expect(start.status).toBe(200)
	const { url } = await start.json()
	const consent = await fetch(url, { redirect: "manual" })
	expect(consent.status).toBe(302)
	return { authorizationURL: url as string, callback: consent.headers.get("location")!, cookies: [cookie, cookieHeader(start)].filter(Boolean).join("; ") }
}

async function complete(auth: ReturnType<typeof createApp>, flow: Awaited<ReturnType<typeof authorize>>) {
	return auth.handler(new Request(flow.callback, { headers: { cookie: flow.cookies } }))
}

describe("OFAuth through Better Auth HTTP endpoints", () => {
	it("keeps a person's identity across changing creator selections and rotates refresh tokens", async () => {
		person = "person-one"
		const auth = createApp()
		const first = await complete(auth, await authorize(auth))
		expect(first.headers.get("location")).toBe("/done")
		const sessionCookies = cookieHeader(first)
		const session = await auth.api.getSession({ headers: new Headers({ cookie: sessionCookies }) })
		expect(session?.user.email).toBe("person-one@example.com")
		creators = ["creator-three"]
		const second = await complete(auth, await authorize(auth))
		const returning = await auth.api.getSession({ headers: new Headers({ cookie: cookieHeader(second) }) })
		expect(returning?.user.id).toBe(session?.user.id)
		const linked = await auth.api.listUserAccounts({ headers: new Headers({ cookie: sessionCookies }) })
		expect(linked).toMatchObject([{ providerId: "ofauth", accountId: "person-one" }])
		const refreshed = await auth.api.refreshToken({
			headers: new Headers({ cookie: sessionCookies }), body: { accountId: linked[0].id },
		})
		expect(refreshed.accessToken).toBeTruthy()
		expect(refreshes).toBeGreaterThan(0)
	})

	it("links OFAuth to an existing app user and refuses stealing the same OFAuth identity", async () => {
		person = "linked-person"
		const auth = createApp({ allowDifferentEmails: true })
		const signup = await auth.api.signUpEmail({
			body: { name: "Existing", email: "existing-app-user@example.com", password: "test-password-1234" }, asResponse: true,
		})
		const cookie = cookieHeader(signup)
		const before = await auth.api.getSession({ headers: new Headers({ cookie }) })
		const linked = await complete(auth, await authorize(auth, "/link-social", cookie))
		expect(linked.headers.get("location")).toBe("/done")
		const accounts = await auth.api.listUserAccounts({ headers: new Headers({ cookie }) })
		expect(accounts.some((account) => account.providerId === "ofauth" && account.accountId === person)).toBe(true)
		const signedIn = await complete(auth, await authorize(auth))
		const session = await auth.api.getSession({ headers: new Headers({ cookie: cookieHeader(signedIn) }) })
		expect(session?.user.id).toBe(before?.user.id)
		const otherSignup = await auth.api.signUpEmail({
			body: { name: "Other", email: "other-app-user@example.com", password: "test-password-1234" }, asResponse: true,
		})
		const otherCookie = cookieHeader(otherSignup)
		const stolen = await complete(auth, await authorize(auth, "/link-social", otherCookie))
		expect(stolen.headers.get("location")).toContain("error=account_already_linked_to_different_user")
		const otherAccounts = await auth.api.listUserAccounts({ headers: new Headers({ cookie: otherCookie }) })
		expect(otherAccounts.some((account) => account.providerId === "ofauth")).toBe(false)
	})

	it("signs in with Live credentials without a purpose parameter or creator access", async () => {
		person = "login-only-person"
		creators = []
		const auth = createApp({ clientId: liveClientId, scopes: [] })
		const flow = await authorize(auth)
		expect(new URL(flow.authorizationURL).searchParams.get("scope")?.split(" ")).toEqual(["identity:read", "offline_access"])
		const response = await complete(auth, flow)
		const session = await auth.api.getSession({ headers: new Headers({ cookie: cookieHeader(response) }) })
		expect(session?.user.email).toBe("login-only-person@example.com")
	})

	it("rejects a changed OAuth state before exchanging the code", async () => {
		const auth = createApp()
		const flow = await authorize(auth)
		const callback = new URL(flow.callback)
		callback.searchParams.set("state", "tampered-state")
		const response = await complete(auth, { ...flow, callback: callback.href })
		expect(response.headers.get("location")).toContain("error=")
		expect(codes.has(callback.searchParams.get("code")!)).toBe(true)
	})

	it("coordinates creator access and requests re-consent after a rejected refresh without retrying or ending the app session", async () => {
		person = "access-person"
		creators = ["shared-creator"]
		const auth = createApp()
		const completed = await complete(auth, await authorize(auth))
		const headers = new Headers({ cookie: cookieHeader(completed) })
		const [account] = await auth.api.listUserAccounts({ headers })
		const context = await auth.$context
		await context.internalAdapter.updateAccount(account.id, { accessTokenExpiresAt: new Date(0) })
		let tail: Promise<unknown> = Promise.resolve()
		const withAccountLock = <T>(_key: string, work: () => Promise<T>): Promise<T> => {
			const result = tail.catch(() => {}).then(work)
			tail = result
			return result
		}
		const access = createOFAuthAccess({ auth, apiURL: issuer, withAccountLock })
		const before = refreshes
		const pages = await Promise.all(Array.from({ length: 3 }, () => access.listLinkedAccounts({ headers })))
		for (const page of pages) expect(page).toMatchObject({ data: [{ id: "shared-creator" }] })
		expect(refreshes - before).toBe(1)
		const client = await access.client({ headers })
		accessTokens.clear()
		const forcedBefore = refreshes
		await Promise.all(Array.from({ length: 3 }, () => client.linkedAccounts.list()))
		expect(refreshes - forcedBefore).toBe(1)
		refreshTokens.clear()
		await context.internalAdapter.updateAccount(account.id, { accessTokenExpiresAt: new Date(0) })
		const attempts = refreshAttempts
		await expect(access.listLinkedAccounts({ headers })).rejects.toMatchObject({ code: "ofauth_token_unavailable", recoveryAction: "restart_authorization" })
		expect(refreshAttempts - attempts).toBe(1)
		expect((await auth.api.getSession({ headers }))?.user.id).toBe(account.userId)
	})

	it("requires selection for multiple creators and keeps an explicit SDK write target stable", async () => {
		person = "sdk-person"
		creators = ["creator-a", "creator-b"]
		const auth = createApp({ scopes: ["messages:write"] })
		const completed = await complete(auth, await authorize(auth))
		const headers = new Headers({ cookie: cookieHeader(completed) })
		const access = createOFAuthAccess({ auth, apiURL: issuer, withAccountLock: (_id, work) => work() })
		const before = writes.length
		await expect(access.client({ headers })).rejects.toMatchObject({ code: "linked_account_selection_required", recoveryAction: "select_linked_account" })
		expect(writes.length).toBe(before)
		const client = await access.client({ headers, linkedAccountId: "creator-b" })
		creators.reverse()
		await client.access.chats.messages.send({ userId: 42, body: { text: "Hello" } })
		expect(writes.slice(before)).toEqual(["creator-b"])
		creators = ["creator-a"]
		await expect(client.access.chats.messages.send({ userId: 42, body: { text: "Hello" } }))
			.rejects.toMatchObject({ code: "linked_account_not_found", recoveryAction: "list_linked_accounts" })
		expect(writes.slice(before)).toEqual(["creator-b"])
		const automatic = await access.client({ headers })
		await automatic.access.chats.messages.send({ userId: 42, body: { text: "Hello" } })
		expect(writes.slice(before)).toEqual(["creator-b", "creator-a"])
		await expect(access.listLinkedAccounts({ headers: new Headers() })).rejects.toMatchObject({ statusCode: 401 })
	})

	it("verifies signed webhooks, resolves the Better Auth account, and delegates durable processing before acknowledging", async () => {
		person = "webhook-person"
		const bindings = new Map<string, string>()
		const auth = createApp({ onAuthorization: ({ authorizationId, ofauthAccountId }) => { bindings.set(authorizationId, ofauthAccountId) } })
		const completed = await complete(auth, await authorize(auth))
		const headers = new Headers({ cookie: cookieHeader(completed) })
		const [account] = await auth.api.listUserAccounts({ headers })
		expect(bindings.get("authz_webhook-person")).toBe("webhook-person")
		const secret = `whsec_${Buffer.from("webhook-test-key-32-bytes-long!!!").toString("base64")}`
		let lookups = 0
		let attempts = 0
		let fail = true
		const applied: Array<{ userId: string; id: string }> = []
		const seen = new Set<string>()
		let lastOrder = -1
		const handler = createOFAuthWebhookHandler({
			auth, secret,
			resolveAccount: async (event) => { lookups++; return bindings.get(event.authorizationId) ?? null },
			// Local stand-in for the app's transaction: production uses durable storage.
			processEvent: async (event, work) => {
				if (seen.has(event.eventId) || event.order <= lastOrder) return
				await work()
				seen.add(event.eventId)
				lastOrder = event.order
			},
			handlers: {
				"authorization.revoked": async ({ account: resolved, event }) => {
					attempts++
					expect(Object.keys(resolved).sort()).toEqual(["accountId", "id", "providerId", "userId"])
					expect(event.data.reason).toBe("owner_revoked")
					if (fail) throw new Error("Temporary app storage failure")
					applied.push({ userId: resolved.userId, id: resolved.id })
				},
			},
		})
		const event = createTestEvent("authorization.revoked", { authorizationId: "authz_webhook-person", order: 5 })
		// Independent signer: the verifier comes from the SDK, not this fixture.
		const signed = (payload: unknown, timestamp = Math.floor(Date.now() / 1000)) => {
			const body = JSON.stringify(payload)
			const id = "msg_better_auth_webhook"
			const signature = createHmac("sha256", Buffer.from(secret.slice(6), "base64")).update(`${id}.${timestamp}.${body}`).digest("base64")
			return new Request(`${appOrigin}/webhooks/ofauth`, { method: "POST", body, headers: {
				"content-type": "application/json", "webhook-id": id, "webhook-timestamp": String(timestamp), "webhook-signature": `v1,${signature}`,
			} })
		}
		const tampered = signed(event)
		expect((await handler(new Request(tampered.url, { method: "POST", headers: tampered.headers, body: "{}" }))).status).toBe(401)
		expect((await handler(signed(event, Math.floor(Date.now() / 1000) - 600))).status).toBe(401)
		expect(lookups).toBe(0)
		expect((await handler(signed({ ...event, order: "invalid" }))).status).toBe(400)
		expect((await handler(signed({ ...event, authorizationId: "unmapped" }))).status).toBe(503)
		const credential = await auth.api.signUpEmail({ body: { name: "Other", email: "webhook-other@example.com", password: "webhook-other-password" } })
		bindings.set("authz_credential", credential.user.id)
		expect((await handler(signed({ ...event, authorizationId: "authz_credential" }))).status).toBe(503)
		expect((await handler(signed(event))).status).toBe(500)
		expect(applied).toEqual([])
		fail = false
		expect((await handler(signed(event))).status).toBe(204)
		expect((await handler(signed(event))).status).toBe(204)
		expect((await handler(signed({ ...event, eventId: "evt_older", order: 4 }))).status).toBe(204)
		expect(attempts).toBe(2)
		expect(applied).toEqual([{ userId: account.userId, id: account.id }])
		expect((await auth.api.getSession({ headers }))?.user.id).toBe(account.userId)
		expect((await auth.api.listUserAccounts({ headers }))[0].id).toBe(account.id)
		expect((await handler(new Request(`${appOrigin}/webhooks/ofauth`))).status).toBe(405)
	})
})
