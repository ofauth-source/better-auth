// See FAILURES.md, written before this harness and runtime replacement.
// This local issuer simulates consent/provider state; it does not certify OFAuth routes.
import { createHash } from "node:crypto"
import { spawn, type ChildProcess } from "node:child_process"
import { createServer, type Server } from "node:http"
import { afterAll, beforeAll, describe, expect, it } from "vitest"
import { betterAuth } from "better-auth"
import { getMigrations } from "better-auth/db/migration"
import { Pool } from "pg"
import { ofauth, ofauthProvider } from "../src/index"
import { genericOAuth } from "better-auth/plugins/generic-oauth"

const appOrigin = "http://localhost:3000"
const clientId = `ofext_test_${"t".repeat(32)}`
const clientSecret = "fixture-only-client-secret"
const schema = `ofauth_adapter_${Date.now()}_${process.pid}`
let issuer: string
let server: Server
let pool: Pool
let adminPool: Pool
let subject = "owner"
let profileEmail: string | undefined
let profileEmailVerified = true
let refreshes = 0
let loseResponse = false
let duringRefresh: (() => Promise<void>) | undefined
const codes = new Map<string, { challenge: string; redirectURI: string; subject: string }>()
const credentials = new Map<string, { subject: string; revoked: boolean }>()
const accessTokens = new Map<string, string>()
const authMethods = new Set<string>()
const children = new Set<ChildProcess>()
async function startProcess() {
 const child = spawn(process.execPath, [new URL("./app-instance.mjs", import.meta.url).pathname], {
  env: { ...process.env, OFAUTH_TEST_SCHEMA: schema, OFAUTH_API_URL: issuer, OFAUTH_CLIENT_ID: clientId, OFAUTH_CLIENT_SECRET: clientSecret }, stdio: ["ignore", "pipe", "ignore"],
 })
 children.add(child)
 const url = await new Promise<string>((resolve, reject) => {
  child.once("exit", () => reject(new Error("Better Auth test process exited before readiness")))
  child.stdout!.once("data", data => { const { port } = JSON.parse(data.toString()); resolve(`http://127.0.0.1:${port}`) })
 })
 return {
  request: (path: string, cookie = "", body?: unknown) => fetch(`${url}/api/auth${path}`, { method: body ? "POST" : "GET", headers: headers(cookie), ...(body ? { body: JSON.stringify(body) } : {}), redirect: "manual" }),
  stop: async () => { if (child.exitCode !== null) return; child.kill("SIGTERM"); await new Promise<void>(resolve => child.once("exit", () => resolve())); children.delete(child) },
 }
}

function createApp(options: { allowDifferentEmails?: boolean; method?: "client_secret_basic" | "client_secret_post"; stock?: boolean } = {}) {
 const provider = { clientId, clientSecret, apiURL: issuer, authURL: issuer, scopes: ["profile:read"], tokenEndpointAuthMethod: options.method }
 return betterAuth({ database: pool, baseURL: appOrigin,
  secret: "fixture-only-better-auth-secret-at-least-32-characters",
  logger: { disabled: true },
  emailAndPassword: { enabled: true },
  account: { encryptOAuthTokens: true, accountLinking: { enabled: true, allowDifferentEmails: options.allowDifferentEmails } },
  plugins: [options.stock ? genericOAuth({ config: [ofauthProvider(provider)] }) : ofauth(provider)],
 })
}
type App = ReturnType<typeof createApp>
function cookies(response: Response) { return response.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ") }
function headers(cookie: string) { return new Headers({ cookie, origin: appOrigin, "content-type": "application/json" }) }
async function signup(auth: App) {
 const email = `app-${crypto.randomUUID()}@example.com`
 const response = await auth.handler(new Request(`${appOrigin}/api/auth/sign-up/email`, { method: "POST", headers: headers(""), body: JSON.stringify({ email, password: "fixture-only-app-password", name: "Application user" }) }))
 expect(response.status).toBe(200)
 return { cookie: cookies(response), user: (await response.json()).user }
}
async function authorize(auth: App, cookie: string) {
 const response = await auth.handler(new Request(`${appOrigin}/api/auth/link-social`, { method: "POST", headers: headers(cookie), body: JSON.stringify({ provider: "ofauth", callbackURL: "/done" }) }))
 expect(response.status).toBe(200)
 const { url } = await response.json()
 const consent = await fetch(url, { redirect: "manual" })
 expect(consent.status).toBe(302)
 return { callback: consent.headers.get("location")!, cookie: [cookie, cookies(response)].filter(Boolean).join("; "), authorizationURL: url as string }
}
async function complete(auth: App, flow: Awaited<ReturnType<typeof authorize>>) { return auth.handler(new Request(flow.callback, { headers: headers(flow.cookie) })) }
async function linked(auth: App, cookie: string) {
 const accounts = await auth.api.listUserAccounts({ headers: headers(cookie) })
 return accounts.find(account => account.providerId === "ofauth")!
}
async function expire(accountId: string) { await pool.query('UPDATE account SET "accessTokenExpiresAt" = $1 WHERE id = $2', [new Date(0), accountId]) }
async function token(auth: App, cookie: string, accountId: string) {
 const response = await auth.handler(new Request(`${appOrigin}/api/auth/get-access-token`, { method: "POST", headers: headers(cookie), body: JSON.stringify({ accountId }) }))
 return { status: response.status, body: await response.json() }
}
async function resource(accessToken: string, path = "/v3/linked-accounts", selected?: string) {
 return fetch(`${issuer}${path}`, { headers: { authorization: `Bearer ${accessToken}`, ...(selected ? { "X-Linked-Account-Id": selected } : {}) }, redirect: "error" })
}

beforeAll(async () => {
 adminPool = new Pool({ connectionString: process.env.POSTGRES_URL ?? "postgres://ofauth:ofauth@localhost:61700/ofauth" })
 await adminPool.query(`CREATE SCHEMA "${schema}"`)
 pool = new Pool({ connectionString: process.env.POSTGRES_URL ?? "postgres://ofauth:ofauth@localhost:61700/ofauth", options: `-c search_path=${schema}` })
 await (await getMigrations(createApp().options)).runMigrations()
 server = createServer(async (request, response) => {
  const url = new URL(request.url!, issuer)
  const json = (body: unknown, status = 200) => { response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" }); response.end(JSON.stringify(body)) }
  if (url.pathname === "/v3/authorize") {
   if (url.searchParams.get("code_challenge_method") !== "S256" || url.searchParams.has("client_secret") || url.searchParams.get("response_type") !== "code") return json({ error: "invalid_request" }, 400)
   const code = crypto.randomUUID()
   const redirectURI = url.searchParams.get("redirect_uri")!
   codes.set(code, { challenge: url.searchParams.get("code_challenge")!, redirectURI, subject })
   const callback = new URL(redirectURI)
   callback.searchParams.set("code", code); callback.searchParams.set("state", url.searchParams.get("state")!)
   callback.searchParams.set("iss", `${issuer}/v3/link`)
   response.writeHead(302, { location: callback.href }); response.end(); return
  }
  if (["/v3/link/token", "/v3/link/revoke"].includes(url.pathname)) {
   const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(Buffer.from(chunk))
   const form = new URLSearchParams(Buffer.concat(chunks).toString())
   if (!request.headers["content-type"]?.startsWith("application/x-www-form-urlencoded")) return json({ error: "invalid_request" }, 400)
   const basic = request.headers.authorization === `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`
   const post = !request.headers.authorization && form.get("client_id") === clientId && form.get("client_secret") === clientSecret
   if ((!basic && !post) || (basic && form.has("client_secret"))) return json({ error: "invalid_client" }, 401)
   authMethods.add(basic ? "client_secret_basic" : "client_secret_post")
   if (url.pathname.endsWith("/revoke")) { const credential = credentials.get(form.get("token")!); if (credential) credential.revoked = true; return json({}) }
   let refreshToken: string
   if (form.get("grant_type") === "refresh_token") {
    refreshToken = form.get("refresh_token")!
    const credential = credentials.get(refreshToken)
    if (!credential || credential.revoked) return json({ error: "invalid_grant" }, 400)
    refreshes++; await duringRefresh?.()
   } else {
    const code = form.get("code")!
    const pending = codes.get(code)
    if (!pending || pending.redirectURI !== form.get("redirect_uri") || createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url") !== pending.challenge) return json({ error: "invalid_grant" }, 400)
    codes.delete(code)
    refreshToken = crypto.randomUUID(); credentials.set(refreshToken, { subject: pending.subject, revoked: false })
   }
   const accessToken = crypto.randomUUID(); accessTokens.set(accessToken, refreshToken)
   if (loseResponse && form.get("grant_type") === "refresh_token") { loseResponse = false; request.socket.destroy(); return }
   return json({ access_token: accessToken, refresh_token: refreshToken, expires_in: 900, token_type: "Bearer", scope: "identity:read profile:read" })
  }
  const credential = credentials.get(accessTokens.get(request.headers.authorization?.slice(7) ?? "") ?? "")
  if (!credential || credential.revoked) return json({ error: "invalid_token" }, 401)
  if (url.pathname === "/v3/link/userinfo") return json({ id: credential.subject, sub: credential.subject, name: "Owner", ...(profileEmail ? { email: profileEmail } : {}), email_verified: profileEmailVerified, picture: null })
  if (url.pathname === "/v3/linked-accounts") return json({ data: [{ id: `${credential.subject}-account` }], has_more: false })
  if (url.pathname === "/v3/access/profile") {
   if (request.headers["x-linked-account-id"] !== `${credential.subject}-account`) return json({ error: "account_not_granted" }, 403)
   return json({ id: `${credential.subject}-account` })
  }
  return json({ error: "not_found" }, 404)
 })
 await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve))
 const address = server.address(); if (!address || typeof address === "string") throw new Error("Missing fixture port")
 issuer = `http://127.0.0.1:${address.port}`
})
afterAll(async () => {
 for (const child of children) child.kill("SIGTERM")
 await new Promise<void>((resolve, reject) => server?.close(error => error ? reject(error) : resolve()))
 await pool?.end(); await adminPool?.query(`DROP SCHEMA "${schema}" CASCADE`); await adminPool?.end()
})

describe("standard Better Auth with simulated OFAuth issuer", () => {
 for (const method of ["client_secret_basic", "client_secret_post"] as const) {
  it(`links an existing different-email user with ${method}, protected tokens and explicit provider account selection`, async () => {
   subject = `owner-${method}`; profileEmail = `${subject}@example.com`
   const auth = createApp({ allowDifferentEmails: true, method, stock: true })
   const app = await signup(auth)
   const flow = await authorize(auth, app.cookie)
   expect(new URL(flow.authorizationURL).searchParams.get("scope")).toBe("identity:read profile:read")
   expect((await complete(auth, flow)).headers.get("location")).toBe("/done")
   expect((await auth.api.getSession({ headers: headers(app.cookie) }))?.user).toMatchObject({ id: app.user.id, email: app.user.email, name: "Application user", emailVerified: false })
   const account = await linked(auth, app.cookie)
   expect(account.accountId).toBe(subject)
   const result = await token(auth, app.cookie, account.id)
   expect(result.status).toBe(200)
   const stored = await pool.query('SELECT "accessToken", "refreshToken" FROM account WHERE id = $1', [account.id])
   expect(stored.rows[0].accessToken).not.toBe(result.body.accessToken)
   expect(credentials.has(stored.rows[0].refreshToken)).toBe(false)
   expect(await (await resource(result.body.accessToken)).json()).toMatchObject({ data: [{ id: `${subject}-account` }] })
   expect((await resource(result.body.accessToken, "/v3/access/profile", "foreign-account")).status).toBe(403)
   expect((await resource(result.body.accessToken, "/v3/access/profile", `${subject}-account`)).status).toBe(200)
   expect(authMethods.has(method)).toBe(true)
   const stranger = await signup(auth)
   expect((await token(auth, stranger.cookie, account.id)).status).toBe(400)
  })
 }
 it("rejects different-email linking by default and absent profile email without fabricating an identity", async () => {
  const auth = createApp(); const app = await signup(auth)
  subject = "policy-owner"; profileEmail = "different@example.com"
  expect((await complete(auth, await authorize(auth, app.cookie))).headers.get("location")).toContain("error=")
  expect(await linked(auth, app.cookie)).toBeUndefined()
  profileEmailVerified = false
  expect((await complete(auth, await authorize(auth, app.cookie))).headers.get("location")).toContain("error=")
  profileEmailVerified = true
  profileEmail = undefined
  expect((await complete(auth, await authorize(auth, app.cookie))).headers.get("location")).toContain("error=")
  expect(await linked(auth, app.cookie)).toBeUndefined()
  expect((await auth.api.getSession({ headers: headers(app.cookie) }))?.user.id).toBe(app.user.id)
 })
 it("rejects tampered state, another session and callback replay without consuming legitimate pending state", async () => {
  const auth = createApp({ allowDifferentEmails: true }); const app = await signup(auth)
  subject = "state-owner"; profileEmail = "state@example.com"
  const flow = await authorize(auth, app.cookie)
  const changed = new URL(flow.callback); changed.searchParams.set("state", "foreign-state")
  expect((await complete(auth, { ...flow, callback: changed.href })).headers.get("location")).toContain("error=")
  expect(codes.has(new URL(flow.callback).searchParams.get("code")!)).toBe(true)
  const stranger = await signup(auth)
  expect((await complete(auth, { ...flow, cookie: stranger.cookie })).headers.get("location")).toContain("error=")
  expect(codes.has(new URL(flow.callback).searchParams.get("code")!)).toBe(true)
  expect((await complete(auth, flow)).headers.get("location")).toBe("/done")
  expect((await complete(auth, flow)).headers.get("location")).toContain("error=")
 })
 it("refreshes in two independent processes, retries a lost response after a process restart, and rejects revocation", async () => {
  subject = "concurrent-owner"; profileEmail = "concurrent@example.com"
  const first = await startProcess(); const second = await startProcess()
  try {
   const signup = await first.request("/sign-up/email", "", { email: `process-${crypto.randomUUID()}@example.com`, password: "fixture-only-app-password", name: "Application user" })
   expect(signup.status).toBe(200)
   const cookie = cookies(signup); const user = (await signup.json()).user
   const started = await first.request("/link-social", cookie, { provider: "ofauth", callbackURL: "/done" })
   const consent = await fetch((await started.json()).url, { redirect: "manual" })
   const flowCookie = [cookie, cookies(started)].filter(Boolean).join("; ")
   const callback = new URL(consent.headers.get("location")!)
   expect((await first.request(callback.pathname.replace("/api/auth", "") + callback.search, flowCookie)).headers.get("location")).toBe("/done")
   const account = (await (await first.request("/list-accounts", cookie)).json()).find((account: { providerId: string }) => account.providerId === "ofauth")
   await expire(account.id)
   let release!: () => void; const waiting = new Promise<void>(resolve => { release = resolve })
   let arrivals = 0
   duringRefresh = async () => { if (++arrivals === 2) release(); await waiting }
   const get = async (instance: Awaited<ReturnType<typeof startProcess>>) => {
    const response = await instance.request("/get-access-token", cookie, { accountId: account.id })
    return { status: response.status, body: await response.json() }
   }
   let results: Awaited<ReturnType<typeof get>>[]
   try { results = await Promise.all([get(first), get(second)]) }
   finally { duringRefresh = undefined; release() }
   expect(arrivals).toBe(2)
   for (const result of results) { expect(result.status).toBe(200); expect((await resource(result.body.accessToken)).status).toBe(200) }
   expect(results[0].body.accessToken === results[1].body.accessToken).toBe(false)
   await expire(account.id); loseResponse = true
   expect((await get(first)).status).toBe(400)
   await first.stop()
   const restarted = await startProcess()
   let recovered: Awaited<ReturnType<typeof get>>
   try { recovered = await get(restarted) } finally { await restarted.stop() }
   expect(recovered.status).toBe(200)
   const refreshToken = accessTokens.get(recovered.body.accessToken)!
   const revoked = await fetch(`${issuer}/v3/link/revoke`, { method: "POST", headers: { authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token: refreshToken, token_type_hint: "refresh_token" }) })
   expect(revoked.status).toBe(200)
   expect((await resource(recovered.body.accessToken)).status).toBe(401)
   await expire(account.id)
   expect((await get(second)).status).toBe(400)
   expect((await (await second.request("/get-session", cookie)).json()).user.id).toBe(user.id)
  } finally { await first.stop(); await second.stop() }
 })
 it("retries the renewable credential after a storage failure without an attempt table", async () => {
  subject = "storage-owner"; profileEmail = "storage@example.com"
  const auth = createApp({ allowDifferentEmails: true }); const app = await signup(auth)
  await complete(auth, await authorize(auth, app.cookie)); const account = await linked(auth, app.cookie)
  await expire(account.id)
  // PostgreSQL failure injection preserves the public Better Auth refresh path.
  await pool.query(`CREATE FUNCTION reject_refresh() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW."accessToken" IS DISTINCT FROM OLD."accessToken" THEN RAISE EXCEPTION 'simulated storage outage'; END IF; RETURN NEW; END $$`)
  await pool.query('CREATE TRIGGER reject_refresh BEFORE UPDATE ON account FOR EACH ROW EXECUTE FUNCTION reject_refresh()')
  try { expect((await token(auth, app.cookie, account.id)).status).toBe(400) }
  finally { await pool.query('DROP TRIGGER reject_refresh ON account'); await pool.query('DROP FUNCTION reject_refresh()') }
  expect((await token(createApp(), app.cookie, account.id)).status).toBe(200)
  const tables = await pool.query("SELECT tablename FROM pg_tables WHERE schemaname = $1", [schema])
  expect(tables.rows.map(row => row.tablename)).not.toContain("ofauth_refresh_attempts")
 })
 it("keeps a replacement registration when an old refresh completes after relinking", async () => {
  subject = "relink-owner"; profileEmail = "relink@example.com"
  const auth = createApp({ allowDifferentEmails: true }); const app = await signup(auth)
  await complete(auth, await authorize(auth, app.cookie)); const account = await linked(auth, app.cookie)
  const original = accessTokens.get((await token(auth, app.cookie, account.id)).body.accessToken)!
  await expire(account.id)
  let started!: () => void; const startedPromise = new Promise<void>(resolve => { started = resolve })
  let release!: () => void; const waiting = new Promise<void>(resolve => { release = resolve })
  duringRefresh = async () => { started(); await waiting }
  const pending = token(auth, app.cookie, account.id)
  await startedPromise
  try {
   expect((await complete(auth, await authorize(auth, app.cookie))).headers.get("location")).toBe("/done")
   credentials.get(original)!.revoked = true
  } finally { duringRefresh = undefined; release() }
  expect((await pending).status).toBe(400)
  await expire(account.id)
  // Only the fresh registration can renew after the original credential is revoked.
  expect((await token(createApp(), app.cookie, account.id)).status).toBe(200)
 })
})
