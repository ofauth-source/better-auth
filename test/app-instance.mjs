// Real, isolated Better Auth process. Point these endpoints at either the explicitly
// simulated issuer in oauth.e2e.test.ts or the actual isolated OFAuth Worker.
import { createServer } from "node:http"
import { betterAuth } from "better-auth"
import { genericOAuth } from "better-auth/plugins/generic-oauth"
import { Pool } from "pg"

const schema = process.env.OFAUTH_TEST_SCHEMA
if (!schema || !/^[a-z0-9_]+$/.test(schema)) throw new Error("A dedicated test schema is required")
const apiURL = process.env.OFAUTH_API_URL
const authURL = process.env.OFAUTH_AUTH_URL ?? apiURL
if (!apiURL) throw new Error("An isolated issuer origin is required")
const pool = new Pool({ connectionString: process.env.POSTGRES_URL ?? "postgres://ofauth:ofauth@localhost:61700/ofauth", options: `-c search_path=${schema}` })
const auth = betterAuth({
 database: pool,
 baseURL: process.env.OFAUTH_APP_ORIGIN ?? "http://localhost:3000",
 secret: "fixture-only-better-auth-secret-at-least-32-characters",
 logger: { disabled: true },
 emailAndPassword: { enabled: true },
 account: { encryptOAuthTokens: true, accountLinking: { enabled: true, allowDifferentEmails: true } },
 plugins: [genericOAuth({ config: [{
  providerId: "ofauth",
  clientId: process.env.OFAUTH_CLIENT_ID,
  clientSecret: process.env.OFAUTH_CLIENT_SECRET,
  authorizationUrl: `${authURL}/v3/authorize`,
  tokenUrl: `${apiURL}/v3/link/token`,
  userInfoUrl: `${apiURL}/v3/link/userinfo`,
  tokenEndpointAuth: { method: "client_secret_basic" },
  scopes: ["identity:read", "profile:read"], pkce: true,
 }] })],
})
const server = createServer(async (request, response) => {
 try {
  const chunks = []; for await (const chunk of request) chunks.push(Buffer.from(chunk))
  const result = await auth.handler(new Request(new URL(request.url, auth.options.baseURL), {
   method: request.method,
   headers: request.headers,
   ...(chunks.length ? { body: Buffer.concat(chunks) } : {}),
  }))
  const resultHeaders = Object.fromEntries(result.headers)
  const cookies = result.headers.getSetCookie()
  if (cookies.length) resultHeaders["set-cookie"] = cookies
  response.writeHead(result.status, resultHeaders)
  response.end(Buffer.from(await result.arrayBuffer()))
 } catch { response.writeHead(500); response.end() }
})
server.listen(0, "127.0.0.1", () => {
 const address = server.address()
 process.stdout.write(`${JSON.stringify({ port: address.port })}\n`)
})
process.on("SIGTERM", () => { server.close(async () => { await pool.end(); process.exit(0) }) })
