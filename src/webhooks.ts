import { createAuthEndpoint, type AuthEndpoint } from "better-auth/api"
import type { WebhookEvent, WebhookEventOf, WebhookEventType } from "@ofauth/onlyfans-sdk"

export type OFAuthWebhookAccount = { id: string; userId: string; accountId: string; providerId: string }

export type OFAuthWebhookHandlers = {
	[Type in WebhookEventType]?: (context: { event: WebhookEventOf<Type>; account: OFAuthWebhookAccount }) => void | Promise<void>
}

export type OFAuthWebhookOptions = {
	secret: string
	/** Resolve the person's OFAuth subject from metadata recorded by onAuthorization. */
	resolveAccount: (event: WebhookEvent) => Promise<string | null>
	/** Durably deduplicate eventId and apply stream order; commit only after work succeeds. */
	processEvent: (event: WebhookEvent, work: () => Promise<void>) => Promise<void>
	handlers: OFAuthWebhookHandlers
}

/** Registers a signed webhook endpoint on Better Auth's router. */
export function ofauthWebhookEndpoint(options: OFAuthWebhookOptions): AuthEndpoint<"/ofauth/webhooks", {
	method: "POST"; disableBody: true; cloneRequest: true; metadata: { isAction: false }
}, Response> {
	if (!options.secret.trim()) throw new Error("OFAuth webhook signing secret is required")
	return createAuthEndpoint("/ofauth/webhooks", {
		method: "POST",
		disableBody: true,
		cloneRequest: true,
		metadata: { isAction: false },
	}, async (ctx) => {
		// Keep the SDK optional for apps that only use sign-in.
		const { verifyWebhookRequest, isWebhookVerificationError } = await import("@ofauth/onlyfans-sdk")
		try {
			if (!ctx.request) return Response.json({ error: "missing_request" }, { status: 400 })
			const event = await verifyWebhookRequest<unknown>(ctx.request, options.secret)
			if (!isEnvelope(event)) return Response.json({ error: "invalid_event" }, { status: 400 })
			if (!Object.hasOwn(options.handlers, event.type) || !options.handlers[event.type]) return new Response(null, { status: 204 })
			const subject = await options.resolveAccount(event)
			if (!subject) return Response.json({ error: "account_binding_pending" }, { status: 503 })
			const accounts = await ctx.context.adapter.findMany<OFAuthWebhookAccount>({
				model: "account", limit: 2,
				select: ["id", "userId", "accountId", "providerId"],
				where: [{ field: "providerId", value: "ofauth" }, { field: "accountId", value: subject }],
			})
			if (accounts.length !== 1) return Response.json({ error: "account_binding_pending" }, { status: 503 })
			const handler = options.handlers[event.type] as (context: { event: WebhookEvent; account: OFAuthWebhookAccount }) => void | Promise<void>
			const { id, userId, accountId, providerId } = accounts[0]
			await options.processEvent(event, async () => { await handler({ event, account: { id, userId, accountId, providerId } }) })
			return new Response(null, { status: 204 })
		} catch (error) {
			if (isWebhookVerificationError(error)) return Response.json({ error: "invalid_webhook" }, { status: 401 })
			return Response.json({ error: "webhook_processing_failed" }, { status: 500 })
		}
	})
}

const isEnvelope = (value: unknown): value is WebhookEvent => {
	if (!value || typeof value !== "object") return false
	const event = value as Record<string, unknown>
	return ["eventId", "type", "authorizationId", "externalOauthClientId", "integrationId"].every((field) => typeof event[field] === "string" && !!event[field]) &&
		event.schemaVersion === "1" && ["test", "live", "sandbox"].includes(String(event.environment)) &&
		typeof event.test === "boolean" && typeof event.order === "number" && Number.isSafeInteger(event.order) && event.order >= 0 &&
		typeof event.occurredAt === "string" && Number.isFinite(Date.parse(event.occurredAt)) &&
		(event.linkedAccountId === null || typeof event.linkedAccountId === "string") &&
		!!event.data && typeof event.data === "object" && !Array.isArray(event.data)
}
