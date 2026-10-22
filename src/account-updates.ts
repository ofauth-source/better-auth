import type { Account, BetterAuthPlugin } from "better-auth"
import { APIError, createAuthMiddleware } from "better-auth/api"
import { getAccountCookie } from "better-auth/cookies"
import { getCurrentAdapter, runWithAdapter } from "@better-auth/core/context"

/** Protect native token persistence without changing Better Auth's OAuth flow. */
export const ofauthAccountProtection = (): BetterAuthPlugin => ({
	id: "ofauth-account-protection",
	hooks: {
		before: [{
			matcher: (context: { path?: string }) => ["/get-access-token", "/refresh-token", "/account-info"].includes(context.path ?? ""),
			handler: createAuthMiddleware(async (context) => {
				const selection = context.body ?? context.query
				if (selection && typeof selection === "object" && "useAccountCookie" in selection && selection.useAccountCookie && (await getAccountCookie(context))?.providerId === "ofauth") {
					throw new APIError("BAD_REQUEST", { message: "Select the saved OFAuth account by accountId" })
				}
				const original = context.context.internalAdapter
				const snapshots = new Map<string, Account>()
				return { context: { context: { internalAdapter: {
					...original,
					findAccounts: async (userId: string) => {
						const accounts = await original.findAccounts(userId)
						for (const account of accounts) if (account.providerId === "ofauth") snapshots.set(account.id, account)
						return accounts
					},
					updateAccount: async (id: string, data: Partial<Account>) => {
						const snapshot = snapshots.get(id)
						if (!snapshot) return original.updateAccount(id, data)
						const adapter = await getCurrentAdapter(context.context.adapter)
						const protectedAdapter: typeof context.context.adapter = {
							...context.context.adapter,
							...adapter,
							update: async (input) => {
								if (input.model !== "account" || !input.where.some(condition => condition.field === "id" && condition.value === id)) return adapter.update(input)
								// Keep the stable credential's ciphertext unchanged across renewals.
								const { refreshToken: _stableCredential, ...update } = input.update
								return adapter.update({ ...input, update, where: [
									...input.where,
									{ field: "id", value: id },
									{ field: "userId", value: snapshot.userId },
									{ field: "providerId", value: "ofauth" },
									{ field: "accountId", value: snapshot.accountId },
									{ field: "refreshToken", value: snapshot.refreshToken ?? null },
								] })
							},
						}
						const updated = await runWithAdapter(protectedAdapter, async () => {
							if (await getCurrentAdapter(context.context.adapter) !== protectedAdapter) {
								throw new APIError("INTERNAL_SERVER_ERROR", { message: "OFAuth account protection is unavailable" })
							}
							return original.updateAccount(id, data)
						})
						if (!updated) throw new APIError("BAD_REQUEST", { message: "OFAuth connection changed during refresh" })
						return updated
					},
				} } } }
			}),
		}],
	},
})
