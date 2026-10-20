import { defineConfig } from "tsup"

export default defineConfig({
	entry: ["src/index.ts", "src/server.ts", "src/webhooks.ts"],
	format: ["esm"],
	dts: true,
	clean: true,
	sourcemap: true,
})
