export const origin = (value: string): string => {
	const url = new URL(value)
	if (url.username || url.password || url.pathname !== "/" || url.search || url.hash ||
		(url.protocol !== "https:" && !(url.protocol === "http:" && ["127.0.0.1", "[::1]", "localhost"].includes(url.hostname)))) {
		throw new Error("OFAuth URLs must be HTTPS origins (HTTP is allowed on loopback for development)")
	}
	return url.origin
}
