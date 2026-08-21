import adapter from '@sveltejs/adapter-node';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	// Consult https://kit.svelte.dev/docs/integrations#preprocessors
	// for more information about preprocessors
	preprocess: vitePreprocess(),

	kit: {
		// build to run in containerized node.js environment
		adapter: adapter(),
		// Two dev servers running out of this one project directory would
		// otherwise share .svelte-kit/ and invalidate each other's module graph
		// mid-request. The cross-site end-to-end layer sets RP_OUT_DIR so its
		// server gets its own; everything else keeps the default.
		outDir: process.env.RP_OUT_DIR || '.svelte-kit',
		// The OP delivers backchannel logout tokens as a cross-origin form POST to
		// /api/backchannel-logout, which SvelteKit's CSRF protection rejects unless
		// the IdP's origin is trusted.
		csrf: {
			trustedOrigins: ['http://localhost:8000']
		}
	}
};

export default config;
