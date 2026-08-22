import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import fs from 'node:fs';

// Optional TLS and Host allow-list, used only by the cross-site end-to-end
// layer (tests/e2e/browser_cross_site). Both are unset in normal development,
// so `npm run dev` keeps serving plain http on localhost exactly as before.
const certPath = process.env.RP_TLS_CERT;
const keyPath = process.env.RP_TLS_KEY;
const https =
	certPath && keyPath
		? { cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) }
		: undefined;
const allowedHosts = process.env.RP_ALLOWED_HOSTS?.split(',').map((host) => host.trim());

export default defineConfig({
	plugins: [sveltekit()],
	// Paired with RP_OUT_DIR (see svelte.config.js): a second dev server in this
	// same project directory needs its own dependency cache too.
	cacheDir: process.env.RP_CACHE_DIR || undefined,
	server: {
		// HMR runs over wss:// once the server is TLS, and the throwaway
		// certificate makes that socket retry noisily. The e2e suite never edits
		// files mid-run, so drop it.
		...(https ? { https, hmr: false } : {}),
		...(allowedHosts ? { allowedHosts } : {})
	}
});
