// Production entry point for the demo RP: adapter-node's handler, with one exception.
//
// An OpenID Provider delivers a back-channel logout token server to server (OpenID
// Connect Back-Channel Logout 1.0 section 2.5): a form POST that carries no Origin
// header. In a production build SvelteKit forbids every form POST without a matching
// Origin, before any hook runs, so the logout endpoint would answer 403. Here such a
// request to that one endpoint is given the RP's own origin. Nothing is lost by it: the
// endpoint authenticates the request by validating the signed logout token (section
// 2.6), not by where it came from. Every other route keeps SvelteKit's CSRF protection.
//
// `npm run dev` needs none of this: SvelteKit does not check origins in development.

import http from 'node:http';

import { handler } from './build/handler.js';

const BACKCHANNEL_LOGOUT_PATH = '/api/backchannel-logout';

// The origin SvelteKit will compute for the request, mirroring adapter-node's own rules
// (the ORIGIN, PROTOCOL_HEADER, HOST_HEADER and PORT_HEADER environment variables).
function ownOrigin(headers) {
	if (process.env.ORIGIN) return process.env.ORIGIN;
	const header = (name) => name && headers[name.toLowerCase()];
	const protocol = header(process.env.PROTOCOL_HEADER) || 'https';
	const host = header(process.env.HOST_HEADER) || headers.host;
	const port = header(process.env.PORT_HEADER);
	return port ? `${protocol}://${host}:${port}` : `${protocol}://${host}`;
}

const server = http.createServer((req, res) => {
	const path = (req.url || '').split('?')[0];
	if (req.method === 'POST' && path === BACKCHANNEL_LOGOUT_PATH && !req.headers.origin) {
		// SvelteKit compares against the URL's origin, which lowercases the host and drops a
		// default port -- what a proxy reporting port 443 would otherwise make differ.
		try {
			req.headers.origin = new URL(ownOrigin(req.headers)).origin;
		} catch {
			// No usable host: leave it to SvelteKit, which refuses the request.
		}
	}
	handler(req, res);
});

const host = process.env.HOST || '0.0.0.0';
const port = Number(process.env.PORT || 3000);
server.listen(port, host, () => {
	console.log(`Listening on http://${host}:${port}`);
});

// Shut down on SIGTERM and SIGINT as adapter-node's own entry point does, which replacing it
// would otherwise lose: in a container this runs as PID 1, which gets no default handling
// for those signals, so `docker stop` would wait out its grace period.
let shutdownTimer;
function shutdown() {
	if (shutdownTimer) return;
	server.closeIdleConnections();
	server.close(() => clearTimeout(shutdownTimer));
	shutdownTimer = setTimeout(
		() => server.closeAllConnections(),
		Number(process.env.SHUTDOWN_TIMEOUT || 30) * 1000
	);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
