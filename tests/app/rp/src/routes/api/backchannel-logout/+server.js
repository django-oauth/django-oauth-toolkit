// OIDC Back-Channel Logout endpoint for the demo RP.
//
// The OP POSTs a logout_token here server to server (OpenID Connect Back-Channel Logout 1.0
// section 2.5), so this is not a browser endpoint: it takes only the form encoding section
// 2.5 specifies, and has no CORS handling. It is authenticated by validating the signed
// logout token (section 2.6), not by the request's origin.

import { sendLogoutEvent } from '../sseClients.js';
import { validateLogoutToken } from '../validateLogoutToken.js';

// Section 2.8: a response must not be cached where it could interfere with a later logout
// request.
const headers = {
	'Content-Type': 'application/json',
	'Cache-Control': 'no-store'
};

// Section 2.8: a request that is invalid, or a logout that failed, is answered with 400 and
// the error parameters of OAuth 2.0 section 5.2.
function badRequest(description) {
	return new Response(
		JSON.stringify({ error: 'invalid_request', error_description: description }),
		{
			status: 400,
			headers
		}
	);
}

/**
 * POST /api/backchannel-logout
 * Receives a logout_token from the OP and logs the user's browser sessions out.
 */
export async function POST({ request }) {
	const contentType = request.headers.get('content-type') || '';
	if (!contentType.includes('application/x-www-form-urlencoded')) {
		return badRequest('The logout request must be application/x-www-form-urlencoded');
	}

	let logoutToken;
	try {
		logoutToken = (await request.formData()).get('logout_token');
	} catch (e) {
		return badRequest('The logout request body could not be read');
	}
	if (!logoutToken) {
		return badRequest('Missing logout_token');
	}

	let payload;
	try {
		payload = await validateLogoutToken(logoutToken);
	} catch (e) {
		console.log('Logout token validation error', e);
		return badRequest(`Invalid logout_token: ${e.message}`);
	}

	// Notify the browser over SSE. DOT does not issue a sid claim yet, so the subscription
	// is keyed on sub; keep using sub here so the two agree.
	try {
		sendLogoutEvent(payload.sub, { sub: payload.sub, sid: payload.sid, event: 'logout' });
	} catch (e) {
		console.log('Error sending logout sse events to frontend', e);
	}
	console.log('Processed backchannel logout for', { sub: payload.sub, sid: payload.sid });
	return new Response(null, { status: 200, headers: { 'Cache-Control': 'no-store' } });
}
