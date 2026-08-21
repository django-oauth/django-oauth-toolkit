// OIDC Backchannel Logout Endpoint for SvelteKit RP
// Receives POST requests from the OP with a logout_token (JWT)

import { sendLogoutEvent } from '../sseClients.js';
import { validateLogoutToken } from '../validateLogoutToken.js';

const corsHeaders = {
	'Access-Control-Allow-Origin': '*',
	'Access-Control-Allow-Methods': 'POST, OPTIONS',
	'Access-Control-Allow-Headers': 'Content-Type',
	Accept: '*'
};

/**
 * POST /api/backchannel-logout
 * Receives a logout_token from the OP and invalidates the user session.
 */
export async function POST({ request }) {
	const headers = {
		'Content-Type': 'application/json',
		...corsHeaders
	};
	try {
		let logout_token;
		const contentType = request.headers.get('content-type') || '';
		if (contentType.includes('application/json')) {
			logout_token = (await request.json()).logout_token;
		} else if (contentType.includes('application/x-www-form-urlencoded')) {
			logout_token = (await request.formData()).get('logout_token');
		} else {
			return new Response(JSON.stringify({ error: 'Unsupported content type' }), {
				status: 415,
				headers
			});
		}
		if (!logout_token) {
			return new Response(JSON.stringify({ error: 'Missing logout_token' }), {
				status: 400,
				headers
			});
		}

		// Validate the logout_token (JWT) according to OIDC spec
		let payload;
		try {
			payload = await validateLogoutToken(logout_token);
		} catch (e) {
			console.log('Logout token validation error', e);
			return new Response(
				JSON.stringify({ error: 'Invalid logout_token', details: e.message }),
				{
					status: 400,
					headers
				}
			);
		}

		// Notify the browser over SSE. DOT does not issue a sid claim yet, so the
		// subscription is keyed on sub; keep using sub here so the two agree.
		try {
			sendLogoutEvent(payload.sub, {
				sub: payload.sub,
				sid: payload.sid,
				event: 'logout'
			});
		} catch (e) {
			console.log('Error sending logout sse events to frontend', e);
		}
		console.log('Processed backchannel logout for', { sub: payload.sub, sid: payload.sid });
		return new Response(
			JSON.stringify({ status: 'logout processed', sub: payload?.sub, sid: payload?.sid }),
			{
				status: 200,
				headers
			}
		);
	} catch (err) {
		console.log('Error processing backchannel logout request', err);
		return new Response(JSON.stringify({ error: 'Invalid request', details: err.message }), {
			status: 400,
			headers
		});
	}
}

// Handle preflight OPTIONS requests for CORS
export async function OPTIONS() {
	return new Response(null, {
		status: 204,
		headers: corsHeaders
	});
}
