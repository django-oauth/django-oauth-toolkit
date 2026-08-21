/**
 * RFC 9126 Pushed Authorization Requests (PAR) — SvelteKit *server* demo.
 *
 * PAR is a back-channel flow, so the push MUST happen server-side: this module
 * (running in the SvelteKit Node server, never the browser) holds the client
 * secret and POSTs the authorization-request parameters directly to the IdP's
 * `/o/par/` endpoint. Only the resulting `client_id` + `request_uri` travel
 * through the user agent to the authorization endpoint.
 *
 * The demo IdP requires PKCE, so the server also generates the PKCE
 * verifier/challenge (pushing the challenge, exchanging with the verifier) and
 * keeps the verifier + state + request_uri in httpOnly cookies across the
 * front-channel round-trip.
 */
import { fail } from '@sveltejs/kit';

import type { Actions, PageServerLoad } from './$types';

const IDP_URL = 'http://localhost:8000';
const CLIENT_ID = 'par-demo-confidential';
const CLIENT_SECRET = 'par-demo-secret';
const REDIRECT_URI = 'http://localhost:5173/par';
const SCOPE = 'openid';

const COOKIE_OPTS = { path: '/par', httpOnly: true, sameSite: 'lax' as const, maxAge: 300 };

function base64url(bytes: Uint8Array): string {
	let binary = '';
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomBase64url(length: number): string {
	return base64url(crypto.getRandomValues(new Uint8Array(length)));
}

async function s256Challenge(verifier: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
	return base64url(new Uint8Array(digest));
}

function authorizeUrl(requestUri: string): string {
	const params = new URLSearchParams({ client_id: CLIENT_ID, request_uri: requestUri });
	return `${IDP_URL}/o/authorize/?${params.toString()}`;
}

/** Handle the authorization response (callback) leg: exchange the code for tokens. */
export const load: PageServerLoad = async ({ url, cookies, fetch }) => {
	const error = url.searchParams.get('error');
	if (error) {
		return { error, errorDescription: url.searchParams.get('error_description') };
	}

	const code = url.searchParams.get('code');
	if (!code) {
		return {}; // Initial visit: show the "push" button.
	}

	// Callback: validate state, then exchange the code server-side (with the PKCE verifier).
	const returnedState = url.searchParams.get('state');
	const expectedState = cookies.get('par_state');
	const verifier = cookies.get('par_verifier');
	const requestUri = cookies.get('par_request_uri');
	for (const name of ['par_state', 'par_verifier', 'par_request_uri']) {
		cookies.delete(name, { path: '/par' });
	}

	if (!expectedState || returnedState !== expectedState) {
		return {
			error: 'state_mismatch',
			errorDescription: 'The state did not match the pushed request.'
		};
	}

	const body = new URLSearchParams({
		grant_type: 'authorization_code',
		code,
		redirect_uri: REDIRECT_URI,
		client_id: CLIENT_ID,
		client_secret: CLIENT_SECRET,
		code_verifier: verifier ?? ''
	});
	const resp = await fetch(`${IDP_URL}/o/token/`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body
	});
	const tokens = await resp.json();
	return { requestUri, tokens, tokenStatus: resp.status };
};

export const actions: Actions = {
	/** Back-channel push: the server posts the request to /o/par/ and gets a request_uri. */
	push: async ({ cookies, fetch }) => {
		const state = randomBase64url(16);
		const verifier = randomBase64url(32);
		const challenge = await s256Challenge(verifier);

		const body = new URLSearchParams({
			client_id: CLIENT_ID,
			client_secret: CLIENT_SECRET,
			response_type: 'code',
			redirect_uri: REDIRECT_URI,
			scope: SCOPE,
			state,
			code_challenge: challenge,
			code_challenge_method: 'S256'
		});
		const resp = await fetch(`${IDP_URL}/o/par/`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body
		});
		if (resp.status !== 201) {
			return fail(resp.status, { parError: await resp.text() });
		}
		const data = await resp.json();
		const requestUri: string = data.request_uri;

		// Carry the PKCE verifier + state + request_uri across the front-channel round-trip.
		cookies.set('par_state', state, COOKIE_OPTS);
		cookies.set('par_verifier', verifier, COOKIE_OPTS);
		cookies.set('par_request_uri', requestUri, COOKIE_OPTS);

		return { requestUri, expiresIn: data.expires_in, authorizeUrl: authorizeUrl(requestUri) };
	}
};
