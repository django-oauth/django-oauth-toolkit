import { SignJWT, decodeJwt, decodeProtectedHeader, importJWK } from 'jose';
import { fail } from '@sveltejs/kit';

// Demo configuration. These are example values for local end-to-end testing --
// the same posture as the IDP's seeded applications and its OIDC signing key.
// The public half of this key is registered on the "RFC 7523 private_key_jwt
// demo" application in tests/app/idp/fixtures/seed.json.
const IDP_URL = process.env.RP_IDP_URL || 'http://127.0.0.1:8000';
const CLIENT_ID = process.env.RP_PKJ_CLIENT_ID || 'private-key-jwt-demo';
const TOKEN_ENDPOINT = `${IDP_URL}/o/token/`;
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const ALG = 'ES256';

const PRIVATE_JWK = JSON.parse(
	process.env.RP_PKJ_PRIVATE_JWK ||
		JSON.stringify({
			kty: 'EC',
			crv: 'P-256',
			kid: 'demo-rp-key',
			x: 'tS3tFvO_rzqp4FW4XU0M8agahChhDCxvfwkAOUf0r1w',
			y: 'RXB1hhJu-vYd1Go5VyQ5gcQcxnNmCaCmE05mBrJ1qM4',
			d: '0QcXCEERHRwHs1XiJFmnzvTwac93g6tFjwl39dwnWv4'
		})
);

// The last assertion this server minted, so the "replay" action can present the
// exact same JWT a second time and show the jti replay cache rejecting it.
let lastAssertion = null;

/**
 * Mint an RFC 7523 section 2.2 client assertion.
 *
 * The private key never leaves the server: this is why the demo lives in a
 * +page.server.js and not in the browser. A public client (like the SPA on the
 * other tabs) cannot use private_key_jwt at all.
 */
async function mintAssertion() {
	const key = await importJWK(PRIVATE_JWK, ALG);
	const now = Math.floor(Date.now() / 1000);
	return await new SignJWT({
		// iss and sub are both the client_id (RFC 7523 section 3).
		iss: CLIENT_ID,
		sub: CLIENT_ID,
		// The audience identifies the AS; the token endpoint URL is always accepted.
		aud: TOKEN_ENDPOINT,
		jti: crypto.randomUUID(),
		iat: now,
		nbf: now,
		exp: now + 60
	})
		.setProtectedHeader({ alg: ALG, kid: PRIVATE_JWK.kid, typ: 'JWT' })
		.sign(key);
}

async function requestToken(assertion) {
	const body = new URLSearchParams({
		grant_type: 'client_credentials',
		client_assertion_type: ASSERTION_TYPE,
		client_assertion: assertion
	});
	const response = await fetch(TOKEN_ENDPOINT, {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body
	});
	const text = await response.text();
	let json;
	try {
		json = JSON.parse(text);
	} catch {
		json = null;
	}
	return {
		assertion,
		header: decodeProtectedHeader(assertion),
		claims: decodeJwt(assertion),
		// Rendered so the page shows the exact form body that was posted; note
		// there is no client_secret anywhere in it.
		requestBody: body.toString(),
		status: response.status,
		response: json,
		rawResponse: json ? null : text
	};
}

export function load() {
	return {
		clientId: CLIENT_ID,
		tokenEndpoint: TOKEN_ENDPOINT,
		kid: PRIVATE_JWK.kid,
		alg: ALG,
		hasReplayable: lastAssertion !== null
	};
}

export const actions = {
	// Sign a brand new assertion and exchange it for an access token.
	token: async () => {
		try {
			lastAssertion = await mintAssertion();
			return { ...(await requestToken(lastAssertion)), replayed: false };
		} catch (err) {
			return fail(502, { error: `could not reach ${TOKEN_ENDPOINT}: ${err.message}` });
		}
	},

	// Re-present the previous assertion. The AS rejects it with invalid_client:
	// a jti is single use, so a captured assertion cannot be replayed.
	replay: async () => {
		if (!lastAssertion) {
			return fail(400, { error: 'Request a token first, then replay it.' });
		}
		try {
			return { ...(await requestToken(lastAssertion)), replayed: true };
		} catch (err) {
			return fail(502, { error: `could not reach ${TOKEN_ENDPOINT}: ${err.message}` });
		}
	}
};
