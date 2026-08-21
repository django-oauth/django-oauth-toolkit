import { SignJWT, decodeJwt, decodeProtectedHeader, importJWK } from 'jose';
import { fail } from '@sveltejs/kit';

// Demo configuration. These are example values for local end-to-end testing --
// the same posture as the IDP's seeded applications and its OIDC signing key.
// The public half of this key is registered on the "demo-jwt-bearer"
// application in tests/app/idp/fixtures/seed.json.
const IDP_URL = process.env.RP_IDP_URL || 'http://127.0.0.1:8000';
const CLIENT_ID = process.env.RP_JWT_BEARER_CLIENT_ID || 'demo-jwt-bearer';
// The resource owner the client acts on behalf of. The default IDP subject
// resolver maps `sub` to a Django username. The seed data ships a non-privileged
// `demo-user`: the default resolver refuses staff/superuser subjects (an
// assertion mints a token without the user's interactive consent), so asserting
// the seeded `superuser` would be rejected unless
// JWT_BEARER_ALLOW_PRIVILEGED_SUBJECTS is enabled.
const SUBJECT = process.env.RP_JWT_BEARER_SUBJECT || 'demo-user';
const TOKEN_ENDPOINT = `${IDP_URL}/o/token/`;
const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const ALG = 'ES256';

const PRIVATE_JWK = JSON.parse(
	process.env.RP_JWT_BEARER_PRIVATE_JWK ||
		JSON.stringify({
			kty: 'EC',
			crv: 'P-256',
			kid: 'demo-jwt-bearer-key',
			x: 'HAkJw3a3LJaPb3Gtb-ovfY2_uGuXbeadWUTB1F4OGXk',
			y: 'cX5_RlhBx4gtpRKFmTC7esWdTZmxuOapL37OdKLD6hM',
			d: 'ftlyffRfHo8Jqqb0tkETd_GJo2hb2d9_4Vnq0o9MYow'
		})
);

// The last assertion this server minted, so the "replay" action can present the
// exact same JWT a second time and show the jti replay cache rejecting it.
let lastAssertion = null;

/**
 * Mint an RFC 7523 section 2.1 JWT bearer grant assertion.
 *
 * Unlike the private_key_jwt demo (RFC 7523 section 2.2, client authentication),
 * here `iss` is the client and `sub` is the *resource owner* the client is
 * acting for -- the assertion is exchanged for an access token bound to that
 * user, with no interactive authorization step. The private key never leaves the
 * server, which is why the demo lives in a +page.server.js.
 */
async function mintAssertion() {
	const key = await importJWK(PRIVATE_JWK, ALG);
	const now = Math.floor(Date.now() / 1000);
	return await new SignJWT({
		// iss is the client acting as issuer; sub is the resource owner.
		iss: CLIENT_ID,
		sub: SUBJECT,
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
	// No explicit scope: the demo IDP ships the default scope set, so the grant
	// falls back to the application's default scopes rather than risk an
	// invalid_scope for a scope the out-of-the-box IDP does not define.
	const body = new URLSearchParams({
		grant_type: GRANT_TYPE,
		assertion,
		client_id: CLIENT_ID
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
		// Rendered so the page shows the exact form body that was posted.
		requestBody: body.toString(),
		status: response.status,
		response: json,
		rawResponse: json ? null : text
	};
}

export function load() {
	return {
		clientId: CLIENT_ID,
		subject: SUBJECT,
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

	// Re-present the previous assertion. The AS rejects it with invalid_grant:
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
