// Logout token validation, following OpenID Connect Back-Channel Logout 1.0 section 2.6.
import { createRemoteJWKSet, jwtVerify } from 'jose';

// The OP this demo RP is registered with. ISSUER must match the iss claim the IdP mints,
// which is OIDC_ISS_ENDPOINT in tests/app/idp/idp/settings.py, and AUDIENCE is this RP's
// client_id from fixtures/seed.json.
const ISSUER = 'http://localhost:8000/o';
const AUDIENCE = '2EIxgjlyy5VgCp2fjhEpKLyRtSMMPK0hZ0gBpNdm';
const JWKS_URI = `${ISSUER}/.well-known/jwks.json`;

const JWKS = createRemoteJWKSet(new URL(JWKS_URI));

export async function validateLogoutToken(token) {
	try {
		// Steps 2-4: signature, alg, and the iss/aud/iat/exp claims. Section 4.1 recommends
		// explicit typing and warns that *requiring* it breaks older OPs -- safe to require
		// here, because the IdP this demo is paired with always types its logout tokens.
		const { payload } = await jwtVerify(token, JWKS, {
			algorithms: ['RS256'],
			issuer: ISSUER,
			audience: AUDIENCE,
			typ: 'logout+jwt'
		});
		// Step 6: events must declare this a logout token.
		if (
			!payload.events ||
			!payload.events['http://schemas.openid.net/event/backchannel-logout']
		) {
			throw new Error('Missing backchannel-logout event');
		}
		// Step 5: sub or sid must be present.
		if (!payload.sub && !payload.sid) {
			throw new Error('Logout token missing sub and sid');
		}
		// Step 7: a nonce is prohibited -- its presence means someone is trying to pass a
		// logout token off as an ID token.
		if ('nonce' in payload) {
			throw new Error('Logout token must not contain a nonce');
		}
		return payload;
	} catch (e) {
		throw new Error('Logout token validation failed: ' + e.message);
	}
}
