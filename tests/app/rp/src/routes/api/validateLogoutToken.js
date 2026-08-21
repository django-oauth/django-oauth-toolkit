// Utility for OIDC logout token validation using jose
import { createRemoteJWKSet, jwtVerify } from 'jose';

// The OP's JWKS endpoint; matches the issuer the RP is configured against.
const JWKS_URI = 'http://localhost:8000/o/.well-known/jwks.json';

const JWKS = createRemoteJWKSet(new URL(JWKS_URI));

export async function validateLogoutToken(token) {
	try {
		const { payload } = await jwtVerify(token, JWKS, {
			algorithms: ['RS256']
			// audience, issuer, etc. can be checked here if needed
		});
		// OIDC Backchannel Logout Token must have events.logout
		if (
			!payload.events ||
			!payload.events['http://schemas.openid.net/event/backchannel-logout']
		) {
			throw new Error('Missing backchannel-logout event');
		}
		// sub or sid must be present
		if (!payload.sub && !payload.sid) {
			throw new Error('Logout token missing sub and sid');
		}
		return payload;
	} catch (e) {
		throw new Error('Logout token validation failed: ' + e.message);
	}
}
