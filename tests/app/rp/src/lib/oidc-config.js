import { env } from '$env/dynamic/public';

// Runtime configuration shared by every page that talks to the OP.
//
// $env/dynamic/public is read from process.env on each request by the dev
// server and by adapter-node, so this needs no build step and no committed
// .env file. The defaults are the historical hard-coded values, so `npm run
// dev` still talks to a local IdP on :8000 with this RP on :5173; the
// cross-site end-to-end layer (tests/e2e/browser_cross_site) overrides them to
// put the IdP and the RP on two genuinely different registrable domains.
//
// The client id is the one seeded in tests/app/idp/fixtures/seed.json.
export const issuer = env.PUBLIC_RP_ISSUER || 'http://localhost:8000/o';
export const clientId = env.PUBLIC_RP_CLIENT_ID || '2EIxgjlyy5VgCp2fjhEpKLyRtSMMPK0hZ0gBpNdm';
export const rpOrigin = env.PUBLIC_RP_ORIGIN || 'http://localhost:5173';
