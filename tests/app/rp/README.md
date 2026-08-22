# create-svelte

**Please Read ../README.md First**

Everything you need to build a Svelte project, powered by [`create-svelte`](https://github.com/sveltejs/kit/tree/master/packages/create-svelte).

## Creating a project

If you're seeing this, you've probably already done this step. Congrats!

```bash
# create a new project in the current directory
npm create svelte@latest

# create a new project in my-app
npm create svelte@latest my-app
```

## Configuration

The OIDC code-flow page (`/`) and the silent-login probe (`/silent`) read their
configuration at runtime, so the same app can be pointed at a different
authorization server without a rebuild. Every variable is optional; the defaults
reproduce the historical hard-coded values.

| Variable                     | Default                   | Purpose                                                                    |
| ---------------------------- | ------------------------- | -------------------------------------------------------------------------- |
| `PUBLIC_RP_ISSUER`           | `http://localhost:8000/o` | The OP's issuer URL.                                                       |
| `PUBLIC_RP_CLIENT_ID`        | the seed OIDC client      | The client to authenticate as.                                             |
| `PUBLIC_RP_ORIGIN`           | `http://localhost:5173`   | This RP's own origin, used for the redirect and post-logout redirect URIs. |
| `RP_TLS_CERT` / `RP_TLS_KEY` | unset                     | Serve the dev server over HTTPS with this certificate.                     |
| `RP_ALLOWED_HOSTS`           | unset                     | Comma-separated hostnames Vite will answer for, beyond localhost.          |

These are read once in `src/lib/oidc-config.js`, which both pages import.

The `/device` and `/par` demos remain pinned to `localhost` / `127.0.0.1`; only
the pages above honour `PUBLIC_RP_*`.

The end-to-end suite's cross-site layer
(`tests/e2e/browser_cross_site`) uses all of these to run this app on
`https://rp.test:5443` against an IdP on `https://idp.test:8443`.

## Developing

Once you've created a project and installed dependencies with `npm install` (or `pnpm install` or `yarn`), start a development server:

```bash
npm run dev

# or start the server and open the app in a new browser tab
npm run dev -- --open
```

## Building

To create a production version of your app:

```bash
npm run build
```

You can preview the production build with `npm run preview`.

> To deploy your app, you may need to install an [adapter](https://kit.svelte.dev/docs/adapters) for your target environment.
