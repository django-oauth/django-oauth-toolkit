<script>
	// Subscribes to the RP's own SSE endpoint so a logout token the OP delivers to
	// the server-side /api/backchannel-logout route can clear this tab's session.
	import { browser } from '$app/environment';
	import { OIDC_CONTEXT_CLIENT_PROMISE, isAuthenticated, userInfo } from '@dopry/svelte-oidc';
	import { getContext, onDestroy } from 'svelte';

	const oidcPromise = getContext(OIDC_CONTEXT_CLIENT_PROMISE);

	let eventSource = null;

	// DOT does not issue a sid claim yet, so fall back to sub as the session key.
	$: sid = $userInfo?.sid || $userInfo?.sub;

	$: {
		// Reactively manage the SSE connection when sid or authentication changes
		if (browser && $isAuthenticated && sid) {
			if (eventSource) {
				eventSource.close();
			}
			eventSource = new EventSource(`/api/logout-events?sid=${sid}`);
			eventSource.addEventListener('logout', async (event) => {
				const oidcClient = await oidcPromise;
				await oidcClient.removeUser();
				console.log('You have been logged out by the OP (backchannel logout).', event);
			});
		} else if (eventSource) {
			eventSource.close();
			eventSource = null;
		}
	}

	onDestroy(() => {
		if (eventSource) {
			eventSource.close();
			eventSource = null;
		}
	});
</script>
