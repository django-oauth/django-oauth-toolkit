<script>
	import { browser } from '$app/environment';
	import { clientId, issuer, rpOrigin } from '$lib/oidc-config';
	import { onMount } from 'svelte';

	const redirectUri = `${rpOrigin}/silent-callback.html`;

	// How long to wait for the iframe to report back before calling it a
	// timeout. A hidden iframe that never resolves would otherwise look
	// indistinguishable from one that is merely slow.
	const TIMEOUT_MS = 15000;

	let outcome = 'pending';
	let detail = '';
	let src = '';

	function handleMessage(event) {
		if (event.origin !== window.location.origin) return;
		if (!event.data || event.data.type !== 'silent-login-result') return;
		const params = new URLSearchParams(event.data.search);
		if (params.get('code')) {
			outcome = 'code';
		} else if (params.get('error')) {
			outcome = params.get('error');
		} else {
			outcome = 'no-parameters';
		}
		detail = event.data.search;
	}

	onMount(() => {
		window.addEventListener('message', handleMessage);
		const params = new URLSearchParams({
			client_id: clientId,
			response_type: 'code',
			redirect_uri: redirectUri,
			scope: 'openid',
			state: 'silent-login-probe',
			prompt: 'none'
		});
		src = `${issuer}/authorize/?${params.toString()}`;
		const timer = setTimeout(() => {
			if (outcome === 'pending') outcome = 'timeout';
		}, TIMEOUT_MS);
		return () => {
			clearTimeout(timer);
			window.removeEventListener('message', handleMessage);
		};
	});
</script>

<div class="row">
	<div class="col s12">
		<h5>Silent login probe</h5>
		<p>
			This page frames the OP's authorization endpoint with <code>prompt=none</code>. If the
			OP's session cookie reaches the third-party iframe, the OP recognises the session and
			answers with an authorization <code>code</code>. If the browser blocks or partitions
			that cookie — as Firefox's Total Cookie Protection does by default — the OP sees an
			unauthenticated request and answers <code>login_required</code> instead. Nothing about the
			OP differs between the two; only the user agent's cookie policy does.
		</p>
		<table>
			<tbody>
				<tr>
					<td style="width: 20%;">outcome</td>
					<td><strong data-testid="silent-outcome">{outcome}</strong></td>
				</tr>
				<tr>
					<td>authorization response</td>
					<td data-testid="silent-detail" style="word-break: break-all;">{detail}</td>
				</tr>
				<tr>
					<td>iframe src</td>
					<td data-testid="silent-src" style="word-break: break-all;">{src}</td>
				</tr>
			</tbody>
		</table>
	</div>
</div>

{#if browser && src}
	<iframe title="silent-login" {src} style="width: 1px; height: 1px; border: 0;"></iframe>
{/if}
