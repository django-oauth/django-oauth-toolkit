<script>
	export let data;
	export let form;
</script>

<div class="row">
	<div class="col s12">
		<h5>Pushed Authorization Requests (RFC 9126)</h5>
		<p>
			PAR is a <strong>back-channel</strong> flow. This page's SvelteKit
			<em>server</em> component (never the browser) holds the client secret and pushes the
			authorization request straight to the IdP's <code>/o/par/</code> endpoint, receiving a
			single-use <code>request_uri</code>. Only <code>client_id</code> +
			<code>request_uri</code>
			then travel through your browser to the authorization endpoint. The demo IdP requires PKCE,
			so the server also generates the PKCE verifier/challenge.
		</p>
	</div>
</div>

{#if form?.parError}
	<div class="row">
		<div class="col s12 card-panel red lighten-4">
			<strong>PAR push failed.</strong>
			<pre>{form.parError}</pre>
		</div>
	</div>
{/if}

{#if data?.error}
	<div class="row">
		<div class="col s12 card-panel red lighten-4">
			<strong>Authorization error:</strong>
			{data.error}
			{#if data.errorDescription}<br />{data.errorDescription}{/if}
		</div>
	</div>
{/if}

{#if data?.tokens}
	<!-- Step 3: the authorization code has been exchanged for tokens (server-side). -->
	<div class="row">
		<div class="col s12">
			<h6>3. Token response (code exchanged server-side)</h6>
			{#if data.requestUri}
				<p>Completed via <code>request_uri</code>: <code>{data.requestUri}</code></p>
			{/if}
			<table>
				<tbody>
					<tr
						><td style="width: 20%;">token endpoint status</td><td
							>{data.tokenStatus}</td
						></tr
					>
					<tr>
						<td>response</td>
						<td style="word-break: break-all;"
							><pre>{JSON.stringify(data.tokens, null, 2)}</pre></td
						>
					</tr>
				</tbody>
			</table>
			<a class="btn waves-effect waves-light" href="/par">Start over</a>
		</div>
	</div>
{:else if form?.requestUri}
	<!-- Step 2: the request has been pushed; hand the request_uri to the browser. -->
	<div class="row">
		<div class="col s12">
			<h6>2. Pushed — received a request_uri</h6>
			<table>
				<tbody>
					<tr
						><td style="width: 20%;">request_uri</td><td style="word-break: break-all;"
							>{form.requestUri}</td
						></tr
					>
					<tr><td>expires_in</td><td>{form.expiresIn}s</td></tr>
				</tbody>
			</table>
			<p>
				The browser now carries only <code>client_id</code> + <code>request_uri</code> to
				the authorization endpoint (log in as <code>superuser</code> / <code>password</code>
				and approve):
			</p>
			<a class="btn waves-effect waves-light" href={form.authorizeUrl}
				>Continue to the authorization endpoint →</a
			>
		</div>
	</div>
{:else}
	<!-- Step 1: kick off the back-channel push. -->
	<div class="row">
		<div class="col s12">
			<h6>1. Push the authorization request (back channel)</h6>
			<form method="POST" action="?/push">
				<button class="btn waves-effect waves-light" type="submit"
					>Push authorization request</button
				>
			</form>
		</div>
	</div>
{/if}
