<script>
	export let data;
	export let form;

	$: result = form && !form.error ? form : null;
	$: succeeded = result && result.status === 200;
</script>

<div class="row">
	<div class="col s12">
		<p>
			The client exchanges a signed JWT assertion for an access token on behalf of a resource
			owner (<a href="https://datatracker.ietf.org/doc/html/rfc7523#section-2.1"
				>RFC 7523 §2.1</a
			>), with no interactive authorization step. The assertion's <code>iss</code> is the
			client and its <code>sub</code> is the user; the issued token is bound to that user. The
			private key lives on this server, never in the browser.
		</p>
		<table>
			<tbody>
				<tr
					><td style="width: 25%;">client_id (iss)</td><td
						><code>{data.clientId}</code></td
					></tr
				>
				<tr><td>subject (sub)</td><td><code>{data.subject}</code></td></tr>
				<tr><td>token endpoint</td><td><code>{data.tokenEndpoint}</code></td></tr>
				<tr
					><td>signing key</td><td
						><code>{data.alg}</code>, kid <code>{data.kid}</code></td
					></tr
				>
			</tbody>
		</table>
	</div>
</div>

<div class="row">
	<div class="col s12">
		<form method="POST" action="?/token" style="display: inline;">
			<button class="btn" type="submit">Request token</button>
		</form>
		<form method="POST" action="?/replay" style="display: inline;">
			<button class="btn grey" type="submit" disabled={!data.hasReplayable && !form}>
				Replay last assertion
			</button>
		</form>
	</div>
</div>

{#if form && form.error}
	<div class="row">
		<div class="col s12">
			<div class="card-panel red lighten-4">{form.error}</div>
		</div>
	</div>
{/if}

{#if result}
	<div class="row">
		<div class="col s12">
			<div class="card-panel {succeeded ? 'green lighten-4' : 'red lighten-4'}">
				{#if result.replayed && !succeeded}
					Replay rejected — the <code>jti</code> was already used. A captured assertion cannot
					be presented twice.
				{:else if succeeded}
					HTTP {result.status} — access token issued for <code>{data.subject}</code>, no
					user login required.
				{:else}
					HTTP {result.status} — the authorization server rejected the assertion.
				{/if}
			</div>
			<table>
				<tbody>
					<tr>
						<td style="width: 25%;">assertion header</td>
						<td><pre>{JSON.stringify(result.header, null, 2)}</pre></td>
					</tr>
					<tr>
						<td>assertion claims</td>
						<td><pre>{JSON.stringify(result.claims, null, 2)}</pre></td>
					</tr>
					<tr>
						<td>posted form body</td>
						<td style="word-break: break-all;"><code>{result.requestBody}</code></td>
					</tr>
					<tr>
						<td>token response</td>
						<td>
							<pre>{result.response
									? JSON.stringify(result.response, null, 2)
									: result.rawResponse}</pre>
						</td>
					</tr>
				</tbody>
			</table>
		</div>
	</div>
{/if}
