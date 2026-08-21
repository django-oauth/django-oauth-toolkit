<script>
	export let data;
	export let form;

	$: result = form && !form.error ? form : null;
	$: succeeded = result && result.status === 200;
</script>

<div class="row">
	<div class="col s12">
		<p>
			The client authenticates with a signed JWT assertion instead of a client secret (<a
				href="https://datatracker.ietf.org/doc/html/rfc7523#section-2.2">RFC 7523 §2.2</a
			>). The private key lives on this server, never in the browser: a SPA is a public client
			and cannot use <code>private_key_jwt</code> at all.
		</p>
		<table>
			<tbody>
				<tr><td style="width: 25%;">client_id</td><td><code>{data.clientId}</code></td></tr>
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
					HTTP {result.status} — access token issued, with no client secret anywhere in the
					request.
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
