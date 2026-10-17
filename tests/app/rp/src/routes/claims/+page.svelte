<script>
	import { browser } from '$app/environment';
	import { clientId, issuer, rpOrigin } from '$lib/oidc-config';
	import {
		EventLog,
		LoginButton,
		LogoutButton,
		OidcContext,
		authError,
		idToken,
		isAuthenticated,
		isLoading,
		userInfo
	} from '@dopry/svelte-oidc';

	// OpenID Connect Core 1.0 section 5.5: ask for individual claims with only the
	// openid scope. The IdP must set OIDC_CLAIMS_PARAMETER_ENABLED (the demo IdP
	// does). name comes back from UserInfo, email in the ID Token.
	const claims = {
		userinfo: { name: { essential: true } },
		id_token: { email: null }
	};

	function decodeIdToken(token) {
		if (!token) return null;
		const payload = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
		return JSON.parse(atob(payload));
	}
</script>

<p>
	Requests <code>{JSON.stringify(claims)}</code> through the <code>claims</code> parameter, with
	only the <code>openid</code> scope. The consent page lists the requested claims.
</p>

{#if browser}
	<OidcContext
		{issuer}
		client_id={clientId}
		redirect_uri={`${rpOrigin}/claims`}
		post_logout_redirect_uri={rpOrigin}
		scope="openid"
		extraOptions={{
			extraQueryParams: { claims: JSON.stringify(claims) }
		}}
	>
		<div class="row">
			<div class="col s12">
				<LoginButton>Login</LoginButton>
				<LogoutButton>Logout</LogoutButton>
			</div>
		</div>
		<div class="row">
			<div class="col s12">
				<table>
					<thead>
						<tr><th>isLoading</th><th>isAuthenticated</th><th>authError</th></tr>
					</thead>
					<tbody>
						<tr>
							<td>{$isLoading}</td>
							<td>{$isAuthenticated}</td>
							<td>{$authError || 'None'}</td>
						</tr>
					</tbody>
				</table>
			</div>
		</div>
		<div class="row">
			<div class="col s12">
				<table>
					<thead>
						<tr
							><th style="width: 20%;">source</th><th style="width: 80%;">claims</th
							></tr
						>
					</thead>
					<tbody>
						<tr>
							<td>ID Token</td>
							<td
								><pre>{JSON.stringify(decodeIdToken($idToken), null, 2) ||
										''}</pre></td
							>
						</tr>
						<tr>
							<td>UserInfo (merged)</td>
							<td><pre>{JSON.stringify($userInfo, null, 2) || ''}</pre></td>
						</tr>
					</tbody>
				</table>
			</div>
		</div>
		<div class="row">
			<div class="col s12">
				<EventLog />
			</div>
		</div>
	</OidcContext>
{/if}
