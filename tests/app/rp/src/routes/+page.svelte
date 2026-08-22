<script>
	import { browser } from '$app/environment';
	import { env } from '$env/dynamic/public';
	import {
		EventLog,
		LoginButton,
		LogoutButton,
		OidcContext,
		RefreshTokenButton,
		accessToken,
		authError,
		idToken,
		isAuthenticated,
		isLoading,
		userInfo
	} from '@dopry/svelte-oidc';

	// Runtime configuration. $env/dynamic/public is read from process.env on
	// every request by the dev server and by adapter-node, so it needs no build
	// step and no committed .env file. The defaults are the historical
	// hard-coded values, so `npm run dev` still talks to a local IdP on :8000
	// with this RP on :5173; the cross-site end-to-end layer overrides them to
	// put the IdP and the RP on two genuinely different registrable domains.
	const issuer = env.PUBLIC_RP_ISSUER || 'http://localhost:8000/o';
	const clientId = env.PUBLIC_RP_CLIENT_ID || '2EIxgjlyy5VgCp2fjhEpKLyRtSMMPK0hZ0gBpNdm';
	const rpOrigin = env.PUBLIC_RP_ORIGIN || 'http://localhost:5173';

	const metadata = {};
</script>

{#if browser}
	<OidcContext
		{issuer}
		client_id={clientId}
		redirect_uri={rpOrigin}
		post_logout_redirect_uri={rpOrigin}
		{metadata}
		scope="openid"
		extraOptions={{
			mergeClaims: true
		}}
	>
		<div class="row">
			<div class="col s12">
				<LoginButton>Login</LoginButton>
				<LogoutButton>Logout</LogoutButton>
				<RefreshTokenButton>refreshToken</RefreshTokenButton>
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
						<tr><th style="width: 20%;">store</th><th style="width: 80%;">value</th></tr
						>
					</thead>
					<tbody>
						<tr
							><td>userInfo</td><td
								><pre>{JSON.stringify($userInfo, null, 2) || ''}</pre></td
							></tr
						>
						<tr
							><td>accessToken</td><td style="word-break: break-all;"
								>{$accessToken}</td
							></tr
						>
						<tr><td>idToken</td><td style="word-break: break-all;">{$idToken}</td></tr>
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
