<script>
	import { browser } from '$app/environment';
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

	const metadata = {};
</script>

{#if browser}
	<OidcContext
		issuer="http://localhost:8000/o"
		client_id="2EIxgjlyy5VgCp2fjhEpKLyRtSMMPK0hZ0gBpNdm"
		redirect_uri="http://localhost:5173"
		post_logout_redirect_uri="http://localhost:5173"
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
