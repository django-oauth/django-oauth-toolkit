<script>
	import { browser } from '$app/environment';
	import { onDestroy } from 'svelte';

	// Configuration
	const IDP_URL = 'http://127.0.0.1:8000';
	const CLIENT_ID = 'Qg8AaxKLs1c2W3PR70Sv5QxuSEREicKUlf83iGX3';
	const POLLING_INTERVAL = 5000; // 5 seconds

	// State variables
	let status = 'idle'; // idle, authorizing, polling, complete, error
	let deviceCode = '';
	let userCode = '';
	let verificationUri = '';
	let verificationUriComplete = '';
	let expiresIn = 0;
	let interval = 5;
	let accessToken = '';
	let tokenType = '';
	let expiresInToken = 0;
	let scope = '';
	let refreshToken = '';
	let errorMessage = '';
	let pollingIntervalId = null;

	/**
	 * Initiate the device authorization flow
	 */
	async function initiateAuthorization() {
		try {
			status = 'authorizing';
			errorMessage = '';
			accessToken = '';

			const response = await fetch(`${IDP_URL}/o/device-authorization/`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded'
				},
				body: new URLSearchParams({
					client_id: CLIENT_ID
				})
			});

			if (!response.ok) {
				const errorData = await response.json().catch(() => ({}));
				throw new Error(
					errorData.error_description || `HTTP error! status: ${response.status}`
				);
			}

			const data = await response.json();

			deviceCode = data.device_code;
			userCode = data.user_code;
			verificationUri = data.verification_uri;
			verificationUriComplete = data.verification_uri_complete || verificationUri;
			expiresIn = data.expires_in;
			interval = data.interval || 5;

			status = 'polling';
			startPolling();
		} catch (error) {
			status = 'error';
			errorMessage = error.message;
			console.error('Error initiating device authorization:', error);
		}
	}

	/**
	 * Poll for the access token
	 */
	async function pollForToken() {
		try {
			const response = await fetch(`${IDP_URL}/o/token/`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded'
				},
				body: new URLSearchParams({
					device_code: deviceCode,
					client_id: CLIENT_ID,
					grant_type: 'urn:ietf:params:oauth:grant-type:device_code'
				})
			});

			const data = await response.json();

			if (response.ok) {
				// Success! We got the token
				accessToken = data.access_token;
				tokenType = data.token_type;
				expiresInToken = data.expires_in;
				scope = data.scope || '';
				refreshToken = data.refresh_token || '';

				status = 'complete';
				stopPolling();
			} else if (data.error === 'authorization_pending') {
				// User hasn't authorized yet, continue polling
				console.log('Authorization pending, will retry...');
			} else if (data.error === 'slow_down') {
				// We're polling too fast, increase interval
				console.log('Slow down requested, increasing interval');
				stopPolling();
				interval = interval + 5;
				startPolling();
			} else if (data.error === 'expired_token') {
				// The device code has expired
				status = 'error';
				errorMessage = 'Device code has expired. Please start over.';
				stopPolling();
			} else if (data.error === 'access_denied') {
				// User denied the authorization
				status = 'error';
				errorMessage = 'Authorization was denied by the user.';
				stopPolling();
			} else {
				// Some other error
				status = 'error';
				errorMessage = data.error_description || data.error || 'Unknown error occurred';
				stopPolling();
			}
		} catch (error) {
			console.error('Error polling for token:', error);
			// Don't stop polling on network errors, just log and continue
		}
	}

	/**
	 * Start polling for the token
	 */
	function startPolling() {
		if (pollingIntervalId) {
			clearInterval(pollingIntervalId);
		}
		pollingIntervalId = setInterval(pollForToken, interval * 1000);
	}

	/**
	 * Stop polling for the token
	 */
	function stopPolling() {
		if (pollingIntervalId) {
			clearInterval(pollingIntervalId);
			pollingIntervalId = null;
		}
	}

	/**
	 * Reset the flow
	 */
	function reset() {
		stopPolling();
		status = 'idle';
		deviceCode = '';
		userCode = '';
		verificationUri = '';
		verificationUriComplete = '';
		expiresIn = 0;
		interval = 5;
		accessToken = '';
		tokenType = '';
		expiresInToken = 0;
		scope = '';
		refreshToken = '';
		errorMessage = '';
	}

	/**
	 * Open verification URI in a new tab
	 */
	function openVerificationUri() {
		if (browser && verificationUriComplete) {
			window.open(verificationUriComplete, '_blank');
		}
	}

	// Cleanup on component destroy
	onDestroy(() => {
		stopPolling();
	});
</script>

<svelte:head>
	<title>Device Authorization Flow Test</title>
</svelte:head>

<div class="card">
	<h2>Test the OAuth 2.0 Device Authorization Grant</h2>
	<p>
		This page demonstrates the Device Authorization Flow (RFC 8628), which is used by devices
		with limited input capabilities (like smart TVs, IoT devices, etc.) to obtain OAuth tokens.
		Do not use device-authorization in a browser, this is just an illustrative example to
		streamline manual testing for maintainers. It shows how you'd need to implement the flow on
		your device. Have a look at <a
			target="_blank"
			href="https://github.com/django-oauth/django-oauth-toolkit/pull/1539/files#diff-72107d6f4a703abaeb6a7cf709e0c99f7ed0b7c74f0b14b0cbc4f35c7c650e26R122"
			>this full user journey test for an implementation in Python</a
		>.
	</p>
</div>

{#if status === 'idle'}
	<div class="card">
		<h3>Step 1: Initiate Authorization</h3>
		<p>Click the button below to start the device authorization flow.</p>
		<button on:click={initiateAuthorization} class="btn-primary">
			Start Device Authorization
		</button>
	</div>
{/if}

{#if status === 'authorizing'}
	<div class="card">
		<h3>Initiating...</h3>
		<p>Contacting the authorization server...</p>
		<div class="spinner"></div>
	</div>
{/if}

{#if status === 'polling'}
	<div class="card success">
		<h3>Step 2: Authorize the Device</h3>
		<p>
			Open the verification URL below in a new tab, enter the user code, and approve the
			authorization.
		</p>

		<div class="info-box">
			<div class="info-row">
				<strong>User Code:</strong>
				<code class="user-code">{userCode}</code>
			</div>
			<div class="info-row">
				<strong>Verification URL:</strong>
				<a href={verificationUriComplete} target="_blank" rel="noopener noreferrer">
					{verificationUri}
				</a>
			</div>
			<div class="info-row">
				<strong>Expires in:</strong>
				<span>{expiresIn} seconds</span>
			</div>
		</div>

		<button on:click={openVerificationUri} class="btn-primary">
			Open Verification URL in New Tab
		</button>

		<div class="polling-status">
			<div class="spinner"></div>
			<p>Polling for authorization... (checking every {interval} seconds)</p>
		</div>

		<button on:click={reset} class="btn-secondary">Cancel</button>
	</div>
{/if}

{#if status === 'complete'}
	<div class="card success">
		<h3>✓ Authorization Complete!</h3>
		<p>Successfully obtained an access token.</p>

		<div class="info-box">
			<div class="info-row">
				<strong>Token Type:</strong>
				<span>{tokenType}</span>
			</div>
			<div class="info-row">
				<strong>Expires In:</strong>
				<span>{expiresInToken} seconds</span>
			</div>
			{#if scope}
				<div class="info-row">
					<strong>Scope:</strong>
					<span>{scope}</span>
				</div>
			{/if}
			<div class="info-row full-width">
				<strong>Access Token:</strong>
				<textarea readonly class="token-display">{accessToken}</textarea>
			</div>
			{#if refreshToken}
				<div class="info-row full-width">
					<strong>Refresh Token:</strong>
					<textarea readonly class="token-display">{refreshToken}</textarea>
				</div>
			{/if}
		</div>

		<button on:click={reset} class="btn-primary">Start New Authorization</button>
	</div>
{/if}

{#if status === 'error'}
	<div class="card error">
		<h3>Error</h3>
		<p>{errorMessage}</p>
		<button on:click={reset} class="btn-primary">Try Again</button>
	</div>
{/if}

<div class="card info">
	<h3>How it works</h3>
	<ol>
		<li>
			<strong>Device requests authorization:</strong> The device sends a request to the authorization
			server with its client ID.
		</li>
		<li>
			<strong>Server returns codes:</strong> The server responds with a device code, user code,
			and verification URI.
		</li>
		<li>
			<strong>User authorizes:</strong> The user visits the verification URI on another device
			(like a phone or computer), enters the user code, and approves the authorization.
		</li>
		<li>
			<strong>Device polls for token:</strong> Meanwhile, the device polls the token endpoint using
			the device code until the user completes authorization.
		</li>
		<li>
			<strong>Token granted:</strong> Once the user approves, the polling request returns the access
			token.
		</li>
	</ol>
</div>

<style>
	h1 {
		color: #333;
		margin-bottom: 2rem;
	}

	h2,
	h3 {
		color: #555;
		margin-top: 0;
	}

	.card {
		background: white;
		border-radius: 8px;
		padding: 1.5rem;
		margin-bottom: 1.5rem;
		box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
	}

	.card.success {
		border-left: 4px solid #4caf50;
	}

	.card.error {
		border-left: 4px solid #f44336;
	}

	.card.info {
		background: #f5f5f5;
	}

	.info-box {
		background: #f9f9f9;
		border: 1px solid #ddd;
		border-radius: 4px;
		padding: 1rem;
		margin: 1rem 0;
	}

	.info-row {
		display: flex;
		gap: 1rem;
		margin-bottom: 0.75rem;
		align-items: center;
	}

	.info-row:last-child {
		margin-bottom: 0;
	}

	.info-row.full-width {
		flex-direction: column;
		align-items: flex-start;
	}

	.info-row strong {
		min-width: 150px;
		color: #666;
	}

	.user-code {
		font-size: 1.5rem;
		font-weight: bold;
		background: #fff;
		padding: 0.5rem 1rem;
		border-radius: 4px;
		color: #2196f3;
		letter-spacing: 0.1em;
	}

	.token-display {
		width: 100%;
		min-height: 100px;
		padding: 0.5rem;
		border: 1px solid #ddd;
		border-radius: 4px;
		font-family: 'Courier New', monospace;
		font-size: 0.85rem;
		resize: vertical;
		word-break: break-all;
	}

	button {
		padding: 0.75rem 1.5rem;
		border: none;
		border-radius: 4px;
		font-size: 1rem;
		cursor: pointer;
		margin-right: 0.5rem;
		margin-top: 0.5rem;
	}

	.btn-primary {
		background: #2196f3;
		color: white;
	}

	.btn-primary:hover {
		background: #1976d2;
	}

	.btn-secondary {
		background: #757575;
		color: white;
	}

	.btn-secondary:hover {
		background: #616161;
	}

	.spinner {
		border: 3px solid #f3f3f3;
		border-top: 3px solid #2196f3;
		border-radius: 50%;
		width: 40px;
		height: 40px;
		animation: spin 1s linear infinite;
		margin: 1rem auto;
	}

	.polling-status {
		margin: 1.5rem 0;
		text-align: center;
		color: #666;
	}

	@keyframes spin {
		0% {
			transform: rotate(0deg);
		}
		100% {
			transform: rotate(360deg);
		}
	}

	ol {
		line-height: 1.8;
		padding-left: 1.5rem;
	}

	ol li {
		margin-bottom: 0.5rem;
	}

	a {
		color: #2196f3;
		text-decoration: none;
	}

	a:hover {
		text-decoration: underline;
	}

	code {
		background: #f5f5f5;
		padding: 0.2rem 0.4rem;
		border-radius: 3px;
		font-family: 'Courier New', monospace;
	}
</style>
