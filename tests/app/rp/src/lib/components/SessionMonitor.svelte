<script>
	import { browser } from '$app/environment';
	import { onMount, onDestroy, getContext } from 'svelte';
	import { isAuthenticated, OIDC_CONTEXT_CLIENT_PROMISE } from '@dopry/svelte-oidc';
	import { env } from '$env/dynamic/public';

	// Configuration - must match the layout's OidcContext
	const IDP_URL = env.PUBLIC_IDP_URL || 'http://localhost:8000';
	const CLIENT_ID = env.PUBLIC_OAUTH_CLIENT_ID || '2EIxgjlyy5VgCp2fjhEpKLyRtSMMPK0hZ0gBpNdm';
	const OIDC_DISCOVERY_PATH =
		env.PUBLIC_OIDC_DISCOVERY_PATH || '/o/.well-known/openid-configuration';

	// State variables
	let checkSessionIframeUrl = null;
	let sessionState = null;
	let sessionSupported = false;
	let sessionStatus = 'unknown'; // 'unknown', 'unchanged', 'changed'
	let monitoringActive = false;
	let lastCheckTime = null;
	let sessionChanged = false;
	let sessionChangeTime = null;
	let opIframe = null;
	let checkInterval = null;
	let discoveryError = null;
	let sessionStateAvailable = false;

	// Get UserManager from context (called during component initialization)
	const userManagerPromise = getContext(OIDC_CONTEXT_CLIENT_PROMISE);

	/**
	 * Extract session_state from User object
	 */
	async function updateSessionState() {
		if (!browser || !$isAuthenticated) {
			sessionState = null;
			sessionStateAvailable = false;
			return;
		}

		try {
			const userManager = await userManagerPromise;
			const user = await userManager.getUser();

			if (user && user.session_state) {
				sessionState = user.session_state;
				sessionStateAvailable = true;
			} else {
				sessionState = null;
				sessionStateAvailable = false;
				console.debug('session_state NOT found in user object');
			}
		} catch (error) {
			console.error('Error getting session_state from User object:', error);
			sessionState = null;
			sessionStateAvailable = false;
		}
	}

	// Reactive statement to update session state when authentication changes
	$: if (browser && $isAuthenticated) {
		// Fetch discovery and update session state when user becomes authenticated
		Promise.all([fetchDiscoveryDocument(), updateSessionState()]).then(() => {
			// Check if we should start monitoring
			if (sessionSupported && sessionStateAvailable && !monitoringActive) {
				setTimeout(() => {
					startMonitoring();
				}, 1000);
			}
		});
	} else if (browser && !$isAuthenticated) {
		sessionState = null;
		sessionStateAvailable = false;
	}

	/**
	 * Fetch OIDC discovery document
	 */
	async function fetchDiscoveryDocument() {
		try {
			discoveryError = null;
			const response = await fetch(`${IDP_URL}${OIDC_DISCOVERY_PATH}`);

			if (!response.ok) {
				throw new Error(`Failed to fetch discovery document: ${response.status}`);
			}

			const metadata = await response.json();

			if (metadata.check_session_iframe) {
				checkSessionIframeUrl = metadata.check_session_iframe;
				sessionSupported = true;
			} else {
				sessionSupported = false;
			}
		} catch (error) {
			console.error('Error fetching discovery document:', error);
			discoveryError = error.message;
			sessionSupported = false;
		}
	}

	/**
	 * Format time for display
	 */
	function formatTime() {
		return new Date().toLocaleTimeString();
	}

	/**
	 * Get origin from URL
	 */
	function getOriginFromUrl(url) {
		try {
			const parsedUrl = new URL(url);
			return parsedUrl.origin;
		} catch (e) {
			console.error('Invalid URL:', url);
			return '';
		}
	}

	/**
	 * Check session status
	 */
	function checkSession() {
		if (!opIframe || !opIframe.contentWindow || !sessionState) {
			console.debug('Skipping session check - iframe not ready or no session state');
			return;
		}

		// Construct message with client_id and session_state
		const message = `${CLIENT_ID} ${sessionState}`;

		// Send message to OP iframe
		try {
			const targetOrigin = getOriginFromUrl(checkSessionIframeUrl);
			opIframe.contentWindow.postMessage(message, targetOrigin);
			lastCheckTime = formatTime();
		} catch (error) {
			console.error('Error posting message to OP iframe:', error);
		}
	}

	/**
	 * Handle messages from the session iframe
	 */
	function handleSessionMessage(event) {
		// Verify the message is from the expected origin
		const expectedOrigin = getOriginFromUrl(checkSessionIframeUrl);

		if (expectedOrigin !== event.origin) {
			return;
		}

		console.log('Session status:', event.data);

		if (event.data === 'unchanged') {
			sessionStatus = 'unchanged';
		} else if (event.data === 'changed') {
			sessionStatus = 'changed';
			if (!sessionChanged) {
				sessionChanged = true;
				sessionChangeTime = formatTime();
			}
		} else {
			sessionStatus = 'unknown';
		}
	}

	/**
	 * Start monitoring session
	 */
	function startMonitoring() {
		if (!sessionSupported || !sessionStateAvailable) {
			return;
		}

		// Add message listener
		window.addEventListener('message', handleSessionMessage);

		// Set up periodic check (every 5 seconds)
		checkInterval = setInterval(() => {
			checkSession();
		}, 5000);

		monitoringActive = true;

		// Initial check after iframe loads
		if (opIframe) {
			opIframe.onload = () => {
				setTimeout(checkSession, 500);
			};
		}
	}

	/**
	 * Stop monitoring session
	 */
	function stopMonitoring() {
		window.removeEventListener('message', handleSessionMessage);
		if (checkInterval) {
			clearInterval(checkInterval);
			checkInterval = null;
		}
		monitoringActive = false;
	}

	/**
	 * Reset session change state
	 */
	function resetSessionChange() {
		sessionChanged = false;
		sessionChangeTime = null;
		sessionStatus = 'unchanged';
	}

	// Lifecycle hooks
	onMount(async () => {
		if (browser && $isAuthenticated) {
			await updateSessionState();
			await fetchDiscoveryDocument();
			if (sessionSupported && sessionStateAvailable) {
				// Wait a bit for the iframe to be ready
				setTimeout(() => {
					startMonitoring();
				}, 1000);
			}
		}
	});

	onDestroy(() => {
		if (browser) {
			stopMonitoring();
		}
	});

	// Stop monitoring when user logs out
	$: if (browser && !$isAuthenticated && monitoringActive) {
		stopMonitoring();
	}
</script>

<div class="card">
	<h2>OIDC Session Management</h2>
	<p>
		This page tests the OpenID Connect Session Management 1.0 specification. It monitors the
		authentication session state with the OIDC provider and detects when the session changes
		(e.g., when you log out from the provider in another tab).
	</p>
</div>

{#if !$isAuthenticated}
	<div class="card">
		<h3>Not Authenticated</h3>
		<p>You must be logged in to test session management.</p>
		<p>Please use the "OIDC Authorization Code Flow" tab to log in first.</p>
	</div>
{:else if discoveryError}
	<div class="card error">
		<h3>Discovery Error</h3>
		<p>Failed to fetch OIDC discovery document: {discoveryError}</p>
	</div>
{:else if !sessionSupported}
	<div class="card error">
		<h3>Session Management Not Supported</h3>
		<p>
			The OIDC provider does not support session management. The discovery document does not
			include a <code>check_session_iframe</code> endpoint.
		</p>
		<p>
			To use this feature, the provider must expose a <code>check_session_iframe</code> in its
			discovery document at <code>{IDP_URL}{OIDC_DISCOVERY_PATH}</code>.
		</p>
	</div>
{:else if !sessionStateAvailable}
	<div class="card error">
		<h3>Session State Not Available</h3>
		<p>
			The authentication response does not contain a <code>session_state</code> parameter. The server
			may not be configured to support session management.
		</p>
		<p>
			The OIDC provider must include the <code>session_state</code> parameter in the authentication
			response for session monitoring to work.
		</p>
	</div>
{:else}
	<!-- Session monitoring is active -->
	<div class="card success">
		<h3>Session Monitoring Active</h3>

		<div class="status-container">
			<div class="status-indicator status-{sessionStatus}">
				<div class="status-dot"></div>
				<div class="status-text">
					{#if sessionStatus === 'unchanged'}
						Session Active
					{:else if sessionStatus === 'changed'}
						Session Changed
					{:else}
						Session Status Unknown
					{/if}
				</div>
			</div>
		</div>

		{#if sessionChanged}
			<div class="warning-box">
				<h4>⚠ Session State Change Detected</h4>
				<p>
					Your session state with the OIDC provider has changed at {sessionChangeTime}.
					This might mean that you have logged out from the provider in another tab or
					browser.
				</p>
				<div class="action-buttons">
					<button on:click={resetSessionChange} class="btn-secondary">
						Acknowledge & Continue Monitoring
					</button>
				</div>
			</div>
		{/if}

		<div class="info-box">
			<h4>Session Information</h4>
			<table>
				<tbody>
					<tr>
						<td><strong>Session State</strong></td>
						<td><code>{sessionState || 'Not available'}</code></td>
					</tr>
					<tr>
						<td><strong>Client ID</strong></td>
						<td><code>{CLIENT_ID}</code></td>
					</tr>
					<tr>
						<td><strong>Monitoring Status</strong></td>
						<td>{monitoringActive ? 'Active' : 'Inactive'}</td>
					</tr>
					<tr>
						<td><strong>Last Check</strong></td>
						<td>{lastCheckTime || 'Never'}</td>
					</tr>
					<tr>
						<td><strong>Check Session Iframe</strong></td>
						<td><code>{checkSessionIframeUrl || 'Not available'}</code></td>
					</tr>
				</tbody>
			</table>
		</div>

		<!-- Hidden iframe for session monitoring -->
		{#if checkSessionIframeUrl}
			<iframe
				bind:this={opIframe}
				src={checkSessionIframeUrl}
				style="display: none;"
				title="OIDC Session Check Iframe"
			></iframe>
		{/if}
	</div>
{/if}

<div class="card info">
	<h3>How OIDC Session Management Works</h3>
	<ol>
		<li>
			<strong>Check Discovery:</strong> The application fetches the OIDC provider's discovery
			document to find the <code>check_session_iframe</code> endpoint.
		</li>
		<li>
			<strong>Load Iframe:</strong> A hidden iframe is created pointing to the provider's check_session_iframe
			endpoint.
		</li>
		<li>
			<strong>Periodic Checks:</strong> Every 5 seconds, the application sends a message to the
			iframe containing the client ID and session state.
		</li>
		<li>
			<strong>Status Response:</strong> The iframe responds with one of three values:
			<ul>
				<li><code>"unchanged"</code> - Session is still active</li>
				<li><code>"changed"</code> - Session has changed (user logged out elsewhere)</li>
				<li><code>"error"</code> - An error occurred</li>
			</ul>
		</li>
		<li>
			<strong>UI Update:</strong> The application updates the UI based on the session status, alerting
			the user if their session has changed.
		</li>
	</ol>
	<p>
		This implements the <a
			href="https://openid.net/specs/openid-connect-session-1_0.html"
			target="_blank"
			rel="noopener noreferrer">OpenID Connect Session Management 1.0</a
		> specification.
	</p>
</div>

<style>
	h2,
	h3,
	h4 {
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

	.status-container {
		display: flex;
		justify-content: center;
		margin: 1.5rem 0;
	}

	.status-indicator {
		display: flex;
		align-items: center;
		padding: 0.75rem 1.5rem;
		border-radius: 2rem;
		background: #f5f5f5;
		gap: 0.5rem;
	}

	.status-dot {
		width: 12px;
		height: 12px;
		border-radius: 50%;
		background: #ccc;
	}

	.status-indicator.status-unchanged {
		background-color: rgba(76, 175, 80, 0.1);
	}

	.status-indicator.status-unchanged .status-dot {
		background-color: #4caf50;
	}

	.status-indicator.status-changed {
		background-color: rgba(244, 67, 54, 0.1);
	}

	.status-indicator.status-changed .status-dot {
		background-color: #f44336;
	}

	.status-text {
		font-weight: 500;
		font-size: 1rem;
	}

	.warning-box {
		background: rgba(255, 152, 0, 0.1);
		border: 1px solid #ff9800;
		border-radius: 4px;
		padding: 1rem;
		margin: 1rem 0;
	}

	.warning-box h4 {
		margin-top: 0;
		color: #f57c00;
	}

	.action-buttons {
		margin-top: 1rem;
		display: flex;
		gap: 0.5rem;
		flex-wrap: wrap;
	}

	.info-box {
		background: #f9f9f9;
		border: 1px solid #ddd;
		border-radius: 4px;
		padding: 1rem;
		margin: 1rem 0;
	}

	.info-box h4 {
		margin-top: 0;
	}

	table {
		width: 100%;
		border-collapse: collapse;
		margin-top: 1rem;
	}

	table td {
		padding: 0.5rem;
		border-bottom: 1px solid #eee;
	}

	table tr:last-child td {
		border-bottom: none;
	}

	table td:first-child {
		width: 200px;
	}

	code {
		background: #f5f5f5;
		padding: 0.2rem 0.4rem;
		border-radius: 3px;
		font-family: 'Courier New', monospace;
		font-size: 0.9em;
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

	ol {
		line-height: 1.8;
		padding-left: 1.5rem;
	}

	ol li {
		margin-bottom: 0.5rem;
	}

	ul {
		line-height: 1.6;
		margin-top: 0.5rem;
	}

	a {
		color: #2196f3;
		text-decoration: none;
	}

	a:hover {
		text-decoration: underline;
	}
</style>
