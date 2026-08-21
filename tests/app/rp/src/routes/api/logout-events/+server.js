// SSE endpoint the browser subscribes to, so a logout token that arrives on the
// server-side backchannel endpoint can reach the tab that is actually logged in.
import { addClient, removeClient } from '../sseClients.js';

export async function GET({ url }) {
	// Get sid from query param (e.g., /api/logout-events?sid=123)
	const sid = url.searchParams.get('sid');
	if (!sid) {
		return new Response('Missing sid', { status: 400 });
	}

	const stream = new ReadableStream({
		start(controller) {
			const encoder = new TextEncoder();
			// Adapt the stream controller to the write/close shape sseClients expects
			const res = {
				write: (data) => {
					try {
						controller.enqueue(encoder.encode(data));
					} catch (err) {
						// Remove client if writing fails
						removeClient(sid, res);
						throw err;
					}
				},
				close: () => controller.close()
			};
			addClient(sid, res);
			// Remove client on stream close
			controller.signal?.addEventListener('abort', () => {
				removeClient(sid, res);
			});
		}
	});

	return new Response(stream, {
		headers: {
			'Content-Type': 'text/event-stream',
			'Cache-Control': 'no-cache',
			Connection: 'keep-alive'
		}
	});
}
