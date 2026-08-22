// In-memory store for SSE clients keyed by sid (session id)
const clients = new Map();

export function addClient(sid, res) {
	if (!clients.has(sid)) {
		clients.set(sid, new Set());
	}
	clients.get(sid).add(res);
}

export function removeClient(sid, res) {
	if (clients.has(sid)) {
		clients.get(sid).delete(res);
		if (clients.get(sid).size === 0) {
			clients.delete(sid);
		}
	}
}

export function sendLogoutEvent(sid, data) {
	if (clients.has(sid)) {
		for (const res of Array.from(clients.get(sid))) {
			try {
				res.write(`event: logout\ndata: ${JSON.stringify(data)}\n\n`);
			} catch (err) {
				// Remove client if writing fails (stream closed)
				removeClient(sid, res);
				console.error('Error sending logout sse events to frontend', err);
			}
		}
	}
}
