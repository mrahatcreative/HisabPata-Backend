const { WebSocketServer } = require('ws');
const jwt = require('jsonwebtoken');
const { prisma } = require('../config/database');
const { getAsrConfig } = require('../config/env');

const JWT_SECRET_FINAL = process.env.JWT_SECRET || 'dev_secret_key_do_not_use_in_production';

let wss = null;
const userClients = new Map();

function setupWebSocket(server) {
  wss = new WebSocketServer({ server });

  wss.on('connection', (ws, req) => {
    const url = new URL(req.url, 'http://localhost');
    const pathname = url.pathname;

    if (pathname === '/asr/stream') {
      return handleAsrStream(ws, url);
    }

    let userId = null;

    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw.toString());
        if (msg.type === 'auth') {
          jwt.verify(msg.token, JWT_SECRET_FINAL, async (err, decoded) => {
            if (err) return;
            try {
              const dbUser = await prisma.user.findUnique({ where: { id: decoded.id }, select: { tokenVersion: true } });
              if (!dbUser || dbUser.tokenVersion !== decoded.tokenVersion) {
                ws.send(JSON.stringify({ type: 'auth_error', message: 'Token revoked' }));
                ws.close();
                return;
              }
            } catch (_) {}
            userId = decoded.id;
            if (!userClients.has(userId)) userClients.set(userId, new Set());
            userClients.get(userId).add(ws);
            ws.send(JSON.stringify({ type: 'auth_ok', userId }));
          });
        }
      } catch (e) {
        console.error('WS message error:', e);
      }
    });

    ws.on('close', () => {
      if (userId && userClients.has(userId)) {
        userClients.get(userId).delete(ws);
        if (userClients.get(userId).size === 0) userClients.delete(userId);
      }
    });

    ws.on('error', () => {});
  });

  return wss;
}

function handleAsrStream(clientWs, url) {
  const { base, key, enabled } = getAsrConfig();
  if (!enabled) {
    clientWs.send(JSON.stringify({ type: 'error', message: 'ASR not configured on server' }));
    clientWs.close();
    return;
  }

  let authenticated = false;
  let asrWs = null;
  let closing = false;

  function cleanup() {
    if (closing) return;
    closing = true;
    try { asrWs?.close(); } catch (_) {}
    try { clientWs.close(); } catch (_) {}
    asrWs = null;
  }

  function forwardAudioChunk(data) {
    if (closing || !asrWs || asrWs.readyState !== WebSocket.OPEN) return;
    if (Buffer.isBuffer(data)) {
      asrWs.send(data);
    }
  }

  clientWs.on('message', (raw) => {
    if (authenticated) {
      forwardAudioChunk(raw);
      return;
    }

    try {
      const msg = JSON.parse(raw.toString());
      if (msg.type === 'auth') {
        jwt.verify(msg.token, JWT_SECRET_FINAL, async (err, decoded) => {
          if (err) {
            clientWs.send(JSON.stringify({ type: 'error', message: 'Invalid token' }));
            clientWs.close();
            return;
          }
          try {
            const dbUser = await prisma.user.findUnique({ where: { id: decoded.id }, select: { tokenVersion: true } });
            if (!dbUser || dbUser.tokenVersion !== decoded.tokenVersion) {
              clientWs.send(JSON.stringify({ type: 'error', message: 'Token revoked' }));
              clientWs.close();
              return;
            }
          } catch (_) {}
          authenticated = true;
          clientWs.send(JSON.stringify({ type: 'auth_ok' }));

          try {
            const wsBase = base.replace('https://', 'wss://').replace('http://', 'ws://');
            const wsUrl = `${wsBase}/asr/stream?api_key=${key}`;
            asrWs = new (require('ws'))(wsUrl);

            asrWs.on('open', () => {});
            asrWs.on('message', (transcript) => {
              if (closing) return;
              clientWs.send(transcript.toString());
            });
            asrWs.on('close', () => {
              if (!closing) cleanup();
            });
            asrWs.on('error', (err) => {
              console.error('[ASR WS Proxy] Upstream error:', err.message);
              if (!closing) {
                clientWs.send(JSON.stringify({ type: 'error', message: 'ASR upstream error' }));
                cleanup();
              }
            });
          } catch (err) {
            console.error('[ASR WS Proxy] Connection error:', err.message);
            clientWs.send(JSON.stringify({ type: 'error', message: err.message }));
            clientWs.close();
          }
        });
      } else {
        clientWs.send(JSON.stringify({ type: 'error', message: 'Send auth first' }));
      }
    } catch (_) {
      clientWs.send(JSON.stringify({ type: 'error', message: 'Send JSON auth message first' }));
    }
  });

  clientWs.on('close', cleanup);
  clientWs.on('error', cleanup);
}

function broadcast(data) {
  if (!wss) return;
  const msg = JSON.stringify(data);
  wss.clients.forEach(client => {
    try {
      if (client.readyState === 1) client.send(msg);
    } catch (e) {
      console.error('Broadcast error:', e);
    }
  });
}

function broadcastToUser(userId, data) {
  if (!userId) return;
  const msg = JSON.stringify(data);
  const clients = userClients.get(userId);
  if (clients) {
    clients.forEach(client => {
      try { if (client.readyState === 1) client.send(msg); } catch (e) { }
    });
  }
}

function broadcastToUsers(userIds, data) {
  if (!userIds || userIds.length === 0) return;
  const msg = JSON.stringify(data);
  for (const userId of userIds) {
    const clients = userClients.get(userId);
    if (clients) {
      clients.forEach(client => {
        try { if (client.readyState === 1) client.send(msg); } catch (e) { }
      });
    }
  }
}

module.exports = { setupWebSocket, broadcast, broadcastToUser, broadcastToUsers, userClients };
