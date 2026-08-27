/**
 * Encrypted chat relay server.
 *
 * IMPORTANT SECURITY PROPERTY: this server never sees plaintext messages
 * and never sees any private key. It only ever handles:
 *   - usernames
 *   - public keys (safe to share by definition)
 *   - ciphertext + nonce blobs it cannot decrypt
 *
 * All encryption and decryption happens in the browser (public/app.js).
 */

const express = require("express");
const http = require("http");
const path = require("path");
const { WebSocketServer } = require("ws");

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.use(express.static(path.join(__dirname, "public")));

// username -> { ws, publicKey }
const clients = new Map();

// username -> array of queued ciphertext envelopes, for offline delivery.
// NOTE: in-memory only. Restarting the server loses undelivered messages.
// For production, replace with a real datastore (see README).
const offlineQueue = new Map();

function send(ws, msg) {
  if (ws && ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify(msg));
  }
}

function broadcastUserList() {
  const users = [...clients.entries()].map(([username, c]) => ({
    username,
    publicKey: c.publicKey,
  }));
  for (const { ws } of clients.values()) {
    send(ws, { type: "user_list", users });
  }
}

wss.on("connection", (ws) => {
  let currentUser = null;

  ws.on("message", (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return; // ignore malformed input
    }

    switch (msg.type) {
      case "register": {
        // { type: "register", username, publicKey }
        // publicKey is a base64 NaCl box public key. This is fine to store
        // and broadcast in the open — it is not secret.
        if (!msg.username || !msg.publicKey) return;
        if (clients.has(msg.username)) {
          send(ws, { type: "error", message: "Username already taken" });
          return;
        }
        currentUser = msg.username;
        clients.set(currentUser, { ws, publicKey: msg.publicKey });
        send(ws, { type: "registered", username: currentUser });
        broadcastUserList();

        // flush any messages that arrived while this user was offline
        const queued = offlineQueue.get(currentUser);
        if (queued && queued.length) {
          for (const envelope of queued) {
            send(ws, envelope);
          }
          offlineQueue.delete(currentUser);
        }
        break;
      }

      case "message": {
        // { type: "message", to, from, nonce, ciphertext }
        // The server only ever forwards these opaque fields. It cannot
        // read the message content.
        if (!msg.to || !msg.nonce || !msg.ciphertext || !currentUser) return;
        const envelope = {
          type: "message",
          from: currentUser,
          nonce: msg.nonce,
          ciphertext: msg.ciphertext,
          timestamp: Date.now(),
        };
        const recipient = clients.get(msg.to);
        if (recipient) {
          send(recipient.ws, envelope);
        } else {
          // recipient offline: queue for delivery on next connect
          if (!offlineQueue.has(msg.to)) offlineQueue.set(msg.to, []);
          offlineQueue.get(msg.to).push(envelope);
        }
        break;
      }

      default:
        break;
    }
  });

  ws.on("close", () => {
    if (currentUser) {
      clients.delete(currentUser);
      broadcastUserList();
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Encrypted chat relay listening on http://localhost:${PORT}`);
});
