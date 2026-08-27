/**
 * All cryptography happens in this file, client-side. The server (server.js)
 * never receives a private key and never receives plaintext.
 *
 * Primitive: NaCl "box" (X25519 key exchange + XSalsa20-Poly1305 AEAD),
 * via libsodium. Each message is encrypted with:
 *     crypto_box_easy(plaintext, nonce, recipientPublicKey, myPrivateKey)
 * which gives confidentiality + authenticity (the recipient can verify the
 * message really came from the claimed sender's key).
 *
 * NOTE on scope: this gives strong per-message encryption but not Signal's
 * full forward-secrecy ratchet (a compromised private key would let an
 * attacker decrypt past traffic they'd recorded). See README.md for how to
 * upgrade this to the Signal protocol.
 */

let sodium; // set once libsodium finishes loading
let myKeyPair = null; // { publicKey: Uint8Array, privateKey: Uint8Array }
let myUsername = null;
let ws = null;
let activeChat = null; // username currently selected
const roster = new Map(); // username -> publicKey (base64)
const messageLog = new Map(); // username -> [{ mine, text, ts }]

const el = (id) => document.getElementById(id);

// ---------- key storage (private key never leaves this browser) ----------

function loadStoredIdentity() {
  const raw = localStorage.getItem("sealed_identity");
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    return {
      username: parsed.username,
      publicKey: sodium.from_base64(parsed.publicKey),
      privateKey: sodium.from_base64(parsed.privateKey),
    };
  } catch {
    return null;
  }
}

function storeIdentity(username, keyPair) {
  localStorage.setItem(
    "sealed_identity",
    JSON.stringify({
      username,
      publicKey: sodium.to_base64(keyPair.publicKey),
      privateKey: sodium.to_base64(keyPair.privateKey),
    })
  );
}

// ---------- fingerprint visualization ----------
// A deterministic strip of colored blocks derived from the public key hash.
// Two users can read these aloud / compare over a call to verify no one is
// performing a man-in-the-middle substitution of keys via the server.

function renderFingerprint(publicKeyBase64, container, blockCount = 6) {
  container.innerHTML = "";
  const hash = sodium.crypto_generichash(16, sodium.from_base64(publicKeyBase64));
  for (let i = 0; i < blockCount; i++) {
    const hue = hash[i * 2] * (360 / 255);
    const light = 45 + (hash[i * 2 + 1] % 20);
    const block = document.createElement("span");
    block.style.background = `hsl(${hue.toFixed(0)}, 65%, ${light}%)`;
    container.appendChild(block);
  }
}

// ---------- bootstrap ----------

(async function init() {
  await sodium_ready();
  sodium = window.sodium;

  const existing = loadStoredIdentity();
  if (existing) {
    myKeyPair = existing;
    myUsername = existing.username;
    connectAndRegister();
  }
})();

function sodium_ready() {
  return new Promise((resolve) => {
    const check = () => {
      if (window.sodium && window.sodium.ready) {
        window.sodium.ready.then(resolve);
      } else {
        setTimeout(check, 30);
      }
    };
    check();
  });
}

// ---------- login flow ----------

el("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = el("username").value.trim();
  if (!username) return;

  el("login-btn").disabled = true;
  el("key-status").hidden = false;

  // generate keypair in-browser; private key is never transmitted
  await new Promise((r) => setTimeout(r, 350)); // let the UI show the state
  myKeyPair = sodium.crypto_box_keypair();
  myUsername = username;
  storeIdentity(username, myKeyPair);

  connectAndRegister();
});

function connectAndRegister() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}`);

  ws.addEventListener("open", () => {
    ws.send(
      JSON.stringify({
        type: "register",
        username: myUsername,
        publicKey: sodium.to_base64(myKeyPair.publicKey),
      })
    );
  });

  ws.addEventListener("message", (event) => {
    const msg = JSON.parse(event.data);
    handleServerMessage(msg);
  });

  ws.addEventListener("close", () => {
    addSystemNote(activeChat, "Disconnected from relay. Refresh to reconnect.");
  });
}

function handleServerMessage(msg) {
  switch (msg.type) {
    case "registered":
      showChatScreen();
      break;

    case "error":
      alert(msg.message);
      localStorage.removeItem("sealed_identity");
      location.reload();
      break;

    case "user_list":
      roster.clear();
      for (const u of msg.users) {
        if (u.username !== myUsername) roster.set(u.username, u.publicKey);
      }
      renderRoster();
      break;

    case "message": {
      const plaintext = decryptFrom(msg.from, msg.nonce, msg.ciphertext);
      if (plaintext === null) {
        addSystemNote(msg.from, "⚠ Could not verify/decrypt a message from this sender (possible tampering).");
        return;
      }
      appendMessage(msg.from, { mine: false, text: plaintext, ts: msg.timestamp });
      if (activeChat === msg.from) renderMessages(msg.from);
      break;
    }

    default:
      break;
  }
}

// ---------- UI: screens & roster ----------

function showChatScreen() {
  el("login-screen").hidden = true;
  el("chat-screen").hidden = false;
  el("me-name").textContent = myUsername;
  renderFingerprint(sodium.to_base64(myKeyPair.publicKey), el("me-fingerprint"));
}

function renderRoster() {
  el("roster-count").textContent = roster.size;
  const list = el("roster");
  list.innerHTML = "";
  for (const [username] of roster) {
    const li = document.createElement("li");
    li.className = username === activeChat ? "active" : "";
    li.innerHTML = `<span class="name"><span class="dot"></span>${escapeHtml(username)}</span>`;
    li.addEventListener("click", () => selectChat(username));
    list.appendChild(li);
  }
}

function selectChat(username) {
  activeChat = username;
  el("chat-with").textContent = username;
  renderFingerprint(roster.get(username), el("chat-with-fp"), 5);
  el("message-input").disabled = false;
  el("send-btn").disabled = false;
  renderRoster();
  renderMessages(username);
}

function renderMessages(username) {
  const box = el("messages");
  box.innerHTML = "";
  const log = messageLog.get(username) || [];
  for (const item of log) {
    if (item.system) {
      const div = document.createElement("div");
      div.className = "system-note";
      div.textContent = item.text;
      box.appendChild(div);
      continue;
    }
    const div = document.createElement("div");
    div.className = `msg ${item.mine ? "mine" : "theirs"}`;
    div.innerHTML = `${escapeHtml(item.text)}<span class="meta">${new Date(item.ts).toLocaleTimeString()}</span>`;
    box.appendChild(div);
  }
  box.scrollTop = box.scrollHeight;
}

function appendMessage(username, item) {
  if (!messageLog.has(username)) messageLog.set(username, []);
  messageLog.get(username).push(item);
}

function addSystemNote(username, text) {
  if (!username) return;
  appendMessage(username, { system: true, text });
  if (activeChat === username) renderMessages(username);
}

// ---------- sending / encryption ----------

el("message-form").addEventListener("submit", (e) => {
  e.preventDefault();
  if (!activeChat) return;
  const input = el("message-input");
  const text = input.value.trim();
  if (!text) return;

  const recipientPublicKey = roster.get(activeChat);
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
  const ciphertext = sodium.crypto_box_easy(
    text,
    nonce,
    sodium.from_base64(recipientPublicKey),
    myKeyPair.privateKey
  );

  ws.send(
    JSON.stringify({
      type: "message",
      to: activeChat,
      nonce: sodium.to_base64(nonce),
      ciphertext: sodium.to_base64(ciphertext),
    })
  );

  appendMessage(activeChat, { mine: true, text, ts: Date.now() });
  renderMessages(activeChat);
  input.value = "";
});

function decryptFrom(fromUsername, nonceB64, ciphertextB64) {
  const senderPublicKeyB64 = roster.get(fromUsername);
  if (!senderPublicKeyB64) return null; // unknown sender, refuse to decrypt
  try {
    const opened = sodium.crypto_box_open_easy(
      sodium.from_base64(ciphertextB64),
      sodium.from_base64(nonceB64),
      sodium.from_base64(senderPublicKeyB64),
      myKeyPair.privateKey
    );
    return sodium.to_string(opened);
  } catch {
    return null; // authentication failed — tampered or wrong key
  }
}

function escapeHtml(str) {
  const d = document.createElement("div");
  d.textContent = str;
  return d.innerHTML;
}
