let sodium = null;
let myKeyPair = null;
let myUsername = null;
let authToken = null;
let ws = null;
let activeChat = null;

const roster = new Map();
const messageLog = new Map();
const MAX_MESSAGES_PER_CHAT = 100;

/* =========================
   WEBRTC AUDIO CALL STATE
========================= */
let peerConnection = null;
let localStream = null;
let currentCallTarget = null;
let isCaller = false;

// STUN + TURN (Me fallback për transmetim midis rrjeteve të ndryshme si 4G/Wi-Fi)
const rtcConfig = {
  iceServers: [
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "stun:stun1.l.google.com:19302" },
    { urls: "stun:stun2.l.google.com:19302" }
  ]
};

const el = (id) => document.getElementById(id);

/* =========================
   STORAGE
========================= */

function saveAuth() {
  localStorage.setItem(
    "sealed_auth",
    JSON.stringify({
      token: authToken,
      username: myUsername,
    })
  );
}

function loadAuth() {
  try {
    const raw = localStorage.getItem("sealed_auth");
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function deriveKeyFromPassword(password, saltBytes) {
  return sodium.crypto_pwhash(
    32,
    password,
    saltBytes,
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_ALG_DEFAULT
  );
}

function saveIdentity(password) {
  if (!myKeyPair || !myUsername || !password) return;

  const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const derivedKey = deriveKeyFromPassword(password, salt);
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);

  const encryptedPrivateKey = sodium.crypto_secretbox_easy(
    myKeyPair.privateKey,
    nonce,
    derivedKey
  );

  localStorage.setItem(
    "sealed_identity",
    JSON.stringify({
      username: myUsername,
      publicKey: sodium.to_base64(myKeyPair.publicKey),
      salt: sodium.to_base64(salt),
      nonce: sodium.to_base64(nonce),
      encryptedPrivateKey: sodium.to_base64(encryptedPrivateKey),
    })
  );
}

function loadRawIdentity() {
  try {
    const raw = localStorage.getItem("sealed_identity");
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function decryptIdentity(password, stored) {
  const salt = sodium.from_base64(stored.salt);
  const derivedKey = deriveKeyFromPassword(password, salt);
  const nonce = sodium.from_base64(stored.nonce);
  const encryptedPrivateKey = sodium.from_base64(stored.encryptedPrivateKey);

  const privateKey = sodium.crypto_secretbox_open_easy(
    encryptedPrivateKey,
    nonce,
    derivedKey
  );

  return {
    username: stored.username,
    publicKey: sodium.from_base64(stored.publicKey),
    privateKey,
  };
}

/* =========================
   UI HELPERS
========================= */

function showAuthError(message) {
  const box = el("auth-error");
  if (!box) return;
  box.textContent = message;
  box.hidden = false;
}

function clearAuthError() {
  const box = el("auth-error");
  if (!box) return;
  box.textContent = "";
  box.hidden = true;
}

function setLoading(loading) {
  const loginBtn = el("login-btn");
  const registerBtn = el("register-btn");
  const status = el("key-status");

  if (loginBtn) loginBtn.disabled = loading;
  if (registerBtn) registerBtn.disabled = loading;
  if (status) status.hidden = !loading;
}

function showChatScreen() {
  el("login-screen").hidden = true;
  el("chat-screen").hidden = false;
  el("me-name").textContent = myUsername;

  if (myKeyPair) {
    renderFingerprint(
      sodium.to_base64(myKeyPair.publicKey),
      el("me-fingerprint")
    );
  }
}

function showLoginScreen() {
  el("login-screen").hidden = false;
  el("chat-screen").hidden = true;
}

/* =========================
   FINGERPRINT
========================= */

function renderFingerprint(publicKeyBase64, container, blockCount = 6) {
  if (!container || !publicKeyBase64) return;
  container.innerHTML = "";

  try {
    const hash = sodium.crypto_generichash(
      16,
      sodium.from_base64(publicKeyBase64)
    );

    for (let i = 0; i < blockCount; i++) {
      const hue = hash[i * 2] * (360 / 255);
      const light = 45 + (hash[i * 2 + 1] % 20);
      const block = document.createElement("span");
      block.style.background = `hsl(${hue.toFixed(0)}, 65%, ${light}%)`;
      container.appendChild(block);
    }
  } catch (error) {
    console.error("Fingerprint error:", error);
  }
}

/* =========================
   SODIUM
========================= */

function sodiumReady() {
  return new Promise((resolve, reject) => {
    let attempts = 0;
    const check = () => {
      attempts++;
      if (window.sodium && window.sodium.ready) {
        window.sodium.ready
          .then(() => {
            sodium = window.sodium;
            resolve();
          })
          .catch(reject);
        return;
      }
      if (attempts > 300) {
        reject(new Error("libsodium failed to load."));
        return;
      }
      setTimeout(check, 50);
    };
    check();
  });
}

/* =========================
   API
========================= */

async function apiRequest(url, method, body) {
  const headers = { "Content-Type": "application/json" };
  if (authToken) {
    headers.Authorization = `Bearer ${authToken}`;
  }

  const response = await fetch(url, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  let data = {};
  try {
    data = await response.json();
  } catch {
    data = {};
  }

  if (!response.ok) {
    throw new Error(data.error || `Request failed (${response.status})`);
  }

  return data;
}

/* =========================
   KEYPAIR
========================= */

function ensureKeyPair() {
  if (!myKeyPair) {
    myKeyPair = sodium.crypto_box_keypair();
  }
}

/* =========================
   FORWARD SECRECY (Double Ratchet System)
========================= */

function concatBytes(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

function kdfRootChain(rootKey, dhOutput) {
  const material = sodium.crypto_generichash(
    64,
    concatBytes(rootKey, dhOutput)
  );

  return {
    newRootKey: material.slice(0, 32),
    chainKey: material.slice(32, 64)
  };
}

function kdfChainStep(chainKey) {
  const messageKey = sodium.crypto_generichash(
    32,
    concatBytes(chainKey, new Uint8Array([0x01]))
  );

  const nextChainKey = sodium.crypto_generichash(
    32,
    concatBytes(chainKey, new Uint8Array([0x02]))
  );

  return { messageKey, nextChainKey };
}

function ratchetStorageKey(contactUsername) {
  return `sealed_ratchet_${myUsername}_${contactUsername}`;
}

function loadRatchetState(contactUsername) {
  try {
    const raw = localStorage.getItem(ratchetStorageKey(contactUsername));
    if (!raw) return null;
    const p = JSON.parse(raw);

    return {
      rootKey: sodium.from_base64(p.rootKey),
      ratchetPrivateKey: p.ratchetPrivateKey ? sodium.from_base64(p.ratchetPrivateKey) : null,
      ratchetPublicKey: p.ratchetPublicKey ? sodium.from_base64(p.ratchetPublicKey) : null,
      remoteRatchetPublicKey: p.remoteRatchetPublicKey ? sodium.from_base64(p.remoteRatchetPublicKey) : null,
      sendChainKey: p.sendChainKey ? sodium.from_base64(p.sendChainKey) : null,
      recvChainKey: p.recvChainKey ? sodium.from_base64(p.recvChainKey) : null,
      needsSendRatchet: !!p.needsSendRatchet
    };
  } catch (error) {
    console.error("Ratchet state load error:", error);
    return null;
  }
}

function saveRatchetState(contactUsername, state) {
  localStorage.setItem(
    ratchetStorageKey(contactUsername),
    JSON.stringify({
      rootKey: sodium.to_base64(state.rootKey),
      ratchetPrivateKey: state.ratchetPrivateKey ? sodium.to_base64(state.ratchetPrivateKey) : null,
      ratchetPublicKey: state.ratchetPublicKey ? sodium.to_base64(state.ratchetPublicKey) : null,
      remoteRatchetPublicKey: state.remoteRatchetPublicKey ? sodium.to_base64(state.remoteRatchetPublicKey) : null,
      sendChainKey: state.sendChainKey ? sodium.to_base64(state.sendChainKey) : null,
      recvChainKey: state.recvChainKey ? sodium.to_base64(state.recvChainKey) : null,
      needsSendRatchet: state.needsSendRatchet
    })
  );
}

function initRatchetState(theirIdentityPublicKeyB64) {
  const dh0 = sodium.crypto_scalarmult(
    myKeyPair.privateKey,
    sodium.from_base64(theirIdentityPublicKeyB64)
  );

  const rootKey = sodium.crypto_generichash(32, dh0);

  return {
    rootKey,
    ratchetPrivateKey: null,
    ratchetPublicKey: null,
    remoteRatchetPublicKey: null,
    sendChainKey: null,
    recvChainKey: null,
    needsSendRatchet: false
  };
}

function getSendingMessageKey(contactUsername, theirIdentityPublicKeyB64) {
  let state = loadRatchetState(contactUsername);
  if (!state) {
    state = initRatchetState(theirIdentityPublicKeyB64);
  }

  if (!state.sendChainKey || state.needsSendRatchet) {
    const freshKeyPair = sodium.crypto_box_keypair();
    const dhPartnerPublicKey = state.remoteRatchetPublicKey || sodium.from_base64(theirIdentityPublicKeyB64);

    const dh = sodium.crypto_scalarmult(freshKeyPair.privateKey, dhPartnerPublicKey);
    const { newRootKey, chainKey } = kdfRootChain(state.rootKey, dh);

    state.rootKey = newRootKey;
    state.ratchetPrivateKey = freshKeyPair.privateKey;
    state.ratchetPublicKey = freshKeyPair.publicKey;
    state.sendChainKey = chainKey;
    state.needsSendRatchet = false;
  }

  const { messageKey, nextChainKey } = kdfChainStep(state.sendChainKey);
  state.sendChainKey = nextChainKey;

  saveRatchetState(contactUsername, state);

  return {
    messageKey,
    ratchetPublicKeyB64: sodium.to_base64(state.ratchetPublicKey)
  };
}

function getReceivingMessageKey(contactUsername, theirIdentityPublicKeyB64, senderRatchetPublicKeyB64) {
  let state = loadRatchetState(contactUsername);
  if (!state) {
    state = initRatchetState(theirIdentityPublicKeyB64);
  }

  if (senderRatchetPublicKeyB64) {
    const currentB64 = state.remoteRatchetPublicKey ? sodium.to_base64(state.remoteRatchetPublicKey) : null;

    if (currentB64 !== senderRatchetPublicKeyB64) {
      const senderRatchetPublicKey = sodium.from_base64(senderRatchetPublicKeyB64);
      const myDhPrivateKey = state.ratchetPrivateKey || myKeyPair.privateKey;

      const dh = sodium.crypto_scalarmult(myDhPrivateKey, senderRatchetPublicKey);
      const { newRootKey, chainKey } = kdfRootChain(state.rootKey, dh);

      state.rootKey = newRootKey;
      state.recvChainKey = chainKey;
      state.remoteRatchetPublicKey = senderRatchetPublicKey;
      state.needsSendRatchet = true;
    }
  }

  if (!state.recvChainKey) {
    const senderRatchetPublicKey = sodium.from_base64(senderRatchetPublicKeyB64);
    const dh = sodium.crypto_scalarmult(myKeyPair.privateKey, senderRatchetPublicKey);
    const { newRootKey, chainKey } = kdfRootChain(state.rootKey, dh);

    state.rootKey = newRootKey;
    state.recvChainKey = chainKey;
    state.remoteRatchetPublicKey = senderRatchetPublicKey;
    state.needsSendRatchet = true;
  }

  const { messageKey, nextChainKey } = kdfChainStep(state.recvChainKey);
  state.recvChainKey = nextChainKey;

  saveRatchetState(contactUsername, state);
  return messageKey;
}

/* =========================
   REGISTER & LOGIN
========================= */

async function register() {
  clearAuthError();

  const username = el("username").value.trim();
  const password = el("password").value;

  if (!username) {
    showAuthError("Please enter a username.");
    return;
  }

  if (password.length < 8) {
    showAuthError("Password must contain at least 8 characters.");
    return;
  }

  setLoading(true);

  try {
    ensureKeyPair();
    const publicKey = sodium.to_base64(myKeyPair.publicKey);

    const result = await apiRequest("/api/register", "POST", {
      username,
      password,
      publicKey,
    });

    authToken = result.token;
    myUsername = result.user.username;

    saveAuth();
    saveIdentity(password);
    connectWebSocket();
  } catch (error) {
    console.error("Registration error:", error);
    showAuthError(error.message);
    setLoading(false);
  }
}

async function login() {
  clearAuthError();

  const username = el("username").value.trim();
  const password = el("password").value;

  if (!username || !password) {
    showAuthError("Username and password are required.");
    return;
  }

  setLoading(true);

  try {
    const result = await apiRequest("/api/login", "POST", { username, password });

    authToken = result.token;
    myUsername = result.user.username;

    const stored = loadRawIdentity();
    if (stored && stored.username === myUsername) {
      try {
        myKeyPair = decryptIdentity(password, stored);
      } catch (error) {
        console.error("Identity decrypt error:", error);
        showAuthError("This password does not match the encrypted key stored in this browser.");
        setLoading(false);
        return;
      }
    } else {
      ensureKeyPair();
      saveIdentity(password);
    }

    saveAuth();
    await apiRequest("/api/me/public-key", "PUT", {
      publicKey: sodium.to_base64(myKeyPair.publicKey),
    });

    connectWebSocket();
  } catch (error) {
    console.error("Login error:", error);
    showAuthError(error.message);
    setLoading(false);
  }
}

/* =========================
   WEBSOCKET
========================= */

function connectWebSocket() {
  if (!authToken) {
    showAuthError("Authentication token is missing.");
    setLoading(false);
    return;
  }

  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
    return;
  }

  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  ws = new WebSocket(`${protocol}//${location.host}`);

  ws.addEventListener("open", () => {
    console.log("WebSocket connected.");
    ws.send(JSON.stringify({ type: "authenticate", token: authToken }));
  });

  ws.addEventListener("message", (event) => {
    try {
      const msg = JSON.parse(event.data);
      handleServerMessage(msg);
    } catch (error) {
      console.error("WebSocket message error:", error);
    }
  });

  ws.addEventListener("error", (error) => {
    console.error("WebSocket error:", error);
  });

  ws.addEventListener("close", () => {
    console.log("WebSocket disconnected.");
    cleanUpCall(); // Ndërpret telefonatën automatikisht nëse shkëputet rrjeti
    if (el("chat-screen").hidden === false) {
      addSystemNote(activeChat, "Disconnected from server. Refresh to reconnect.");
    }
  });
}

/* =========================
   SERVER MESSAGES & WEBRTC HANDLERS
========================= */

async function handleServerMessage(msg) {
  switch (msg.type) {
    case "authenticated":
      myUsername = msg.username;
      saveAuth();
      setLoading(false);
      showChatScreen();
      break;

    case "auth_error":
      setLoading(false);
      showLoginScreen();
      showAuthError(msg.message || "Authentication failed.");
      if (msg.message && msg.message.toLowerCase().includes("expired")) {
        localStorage.removeItem("sealed_auth");
      }
      break;

    case "error":
      setLoading(false);
      showAuthError(msg.message || "An error occurred.");
      break;

    case "user_list":
      roster.clear();
      for (const user of msg.users || []) {
        if (user.username !== myUsername) {
          roster.set(user.username, user.publicKey);
        }
      }
      renderRoster();
      break;

    case "message": {
      const plaintext = decryptFrom(msg.from, msg.nonce, msg.ciphertext, msg.ratchetPublicKey);

      if (plaintext === null) {
        addSystemNote(msg.from, "Could not verify or decrypt this message.");
        return;
      }

      appendMessage(msg.from, {
        mine: false,
        text: plaintext,
        ts: msg.timestamp || Date.now(),
      });

      if (activeChat === msg.from) {
        renderMessages(msg.from);
      }
      break;
    }

    /* WEBRTC AUDIO CALL SIGNALS */
    case "call_offer":
      handleCallOffer(msg.from, msg.offer);
      break;

    case "call_answer":
      if (peerConnection && msg.from === currentCallTarget) {
        await peerConnection.setRemoteDescription(new RTCSessionDescription(msg.answer));
        el("call-status").textContent = "Connected";
      }
      break;

    case "ice_candidate":
      if (peerConnection && msg.from === currentCallTarget && msg.candidate) {
        try {
          await peerConnection.addIceCandidate(new RTCIceCandidate(msg.candidate));
        } catch (e) {
          console.error("Error adding ICE candidate", e);
        }
      }
      break;

    case "call_end":
      if (msg.from === currentCallTarget) {
        cleanUpCall();
        alert(`${msg.from} ended the call.`);
      }
      break;

    case "call_unavailable":
      cleanUpCall();
      alert(`User ${msg.to} is offline or unavailable.`);
      break;

    default:
      console.log("Unknown server message:", msg);
      break;
  }
}

/* =========================
   WEBRTC AUDIO LOGIC
========================= */

async function setupLocalAudio() {
  try {
    localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
    return true;
  } catch (err) {
    console.error("Microphone permission denied:", err);
    alert("Microphone access is required to place/receive calls.");
    return false;
  }
}

function createPeerConnection(targetUser) {
  peerConnection = new RTCPeerConnection(rtcConfig);

  if (localStream) {
    localStream.getTracks().forEach((track) => {
      peerConnection.addTrack(track, localStream);
    });
  }

  peerConnection.ontrack = (event) => {
    const remoteAudio = el("remote-audio");
    if (remoteAudio && event.streams[0]) {
      remoteAudio.srcObject = event.streams[0];
      remoteAudio.play().catch((err) => {
        console.error("Autoplay Error:", err);
      });
    }
  };

  peerConnection.onicecandidate = (event) => {
    if (event.candidate && ws) {
      ws.send(JSON.stringify({
        type: "ice_candidate",
        to: targetUser,
        candidate: event.candidate
      }));
    }
  };

  peerConnection.oniceconnectionstatechange = () => {
    if (peerConnection) {
      if (peerConnection.iceConnectionState === "disconnected" || peerConnection.iceConnectionState === "failed") {
        cleanUpCall();
      }
    }
  };
}

async function startAudioCall() {
  if (!activeChat) return;

  const gotAudio = await setupLocalAudio();
  if (!gotAudio) return;

  currentCallTarget = activeChat;
  isCaller = true;

  showCallModal("Calling...", currentCallTarget, false, false, true);
  createPeerConnection(currentCallTarget);

  const offer = await peerConnection.createOffer();
  await peerConnection.setLocalDescription(offer);

  ws.send(JSON.stringify({
    type: "call_offer",
    to: currentCallTarget,
    offer: offer
  }));
}

async function handleCallOffer(fromUser, offer) {
  currentCallTarget = fromUser;
  isCaller = false;

  showCallModal("Incoming Audio Call", fromUser, true, true, false);
  window.pendingCallOffer = offer;
}

async function acceptCall() {
  const gotAudio = await setupLocalAudio();
  if (!gotAudio) {
    rejectCall();
    return;
  }

  showCallModal("Connected", currentCallTarget, false, false, true);
  createPeerConnection(currentCallTarget);

  await peerConnection.setRemoteDescription(new RTCSessionDescription(window.pendingCallOffer));
  const answer = await peerConnection.createAnswer();
  await peerConnection.setLocalDescription(answer);

  ws.send(JSON.stringify({
    type: "call_answer",
    to: currentCallTarget,
    answer: answer
  }));

  window.pendingCallOffer = null;
}

function rejectCall() {
  if (ws && currentCallTarget) {
    ws.send(JSON.stringify({ type: "call_end", to: currentCallTarget }));
  }
  cleanUpCall();
}

function endCall() {
  if (ws && currentCallTarget) {
    ws.send(JSON.stringify({ type: "call_end", to: currentCallTarget }));
  }
  cleanUpCall();
}

function cleanUpCall() {
  if (peerConnection) {
    peerConnection.close();
    peerConnection = null;
  }
  if (localStream) {
    localStream.getTracks().forEach((track) => track.stop());
    localStream = null;
  }
  const remoteAudio = el("remote-audio");
  if (remoteAudio) {
    remoteAudio.srcObject = null;
  }

  currentCallTarget = null;
  window.pendingCallOffer = null;
  hideCallModal();
}

function showCallModal(statusText, userName, showAccept, showReject, showEnd) {
  const modal = el("call-modal");
  if (!modal) return;

  el("call-status").textContent = statusText;
  el("call-user-name").textContent = userName;

  el("accept-call-btn").style.display = showAccept ? "inline-block" : "none";
  el("reject-call-btn").style.display = showReject ? "inline-block" : "none";
  el("end-call-btn").style.display = showEnd ? "inline-block" : "none";

  modal.style.display = "flex";
}

function hideCallModal() {
  const modal = el("call-modal");
  if (modal) {
    modal.style.display = "none";
  }
}

/* =========================
   ROSTER & CHAT UI
========================= */

function renderRoster() {
  const count = el("roster-count");
  const list = el("roster");

  count.textContent = roster.size;
  list.innerHTML = "";

  for (const [username] of roster) {
    const li = document.createElement("li");
    li.className = username === activeChat ? "active" : "";

    const name = document.createElement("span");
    name.className = "name";

    const dot = document.createElement("span");
    dot.className = "dot";

    name.appendChild(dot);
    const text = document.createTextNode(username);
    name.appendChild(text);

    li.appendChild(name);
    li.addEventListener("click", () => {
      selectChat(username);
    });

    list.appendChild(li);
  }
}

function selectChat(username) {
  const publicKey = roster.get(username);
  if (!publicKey) return;

  activeChat = username;

  el("chat-with").textContent = username;
  renderFingerprint(publicKey, el("chat-with-fp"), 5);

  el("message-input").disabled = false;
  el("send-btn").disabled = false;

  const callBtn = el("call-btn");
  if (callBtn) {
    callBtn.style.display = "inline-block";
  }

  renderRoster();
  renderMessages(username);
  el("message-input").focus();
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

    const text = document.createTextNode(item.text);
    div.appendChild(text);

    const meta = document.createElement("span");
    meta.className = "meta";
    meta.textContent = new Date(item.ts).toLocaleTimeString();

    div.appendChild(meta);
    box.appendChild(div);
  }

  box.scrollTop = box.scrollHeight;
}

function appendMessage(username, item) {
  if (!messageLog.has(username)) {
    messageLog.set(username, []);
  }

  const log = messageLog.get(username);
  log.push(item);

  // Kufizon numrin e mesazheve për të mbrojtur memorien
  if (log.length > MAX_MESSAGES_PER_CHAT) {
    log.shift();
  }
}

function addSystemNote(username, text) {
  if (!username) return;
  appendMessage(username, { system: true, text });
  if (activeChat === username) {
    renderMessages(username);
  }
}

function sendMessage() {
  if (!activeChat) return;

  if (!ws || ws.readyState !== WebSocket.OPEN) {
    alert("Not connected to the server.");
    return;
  }

  const input = el("message-input");
  const text = input.value.trim();
  if (!text) return;

  const recipientPublicKey = roster.get(activeChat);
  if (!recipientPublicKey) {
    alert("Recipient key is not available.");
    return;
  }

  try {
    const { messageKey, ratchetPublicKeyB64 } = getSendingMessageKey(
      activeChat,
      recipientPublicKey
    );

    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const ciphertext = sodium.crypto_secretbox_easy(text, nonce, messageKey);

    ws.send(
      JSON.stringify({
        type: "message",
        to: activeChat,
        nonce: sodium.to_base64(nonce),
        ciphertext: sodium.to_base64(ciphertext),
        ratchetPublicKey: ratchetPublicKeyB64,
      })
    );

    appendMessage(activeChat, {
      mine: true,
      text,
      ts: Date.now(),
    });

    renderMessages(activeChat);

    input.value = "";
    input.focus();
  } catch (error) {
    console.error("Encryption/send error:", error);
    alert("Could not encrypt/send the message.");
  }
}

function decryptFrom(fromUsername, nonceB64, ciphertextB64, ratchetPublicKeyB64) {
  const senderPublicKeyB64 = roster.get(fromUsername);
  if (!senderPublicKeyB64) return null;

  try {
    const messageKey = getReceivingMessageKey(
      fromUsername,
      senderPublicKeyB64,
      ratchetPublicKeyB64
    );

    if (!messageKey) return null;

    const opened = sodium.crypto_secretbox_open_easy(
      sodium.from_base64(ciphertextB64),
      sodium.from_base64(nonceB64),
      messageKey
    );

    return sodium.to_string(opened);
  } catch (error) {
    console.error("Decrypt error:", error);
    return null;
  }
}

/* =========================
   EVENTS
========================= */

document.addEventListener("DOMContentLoaded", async () => {
  try {
    await sodiumReady();
    console.log("libsodium ready.");

    const loginForm = el("login-form");
    const registerBtn = el("register-btn");
    const messageForm = el("message-form");
    const callBtn = el("call-btn");

    const acceptCallBtn = el("accept-call-btn");
    const rejectCallBtn = el("reject-call-btn");
    const endCallBtn = el("end-call-btn");

    if (loginForm) {
      loginForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        await login();
      });
    }

    if (registerBtn) {
      registerBtn.addEventListener("click", async () => {
        await register();
      });
    }

    if (messageForm) {
      messageForm.addEventListener("submit", (event) => {
        event.preventDefault();
        sendMessage();
      });
    }

    if (callBtn) {
      callBtn.addEventListener("click", () => {
        startAudioCall();
      });
    }

    if (acceptCallBtn) acceptCallBtn.addEventListener("click", acceptCall);
    if (rejectCallBtn) rejectCallBtn.addEventListener("click", rejectCall);
    if (endCallBtn) endCallBtn.addEventListener("click", endCall);

    const savedAuth = loadAuth();
    if (savedAuth && savedAuth.username) {
      const usernameInput = el("username");
      if (usernameInput) usernameInput.value = savedAuth.username;
      const passwordInput = el("password");
      if (passwordInput) passwordInput.focus();
    }
  } catch (error) {
    console.error("Application startup error:", error);
    showAuthError("Could not start encryption system. Check that libsodium loaded correctly.");
  }
});
