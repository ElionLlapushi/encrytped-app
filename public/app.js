let sodium = null;
let myKeyPair = null;
let myUsername = null;
let authToken = null;
let ws = null;
let activeChat = null;

/* =========================
   WEBRTC STATE
========================= */

let localStream = null;
let peerConnection = null;
let currentCallTarget = null;
let isCaller = false;
let pendingIceCandidates = [];

/* =========================
   APP STATE
========================= */

const roster = new Map();
const messageLog = new Map();

const MAX_MESSAGES_PER_CHAT = 100;

/* =========================
   SECURE INDEXEDDB STORAGE
========================= */

const DB_NAME = "SealedSecureDB";
const DB_VERSION = 1;
const STORE_KEYS = "keys";

function openSecureDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event) => {
      const db = event.target.result;

      if (!db.objectStoreNames.contains(STORE_KEYS)) {
        db.createObjectStore(STORE_KEYS);
      }
    };

    request.onsuccess = () => {
      resolve(request.result);
    };

    request.onerror = () => {
      reject(request.error);
    };
  });
}

async function setSecureItem(key, value) {
  const db = await openSecureDB();

  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_KEYS, "readwrite");
    const store = tx.objectStore(STORE_KEYS);

    const request = store.put(value, key);

    request.onsuccess = () => {
      resolve();
    };

    request.onerror = () => {
      reject(request.error);
    };
  });
}

async function getSecureItem(key) {
  const db = await openSecureDB();

  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_KEYS, "readonly");
    const store = tx.objectStore(STORE_KEYS);

    const request = store.get(key);

    request.onsuccess = () => {
      resolve(request.result);
    };

    request.onerror = () => {
      reject(request.error);
    };
  });
}

async function removeSecureItem(key) {
  const db = await openSecureDB();

  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_KEYS, "readwrite");
    const store = tx.objectStore(STORE_KEYS);

    const request = store.delete(key);

    request.onsuccess = () => {
      resolve();
    };

    request.onerror = () => {
      reject(request.error);
    };
  });
}

/* =========================
   DOM HELPER
========================= */

const el = (id) => document.getElementById(id);

/* =========================
   STUN + TURN CONFIG
========================= */

let rtcConfig = {
  iceServers: [
    {
      urls: "stun:stun.l.google.com:19302"
    },
    {
      urls: "stun:stun1.l.google.com:19302"
    },
    {
      urls: "stun:stun2.l.google.com:19302"
    }
  ]
};

/* =========================
   LOAD TURN CONFIG
========================= */

async function loadRtcConfig() {
  try {
    const data = await apiRequest(
      "/api/turn-credentials",
      "GET"
    );

    if (
      data &&
      Array.isArray(data.iceServers) &&
      data.iceServers.length > 0
    ) {
      rtcConfig = {
        iceServers: data.iceServers
      };

      console.log("TURN configuration loaded.");
    } else {
      console.warn(
        "TURN credentials were empty. Using STUN only."
      );
    }
  } catch (error) {
    console.error(
      "Could not load TURN config. Falling back to STUN only:",
      error
    );
  }
}

/* =========================
   AUTH STORAGE
========================= */

function saveAuth() {
  localStorage.setItem(
    "sealed_auth",
    JSON.stringify({
      token: authToken,
      username: myUsername
    })
  );
}

function loadAuth() {
  try {
    const raw = localStorage.getItem("sealed_auth");

    if (!raw) {
      return null;
    }

    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/* =========================
   PASSWORD KEY DERIVATION
========================= */

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

/* =========================
   SAVE IDENTITY
========================= */

async function saveIdentity(password) {
  if (!myKeyPair || !myUsername || !password) {
    return;
  }

  const salt = sodium.randombytes_buf(
    sodium.crypto_pwhash_SALTBYTES
  );

  const derivedKey = deriveKeyFromPassword(
    password,
    salt
  );

  const nonce = sodium.randombytes_buf(
    sodium.crypto_secretbox_NONCEBYTES
  );

  const encryptedPrivateKey =
    sodium.crypto_secretbox_easy(
      myKeyPair.privateKey,
      nonce,
      derivedKey
    );

  const identityData = {
    username: myUsername,

    publicKey: sodium.to_base64(
      myKeyPair.publicKey
    ),

    salt: sodium.to_base64(salt),

    nonce: sodium.to_base64(nonce),

    encryptedPrivateKey:
      sodium.to_base64(encryptedPrivateKey)
  };

  await setSecureItem(
    "sealed_identity",
    identityData
  );
}

/* =========================
   LOAD IDENTITY
========================= */

async function loadRawIdentity() {
  try {
    const data = await getSecureItem(
      "sealed_identity"
    );

    return data || null;
  } catch (error) {
    console.error(
      "Error loading identity from IndexedDB:",
      error
    );

    return null;
  }
}

/* =========================
   DECRYPT IDENTITY
========================= */

function decryptIdentity(password, stored) {
  const salt = sodium.from_base64(
    stored.salt
  );

  const derivedKey =
    deriveKeyFromPassword(
      password,
      salt
    );

  const nonce = sodium.from_base64(
    stored.nonce
  );

  const encryptedPrivateKey =
    sodium.from_base64(
      stored.encryptedPrivateKey
    );

  const privateKey =
    sodium.crypto_secretbox_open_easy(
      encryptedPrivateKey,
      nonce,
      derivedKey
    );

  return {
    username: stored.username,

    publicKey: sodium.from_base64(
      stored.publicKey
    ),

    privateKey
  };
}

/* =========================
   UI HELPERS
========================= */

function showAuthError(message) {
  const box = el("auth-error");

  if (!box) {
    return;
  }

  box.textContent = message;
  box.hidden = false;
}

function clearAuthError() {
  const box = el("auth-error");

  if (!box) {
    return;
  }

  box.textContent = "";
  box.hidden = true;
}

function setLoading(loading) {
  const loginBtn = el("login-btn");
  const registerBtn = el("register-btn");
  const status = el("key-status");

  if (loginBtn) {
    loginBtn.disabled = loading;
  }

  if (registerBtn) {
    registerBtn.disabled = loading;
  }

  if (status) {
    status.hidden = !loading;
  }
}

function showChatScreen() {
  const loginScreen = el("login-screen");
  const chatScreen = el("chat-screen");

  if (loginScreen) {
    loginScreen.hidden = true;
  }

  if (chatScreen) {
    chatScreen.hidden = false;
  }

  const meName = el("me-name");

  if (meName) {
    meName.textContent = myUsername;
  }

  if (myKeyPair) {
    renderFingerprint(
      sodium.to_base64(
        myKeyPair.publicKey
      ),
      el("me-fingerprint")
    );
  }
}

function showLoginScreen() {
  const loginScreen = el("login-screen");
  const chatScreen = el("chat-screen");

  if (loginScreen) {
    loginScreen.hidden = false;
  }

  if (chatScreen) {
    chatScreen.hidden = true;
  }
}

/* =========================
   FINGERPRINT
========================= */

function renderFingerprint(
  publicKeyBase64,
  container,
  blockCount = 6
) {
  if (!container || !publicKeyBase64) {
    return;
  }

  container.innerHTML = "";

  try {
    const hash =
      sodium.crypto_generichash(
        16,
        sodium.from_base64(
          publicKeyBase64
        )
      );

    for (
      let i = 0;
      i < blockCount;
      i++
    ) {
      const hue =
        hash[i * 2] *
        (360 / 255);

      const light =
        45 +
        (hash[i * 2 + 1] % 20);

      const block =
        document.createElement(
          "span"
        );

      block.style.background =
        `hsl(${hue.toFixed(0)}, 65%, ${light}%)`;

      container.appendChild(block);
    }
  } catch (error) {
    console.error(
      "Fingerprint error:",
      error
    );
  }
}

/* =========================
   SODIUM
========================= */

function sodiumReady() {
  return new Promise(
    (resolve, reject) => {
      let attempts = 0;

      const check = () => {
        attempts++;

        if (
          window.sodium &&
          window.sodium.ready
        ) {
          window.sodium.ready
            .then(() => {
              sodium = window.sodium;
              resolve();
            })
            .catch(reject);

          return;
        }

        if (attempts > 300) {
          reject(
            new Error(
              "libsodium failed to load."
            )
          );

          return;
        }

        setTimeout(
          check,
          50
        );
      };

      check();
    }
  );
}

/* =========================
   API
========================= */

async function apiRequest(
  url,
  method,
  body
) {
  const headers = {
    "Content-Type": "application/json"
  };

  if (authToken) {
    headers.Authorization =
      `Bearer ${authToken}`;
  }

  const response = await fetch(
    url,
    {
      method,
      headers,
      body:
        body !== undefined
          ? JSON.stringify(body)
          : undefined
    }
  );

  let data = {};

  try {
    data = await response.json();
  } catch {
    data = {};
  }

  if (!response.ok) {
    throw new Error(
      data.error ||
      `Request failed (${response.status})`
    );
  }

  return data;
}

/* =========================
   KEYPAIR
========================= */

function ensureKeyPair() {
  if (!myKeyPair) {
    myKeyPair =
      sodium.crypto_box_keypair();
  }
}

/* =========================
   DOUBLE RATCHET
========================= */

function concatBytes(...arrays) {
  const total =
    arrays.reduce(
      (sum, a) =>
        sum + a.length,
      0
    );

  const out =
    new Uint8Array(total);

  let offset = 0;

  for (const a of arrays) {
    out.set(
      a,
      offset
    );

    offset += a.length;
  }

  return out;
}

function kdfRootChain(
  rootKey,
  dhOutput
) {
  const material =
    sodium.crypto_generichash(
      64,
      concatBytes(
        rootKey,
        dhOutput
      )
    );

  return {
    newRootKey:
      material.slice(0, 32),

    chainKey:
      material.slice(32, 64)
  };
}

function kdfChainStep(
  chainKey
) {
  const messageKey =
    sodium.crypto_generichash(
      32,
      concatBytes(
        chainKey,
        new Uint8Array([0x01])
      )
    );

  const nextChainKey =
    sodium.crypto_generichash(
      32,
      concatBytes(
        chainKey,
        new Uint8Array([0x02])
      )
    );

  return {
    messageKey,
    nextChainKey
  };
}

function ratchetStorageKey(
  contactUsername
) {
  return `sealed_ratchet_${myUsername}_${contactUsername}`;
}

async function loadRatchetState(
  contactUsername
) {
  try {
    const raw =
      await getSecureItem(
        ratchetStorageKey(
          contactUsername
        )
      );

    if (!raw) {
      return null;
    }

    return {
      rootKey:
        sodium.from_base64(
          raw.rootKey
        ),

      ratchetPrivateKey:
        raw.ratchetPrivateKey
          ? sodium.from_base64(
              raw.ratchetPrivateKey
            )
          : null,

      ratchetPublicKey:
        raw.ratchetPublicKey
          ? sodium.from_base64(
              raw.ratchetPublicKey
            )
          : null,

      remoteRatchetPublicKey:
        raw.remoteRatchetPublicKey
          ? sodium.from_base64(
              raw.remoteRatchetPublicKey
            )
          : null,

      sendChainKey:
        raw.sendChainKey
          ? sodium.from_base64(
              raw.sendChainKey
            )
          : null,

      recvChainKey:
        raw.recvChainKey
          ? sodium.from_base64(
              raw.recvChainKey
            )
          : null,

      needsSendRatchet:
        !!raw.needsSendRatchet
    };
  } catch (error) {
    console.error(
      "Ratchet state load error:",
      error
    );

    return null;
  }
}

async function saveRatchetState(
  contactUsername,
  state
) {
  await setSecureItem(
    ratchetStorageKey(
      contactUsername
    ),
    {
      rootKey:
        sodium.to_base64(
          state.rootKey
        ),

      ratchetPrivateKey:
        state.ratchetPrivateKey
          ? sodium.to_base64(
              state.ratchetPrivateKey
            )
          : null,

      ratchetPublicKey:
        state.ratchetPublicKey
          ? sodium.to_base64(
              state.ratchetPublicKey
            )
          : null,

      remoteRatchetPublicKey:
        state.remoteRatchetPublicKey
          ? sodium.to_base64(
              state.remoteRatchetPublicKey
            )
          : null,

      sendChainKey:
        state.sendChainKey
          ? sodium.to_base64(
              state.sendChainKey
            )
          : null,

      recvChainKey:
        state.recvChainKey
          ? sodium.to_base64(
              state.recvChainKey
            )
          : null,

      needsSendRatchet:
        state.needsSendRatchet
    }
  );
}

function initRatchetState(
  theirIdentityPublicKeyB64
) {
  const dh =
    sodium.crypto_scalarmult(
      myKeyPair.privateKey,
      sodium.from_base64(
        theirIdentityPublicKeyB64
      )
    );

  const rootKey =
    sodium.crypto_generichash(
      32,
      dh
    );

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

async function getSendingMessageKey(
  contactUsername,
  theirIdentityPublicKeyB64
) {
  let state =
    await loadRatchetState(
      contactUsername
    );

  if (!state) {
    state =
      initRatchetState(
        theirIdentityPublicKeyB64
      );
  }

  if (
    !state.sendChainKey ||
    state.needsSendRatchet
  ) {
    const freshKeyPair =
      sodium.crypto_box_keypair();

    const dhPartnerPublicKey =
      state.remoteRatchetPublicKey ||
      sodium.from_base64(
        theirIdentityPublicKeyB64
      );

    const dh =
      sodium.crypto_scalarmult(
        freshKeyPair.privateKey,
        dhPartnerPublicKey
      );

    const {
      newRootKey,
      chainKey
    } =
      kdfRootChain(
        state.rootKey,
        dh
      );

    state.rootKey =
      newRootKey;

    state.ratchetPrivateKey =
      freshKeyPair.privateKey;

    state.ratchetPublicKey =
      freshKeyPair.publicKey;

    state.sendChainKey =
      chainKey;

    state.needsSendRatchet =
      false;
  }

  const {
    messageKey,
    nextChainKey
  } =
    kdfChainStep(
      state.sendChainKey
    );

  state.sendChainKey =
    nextChainKey;

  await saveRatchetState(
    contactUsername,
    state
  );

  return {
    messageKey,

    ratchetPublicKeyB64:
      sodium.to_base64(
        state.ratchetPublicKey
      )
  };
}

async function getReceivingMessageKey(
  contactUsername,
  theirIdentityPublicKeyB64,
  senderRatchetPublicKeyB64
) {
  let state =
    await loadRatchetState(
      contactUsername
    );

  if (!state) {
    state =
      initRatchetState(
        theirIdentityPublicKeyB64
      );
  }

  if (senderRatchetPublicKeyB64) {
    const currentB64 =
      state.remoteRatchetPublicKey
        ? sodium.to_base64(
            state.remoteRatchetPublicKey
          )
        : null;

    if (
      currentB64 !==
      senderRatchetPublicKeyB64
    ) {
      const senderRatchetPublicKey =
        sodium.from_base64(
          senderRatchetPublicKeyB64
        );

      const myDhPrivateKey =
        state.ratchetPrivateKey ||
        myKeyPair.privateKey;

      const dh =
        sodium.crypto_scalarmult(
          myDhPrivateKey,
          senderRatchetPublicKey
        );

      const {
        newRootKey,
        chainKey
      } =
        kdfRootChain(
          state.rootKey,
          dh
        );

      state.rootKey =
        newRootKey;

      state.recvChainKey =
        chainKey;

      state.remoteRatchetPublicKey =
        senderRatchetPublicKey;

      state.needsSendRatchet =
        true;
    }
  }

  if (!state.recvChainKey) {
    if (!senderRatchetPublicKeyB64) {
      throw new Error(
        "Missing sender ratchet public key."
      );
    }

    const senderRatchetPublicKey =
      sodium.from_base64(
        senderRatchetPublicKeyB64
      );

    const dh =
      sodium.crypto_scalarmult(
        myKeyPair.privateKey,
        senderRatchetPublicKey
      );

    const {
      newRootKey,
      chainKey
    } =
      kdfRootChain(
        state.rootKey,
        dh
      );

    state.rootKey =
      newRootKey;

    state.recvChainKey =
      chainKey;

    state.remoteRatchetPublicKey =
      senderRatchetPublicKey;

    state.needsSendRatchet =
      true;
  }

  const {
    messageKey,
    nextChainKey
  } =
    kdfChainStep(
      state.recvChainKey
    );

  state.recvChainKey =
    nextChainKey;

  await saveRatchetState(
    contactUsername,
    state
  );

  return messageKey;
}

/* =========================
   REGISTER
========================= */

async function register() {
  clearAuthError();

  const username =
    el("username").value.trim();

  const password =
    el("password").value;

  if (!username) {
    showAuthError(
      "Please enter a username."
    );

    return;
  }

  if (password.length < 8) {
    showAuthError(
      "Password must contain at least 8 characters."
    );

    return;
  }

  setLoading(true);

  try {
    ensureKeyPair();

    const publicKey =
      sodium.to_base64(
        myKeyPair.publicKey
      );

    const result =
      await apiRequest(
        "/api/register",
        "POST",
        {
          username,
          password,
          publicKey
        }
      );

    authToken =
      result.token;

    myUsername =
      result.user.username;

    saveAuth();

    await saveIdentity(
      password
    );

    connectWebSocket();
  } catch (error) {
    console.error(
      "Registration error:",
      error
    );

    showAuthError(
      error.message
    );

    setLoading(false);
  }
}

/* =========================
   LOGIN
========================= */

async function login() {
  clearAuthError();

  const username =
    el("username").value.trim();

  const password =
    el("password").value;

  if (!username || !password) {
    showAuthError(
      "Username and password are required."
    );

    return;
  }

  setLoading(true);

  try {
    const result =
      await apiRequest(
        "/api/login",
        "POST",
        {
          username,
          password
        }
      );

    authToken =
      result.token;

    myUsername =
      result.user.username;

    const stored =
      await loadRawIdentity();

    if (
      stored &&
      stored.username === myUsername
    ) {
      try {
        myKeyPair =
          decryptIdentity(
            password,
            stored
          );
      } catch (error) {
        console.error(
          "Identity decrypt error:",
          error
        );

        showAuthError(
          "This password does not match the encrypted key stored in this browser."
        );

        setLoading(false);

        return;
      }
    } else {
      ensureKeyPair();

      await saveIdentity(
        password
      );
    }

    saveAuth();

    await apiRequest(
      "/api/me/public-key",
      "PUT",
      {
        publicKey:
          sodium.to_base64(
            myKeyPair.publicKey
          )
      }
    );

    connectWebSocket();
  } catch (error) {
    console.error(
      "Login error:",
      error
    );

    showAuthError(
      error.message
    );

    setLoading(false);
  }
}

/* =========================
   WEBSOCKET
========================= */

function connectWebSocket() {
  if (!authToken) {
    showAuthError(
      "Authentication token is missing."
    );

    setLoading(false);

    return;
  }

  if (
    ws &&
    (
      ws.readyState ===
      WebSocket.OPEN ||
      ws.readyState ===
      WebSocket.CONNECTING
    )
  ) {
    return;
  }

  const protocol =
    location.protocol === "https:"
      ? "wss:"
      : "ws:";

  ws =
    new WebSocket(
      `${protocol}//${location.host}`
    );

  ws.addEventListener(
    "open",
    () => {
      console.log(
        "WebSocket connected."
      );

      ws.send(
        JSON.stringify({
          type: "authenticate",
          token: authToken
        })
      );
    }
  );

  ws.addEventListener(
    "message",
    (event) => {
      try {
        const msg =
          JSON.parse(
            event.data
          );

        handleServerMessage(
          msg
        );
      } catch (error) {
        console.error(
          "WebSocket message error:",
          error
        );
      }
    }
  );

  ws.addEventListener(
    "error",
    (error) => {
      console.error(
        "WebSocket error:",
        error
      );
    }
  );

  ws.addEventListener(
    "close",
    () => {
      console.log(
        "WebSocket disconnected."
      );

      cleanUpCall();

      const chatScreen =
        el("chat-screen");

      if (
        chatScreen &&
        chatScreen.hidden === false
      ) {
        addSystemNote(
          activeChat,
          "Disconnected from server. Refresh to reconnect."
        );
      }
    }
  );
}

/* =========================
   SERVER MESSAGES
========================= */

async function handleServerMessage(msg) {
  switch (msg.type) {

    /* =====================
       AUTHENTICATED
    ===================== */

    case "authenticated":
      myUsername =
        msg.username;

      saveAuth();

      await loadRtcConfig();

      setLoading(false);

      showChatScreen();

      break;

    /* =====================
       AUTH ERROR
    ===================== */

    case "auth_error":
      setLoading(false);

      showLoginScreen();

      showAuthError(
        msg.message ||
        "Authentication failed."
      );

      if (
        msg.message &&
        msg.message
          .toLowerCase()
          .includes("expired")
      ) {
        localStorage.removeItem(
          "sealed_auth"
        );
      }

      break;

    /* =====================
       ERROR
    ===================== */

    case "error":
      setLoading(false);

      showAuthError(
        msg.message ||
        "An error occurred."
      );

      break;

    /* =====================
       USER LIST
    ===================== */

    case "user_list":
      roster.clear();

      for (
        const user of
        msg.users || []
      ) {
        if (
          user.username !==
          myUsername
        ) {
          roster.set(
            user.username,
            user.publicKey
          );
        }
      }

      renderRoster();

      break;

    /* =====================
       MESSAGE
    ===================== */

    case "message": {
      const plaintext =
        await decryptFrom(
          msg.from,
          msg.nonce,
          msg.ciphertext,
          msg.ratchetPublicKey
        );

      if (
        plaintext === null
      ) {
        addSystemNote(
          msg.from,
          "Could not verify or decrypt this message."
        );

        return;
      }

      appendMessage(
        msg.from,
        {
          mine: false,
          text: plaintext,
          ts:
            msg.timestamp ||
            Date.now()
        }
      );

      if (
        activeChat ===
        msg.from
      ) {
        renderMessages(
          msg.from
        );
      }

      break;
    }

    /* =====================
       WEBRTC CALL OFFER
    ===================== */

    case "call_offer":
      await handleCallOffer(
        msg.from,
        msg.offer
      );

      break;

    /* =====================
       WEBRTC CALL ANSWER
    ===================== */

    case "call_answer":

      if (
        peerConnection &&
        msg.from === currentCallTarget &&
        msg.answer
      ) {
        try {
          await peerConnection.setRemoteDescription(
            new RTCSessionDescription(
              msg.answer
            )
          );

          console.log(
            "Remote answer description set."
          );

          await flushPendingIceCandidates();

          const callStatus =
            el("call-status");

          if (callStatus) {
            callStatus.textContent =
              "Connected";
          }

          const remoteAudio =
            el("remote-audio");

          if (remoteAudio) {
            try {
              await remoteAudio.play();
            } catch (error) {
              console.warn(
                "Remote audio playback blocked:",
                error
              );
            }
          }
        } catch (error) {
          console.error(
            "Error setting remote answer:",
            error
          );

          const callStatus =
            el("call-status");

          if (callStatus) {
            callStatus.textContent =
              "Connection failed";
          }
        }
      }

      break;

    /* =====================
       WEBRTC ICE CANDIDATE
    ===================== */

    case "ice_candidate":

      if (
        msg.from === currentCallTarget &&
        msg.candidate
      ) {
        await addRemoteIceCandidate(
          msg.candidate
        );
      }

      break;

    /* =====================
       CALL END
    ===================== */

    case "call_end":

      if (
        msg.from ===
        currentCallTarget
      ) {
        cleanUpCall();

        alert(
          `${msg.from} ended the call.`
        );
      }

      break;

    /* =====================
       CALL UNAVAILABLE
    ===================== */

    case "call_unavailable":

      cleanUpCall();

      alert(
        `User ${msg.to} is offline or unavailable.`
      );

      break;

    default:

      console.log(
        "Unknown server message:",
        msg
      );

      break;
  }
}

/* =========================
   WEBRTC MICROPHONE
========================= */

async function setupLocalAudio() {
  try {
    if (
      !navigator.mediaDevices ||
      !navigator.mediaDevices.getUserMedia
    ) {
      throw new Error(
        "getUserMedia is not supported by this browser."
      );
    }

    localStream =
      await navigator.mediaDevices.getUserMedia({
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true
        },
        video: false
      });

    console.log(
      "Microphone access granted."
    );

    return true;
  } catch (error) {
    console.error(
      "Microphone permission denied:",
      error
    );

    alert(
      "Microphone access is required to place or receive calls. Please allow microphone access for this website."
    );

    return false;
  }
}

/* =========================
   CREATE PEER CONNECTION
========================= */

function createPeerConnection(
  targetUser
) {
  console.log(
    "Creating PeerConnection for:",
    targetUser
  );

  console.log(
    "Using ICE configuration:",
    rtcConfig
  );

  peerConnection =
    new RTCPeerConnection(
      rtcConfig
    );

  /* =====================
     LOCAL AUDIO
  ===================== */

  if (localStream) {
    localStream
      .getTracks()
      .forEach((track) => {
        console.log(
          "Adding local audio track:",
          track.kind
        );

        peerConnection.addTrack(
          track,
          localStream
        );
      });
  }

  /* =====================
     REMOTE AUDIO
  ===================== */

  peerConnection.ontrack =
    async (event) => {
      console.log(
        "Remote audio track received."
      );

      const remoteAudio =
        el("remote-audio");

      if (
        !remoteAudio ||
        !event.streams ||
        !event.streams[0]
      ) {
        console.error(
          "Remote audio element or stream not found."
        );

        return;
      }

      remoteAudio.srcObject =
        event.streams[0];

      try {
        await remoteAudio.play();

        console.log(
          "Remote audio playback started."
        );
      } catch (error) {
        console.warn(
          "Remote audio autoplay was blocked:",
          error
        );
      }
    };

  /* =====================
     ICE CANDIDATES
  ===================== */

  peerConnection.onicecandidate =
    (event) => {
      if (!event.candidate) {
        console.log(
          "ICE gathering completed."
        );

        return;
      }

      console.log(
        "Sending ICE candidate:",
        event.candidate.candidate
      );

      if (
        !ws ||
        ws.readyState !==
          WebSocket.OPEN
      ) {
        console.error(
          "WebSocket is not available for ICE candidate."
        );

        return;
      }

      ws.send(
        JSON.stringify({
          type:
            "ice_candidate",

          to:
            targetUser,

          candidate:
            event.candidate
        })
      );
    };

  /* =====================
     ICE CONNECTION STATE
  ===================== */

  peerConnection
    .oniceconnectionstatechange =
    () => {
      if (!peerConnection) {
        return;
      }

      const state =
        peerConnection.iceConnectionState;

      console.log(
        "ICE connection state:",
        state
      );

      const status =
        el("call-status");

      if (!status) {
        return;
      }

      switch (state) {
        case "checking":
          status.textContent =
            "Connecting...";
          break;

        case "connected":
        case "completed":
          status.textContent =
            "Connected";
          break;

        case "disconnected":
          status.textContent =
            "Connection interrupted...";
          break;

        case "failed":
          status.textContent =
            "Connection failed.";
          break;

        case "closed":
          console.log(
            "ICE connection closed."
          );
          break;
      }
    };

  /* =====================
     PEER CONNECTION STATE
  ===================== */

  peerConnection
    .onconnectionstatechange =
    () => {
      if (!peerConnection) {
        return;
      }

      const state =
        peerConnection.connectionState;

      console.log(
        "Peer connection state:",
        state
      );

      const status =
        el("call-status");

      if (!status) {
        return;
      }

      switch (state) {
        case "connecting":
          status.textContent =
            "Connecting...";
          break;

        case "connected":
          status.textContent =
            "Connected";
          break;

        case "disconnected":
          status.textContent =
            "Connection interrupted...";
          break;

        case "failed":
          status.textContent =
            "Connection failed.";
          break;

        case "closed":
          console.log(
            "Peer connection closed."
          );
          break;
      }
    };
}

/* =========================
   ADD REMOTE ICE CANDIDATE
========================= */

async function addRemoteIceCandidate(
  candidate
) {
  if (!candidate) {
    return;
  }

  if (!peerConnection) {
    console.warn(
      "PeerConnection does not exist. Queueing ICE candidate."
    );

    pendingIceCandidates.push(
      candidate
    );

    return;
  }

  if (!peerConnection.remoteDescription) {
    console.log(
      "Remote description not ready. Queueing ICE candidate."
    );

    pendingIceCandidates.push(
      candidate
    );

    return;
  }

  try {
    await peerConnection.addIceCandidate(
      new RTCIceCandidate(candidate)
    );

    console.log(
      "ICE candidate added."
    );
  } catch (error) {
    console.error(
      "Error adding ICE candidate:",
      error
    );
  }
}

/* =========================
   FLUSH ICE QUEUE
========================= */

async function flushPendingIceCandidates() {
  if (!peerConnection) {
    return;
  }

  if (!peerConnection.remoteDescription) {
    return;
  }

  if (
    pendingIceCandidates.length === 0
  ) {
    return;
  }

  console.log(
    `Adding ${pendingIceCandidates.length} queued ICE candidates.`
  );

  const candidates =
    [...pendingIceCandidates];

  pendingIceCandidates = [];

  for (
    const candidate of candidates
  ) {
    try {
      await peerConnection.addIceCandidate(
        new RTCIceCandidate(candidate)
      );

      console.log(
        "Queued ICE candidate added."
      );
    } catch (error) {
      console.error(
        "Failed to add queued ICE candidate:",
        error
      );
    }
  }
}

/* =========================
   START AUDIO CALL
========================= */

async function startAudioCall() {
  if (!activeChat) {
    alert(
      "Select a user first."
    );

    return;
  }

  if (peerConnection) {
    alert(
      "You are already in a call."
    );

    return;
  }

  if (
    !ws ||
    ws.readyState !==
      WebSocket.OPEN
  ) {
    alert(
      "Not connected to the server."
    );

    return;
  }

  if (!roster.has(activeChat)) {
    alert(
      "This user is currently offline."
    );

    return;
  }

  const gotAudio =
    await setupLocalAudio();

  if (!gotAudio) {
    return;
  }

  currentCallTarget =
    activeChat;

  isCaller = true;

  pendingIceCandidates = [];

  showCallModal(
    "Calling...",
    currentCallTarget,
    false,
    false,
    true
  );

  try {
    createPeerConnection(
      currentCallTarget
    );

    const offer =
      await peerConnection.createOffer({
        offerToReceiveAudio: true
      });

    await peerConnection.setLocalDescription(
      offer
    );

    console.log(
      "Sending call offer to:",
      currentCallTarget
    );

    ws.send(
      JSON.stringify({
        type:
          "call_offer",

        to:
          currentCallTarget,

        offer:
          peerConnection.localDescription
      })
    );
  } catch (error) {
    console.error(
      "Could not start audio call:",
      error
    );

    alert(
      "Could not start the audio call."
    );

    cleanUpCall();
  }
}

/* =========================
   HANDLE INCOMING CALL
========================= */

async function handleCallOffer(
  fromUser,
  offer
) {
  console.log(
    "Incoming audio call from:",
    fromUser
  );

  if (
    peerConnection ||
    currentCallTarget
  ) {
    console.warn(
      "Already in another call. Rejecting incoming call."
    );

    if (
      ws &&
      ws.readyState ===
        WebSocket.OPEN
    ) {
      ws.send(
        JSON.stringify({
          type:
            "call_end",

          to:
            fromUser
        })
      );
    }

    return;
  }

  currentCallTarget =
    fromUser;

  isCaller = false;

  pendingIceCandidates = [];

  window.pendingCallOffer =
    offer;

  showCallModal(
    "Incoming Audio Call",
    fromUser,
    true,
    true,
    false
  );
}

/* =========================
   ACCEPT CALL
========================= */

async function acceptCall() {
  if (
    !currentCallTarget ||
    !window.pendingCallOffer
  ) {
    console.error(
      "No pending call to accept."
    );

    return;
  }

  const gotAudio =
    await setupLocalAudio();

  if (!gotAudio) {
    rejectCall();

    return;
  }

  showCallModal(
    "Connecting...",
    currentCallTarget,
    false,
    false,
    true
  );

  try {
    createPeerConnection(
      currentCallTarget
    );

    /* =====================
       SET REMOTE OFFER
    ===================== */

    await peerConnection.setRemoteDescription(
      new RTCSessionDescription(
        window.pendingCallOffer
      )
    );

    console.log(
      "Remote offer description set."
    );

    /* =====================
       FLUSH ICE
    ===================== */

    await flushPendingIceCandidates();

    /* =====================
       CREATE ANSWER
    ===================== */

    const answer =
      await peerConnection.createAnswer({
        offerToReceiveAudio: true
      });

    /* =====================
       SET LOCAL ANSWER
    ===================== */

    await peerConnection.setLocalDescription(
      answer
    );

    /* =====================
       SEND ANSWER
    ===================== */

    if (
      !ws ||
      ws.readyState !==
        WebSocket.OPEN
    ) {
      throw new Error(
        "WebSocket is not connected."
      );
    }

    ws.send(
      JSON.stringify({
        type:
          "call_answer",

        to:
          currentCallTarget,

        answer:
          peerConnection.localDescription
      })
    );

    console.log(
      "Call answer sent."
    );

    window.pendingCallOffer =
      null;

    /* =====================
       REMOTE AUDIO PLAY
    ===================== */

    const remoteAudio =
      el("remote-audio");

    if (remoteAudio) {
      try {
        await remoteAudio.play();
      } catch (error) {
        console.warn(
          "Remote audio playback blocked:",
          error
        );
      }
    }
  } catch (error) {
    console.error(
      "Could not accept audio call:",
      error
    );

    alert(
      "Could not establish the audio call."
    );

    cleanUpCall();
  }
}

/* =========================
   REJECT CALL
========================= */

function rejectCall() {
  console.log(
    "Rejecting call from:",
    currentCallTarget
  );

  if (
    ws &&
    ws.readyState ===
      WebSocket.OPEN &&
    currentCallTarget
  ) {
    ws.send(
      JSON.stringify({
        type:
          "call_end",

        to:
          currentCallTarget
      })
    );
  }

  cleanUpCall();
}

/* =========================
   END CALL
========================= */

function endCall() {
  console.log(
    "Ending call with:",
    currentCallTarget
  );

  if (
    ws &&
    ws.readyState ===
      WebSocket.OPEN &&
    currentCallTarget
  ) {
    ws.send(
      JSON.stringify({
        type:
          "call_end",

        to:
          currentCallTarget
      })
    );
  }

  cleanUpCall();
}

/* =========================
   CLEANUP CALL
========================= */

function cleanUpCall() {
  console.log(
    "Cleaning up call."
  );

  /* =====================
     PEER CONNECTION
  ===================== */

  if (peerConnection) {
    try {
      peerConnection.ontrack = null;
      peerConnection.onicecandidate = null;
      peerConnection.oniceconnectionstatechange = null;
      peerConnection.onconnectionstatechange = null;

      peerConnection.close();
    } catch (error) {
      console.error(
        "PeerConnection cleanup error:",
        error
      );
    }

    peerConnection = null;
  }

  /* =====================
     MICROPHONE
  ===================== */

  if (localStream) {
    localStream
      .getTracks()
      .forEach((track) => {
        try {
          track.stop();
        } catch {}
      });

    localStream = null;
  }

  /* =====================
     REMOTE AUDIO
  ===================== */

  const remoteAudio =
    el("remote-audio");

  if (remoteAudio) {
    try {
      remoteAudio.pause();
    } catch {}

    remoteAudio.srcObject = null;
  }

  /* =====================
     CLEAR CALL STATE
  ===================== */

  pendingIceCandidates = [];

  currentCallTarget = null;

  isCaller = false;

  window.pendingCallOffer =
    null;

  hideCallModal();
}

/* =========================
   CALL MODAL
========================= */

function showCallModal(
  statusText,
  userName,
  showAccept,
  showReject,
  showEnd
) {
  const modal =
    el("call-modal");

  if (!modal) {
    return;
  }

  const status =
    el("call-status");

  const user =
    el("call-user-name");

  const acceptBtn =
    el("accept-call-btn");

  const rejectBtn =
    el("reject-call-btn");

  const endBtn =
    el("end-call-btn");

  if (status) {
    status.textContent =
      statusText;
  }

  if (user) {
    user.textContent =
      userName;
  }

  if (acceptBtn) {
    acceptBtn.style.display =
      showAccept
        ? "inline-block"
        : "none";
  }

  if (rejectBtn) {
    rejectBtn.style.display =
      showReject
        ? "inline-block"
        : "none";
  }

  if (endBtn) {
    endBtn.style.display =
      showEnd
        ? "inline-block"
        : "none";
  }

  modal.style.display =
    "flex";
}

function hideCallModal() {
  const modal =
    el("call-modal");

  if (modal) {
    modal.style.display =
      "none";
  }
}

/* =========================
   ROSTER
========================= */

function renderRoster() {
  const count =
    el("roster-count");

  const list =
    el("roster");

  if (!count || !list) {
    return;
  }

  count.textContent =
    roster.size;

  list.innerHTML = "";

  for (
    const [username]
    of roster
  ) {
    const li =
      document.createElement(
        "li"
      );

    li.className =
      username === activeChat
        ? "active"
        : "";

    const name =
      document.createElement(
        "span"
      );

    name.className =
      "name";

    const dot =
      document.createElement(
        "span"
      );

    dot.className =
      "dot";

    name.appendChild(
      dot
    );

    const text =
      document.createTextNode(
        username
      );

    name.appendChild(
      text
    );

    li.appendChild(
      name
    );

    li.addEventListener(
      "click",
      () => {
        selectChat(
          username
        );
      }
    );

    list.appendChild(
      li
    );
  }
}

/* =========================
   SELECT CHAT
========================= */

function selectChat(
  username
) {
  const publicKey =
    roster.get(username);

  if (!publicKey) {
    return;
  }

  activeChat =
    username;

  const chatWith =
    el("chat-with");

  if (chatWith) {
    chatWith.textContent =
      username;
  }

  renderFingerprint(
    publicKey,
    el("chat-with-fp"),
    5
  );

  const messageInput =
    el("message-input");

  const sendBtn =
    el("send-btn");

  if (messageInput) {
    messageInput.disabled =
      false;
  }

  if (sendBtn) {
    sendBtn.disabled =
      false;
  }

  const callBtn =
    el("call-btn");

  if (callBtn) {
    callBtn.style.display =
      "inline-block";
  }

  renderRoster();

  renderMessages(
    username
  );

  if (messageInput) {
    messageInput.focus();
  }
}

/* =========================
   RENDER MESSAGES
========================= */

function renderMessages(
  username
) {
  const box =
    el("messages");

  if (!box) {
    return;
  }

  box.innerHTML = "";

  const log =
    messageLog.get(
      username
    ) || [];

  for (
    const item of log
  ) {
    if (item.system) {
      const div =
        document.createElement(
          "div"
        );

      div.className =
        "system-note";

      div.textContent =
        item.text;

      box.appendChild(
        div
      );

      continue;
    }

    const div =
      document.createElement(
        "div"
      );

    div.className =
      `msg ${
        item.mine
          ? "mine"
          : "theirs"
      }`;

    const text =
      document.createTextNode(
        item.text
      );

    div.appendChild(
      text
    );

    const meta =
      document.createElement(
        "span"
      );

    meta.className =
      "meta";

    meta.textContent =
      new Date(
        item.ts
      ).toLocaleTimeString();

    div.appendChild(
      meta
    );

    box.appendChild(
      div
    );
  }

  box.scrollTop =
    box.scrollHeight;
}

/* =========================
   APPEND MESSAGE
========================= */

function appendMessage(
  username,
  item
) {
  if (
    !messageLog.has(
      username
    )
  ) {
    messageLog.set(
      username,
      []
    );
  }

  const log =
    messageLog.get(
      username
    );

  log.push(item);

  if (
    log.length >
    MAX_MESSAGES_PER_CHAT
  ) {
    log.shift();
  }
}

/* =========================
   SYSTEM NOTE
========================= */

function addSystemNote(
  username,
  text
) {
  if (!username) {
    return;
  }

  appendMessage(
    username,
    {
      system: true,
      text
    }
  );

  if (
    activeChat ===
    username
  ) {
    renderMessages(
      username
    );
  }
}

/* =========================
   SEND MESSAGE
========================= */

async function sendMessage() {
  if (!activeChat) {
    return;
  }

  if (
    !ws ||
    ws.readyState !==
      WebSocket.OPEN
  ) {
    alert(
      "Not connected to the server."
    );

    return;
  }

  const input =
    el("message-input");

  if (!input) {
    return;
  }

  const text =
    input.value.trim();

  if (!text) {
    return;
  }

  const recipientPublicKey =
    roster.get(
      activeChat
    );

  if (!recipientPublicKey) {
    alert(
      "Recipient key is not available."
    );

    return;
  }

  try {
    const {
      messageKey,
      ratchetPublicKeyB64
    } =
      await getSendingMessageKey(
        activeChat,
        recipientPublicKey
      );

    const nonce =
      sodium.randombytes_buf(
        sodium.crypto_secretbox_NONCEBYTES
      );

    const ciphertext =
      sodium.crypto_secretbox_easy(
        text,
        nonce,
        messageKey
      );

    ws.send(
      JSON.stringify({
        type:
          "message",

        to:
          activeChat,

        nonce:
          sodium.to_base64(
            nonce
          ),

        ciphertext:
          sodium.to_base64(
            ciphertext
          ),

        ratchetPublicKey:
          ratchetPublicKeyB64
      })
    );

    appendMessage(
      activeChat,
      {
        mine: true,
        text,
        ts: Date.now()
      }
    );

    renderMessages(
      activeChat
    );

    input.value = "";

    input.focus();
  } catch (error) {
    console.error(
      "Encryption/send error:",
      error
    );

    alert(
      "Could not encrypt/send the message."
    );
  }
}

/* =========================
   DECRYPT MESSAGE
========================= */

async function decryptFrom(
  fromUsername,
  nonceB64,
  ciphertextB64,
  ratchetPublicKeyB64
) {
  const senderPublicKeyB64 =
    roster.get(
      fromUsername
    );

  if (!senderPublicKeyB64) {
    return null;
  }

  try {
    const messageKey =
      await getReceivingMessageKey(
        fromUsername,
        senderPublicKeyB64,
        ratchetPublicKeyB64
      );

    if (!messageKey) {
      return null;
    }

    const opened =
      sodium.crypto_secretbox_open_easy(
        sodium.from_base64(
          ciphertextB64
        ),

        sodium.from_base64(
          nonceB64
        ),

        messageKey
      );

    return sodium.to_string(
      opened
    );
  } catch (error) {
    console.error(
      "Decrypt error:",
      error
    );

    return null;
  }
}

/* =========================
   EVENTS
========================= */

document.addEventListener(
  "DOMContentLoaded",
  async () => {
    try {
      await sodiumReady();

      console.log(
        "libsodium ready."
      );

      const loginForm =
        el("login-form");

      const registerBtn =
        el("register-btn");

      const messageForm =
        el("message-form");

      const callBtn =
        el("call-btn");

      const acceptCallBtn =
        el("accept-call-btn");

      const rejectCallBtn =
        el("reject-call-btn");

      const endCallBtn =
        el("end-call-btn");

      /* ===================
         LOGIN
      =================== */

      if (loginForm) {
        loginForm.addEventListener(
          "submit",
          async (event) => {
            event.preventDefault();

            await login();
          }
        );
      }

      /* ===================
         REGISTER
      =================== */

      if (registerBtn) {
        registerBtn.addEventListener(
          "click",
          async () => {
            await register();
          }
        );
      }

      /* ===================
         MESSAGES
      =================== */

      if (messageForm) {
        messageForm.addEventListener(
          "submit",
          async (event) => {
            event.preventDefault();

            await sendMessage();
          }
        );
      }

      /* ===================
         START CALL
      =================== */

      if (callBtn) {
        callBtn.addEventListener(
          "click",
          async () => {
            await startAudioCall();
          }
        );
      }

      /* ===================
         ACCEPT CALL
      =================== */

      if (acceptCallBtn) {
        acceptCallBtn.addEventListener(
          "click",
          async () => {
            await acceptCall();
          }
        );
      }

      /* ===================
         REJECT CALL
      =================== */

      if (rejectCallBtn) {
        rejectCallBtn.addEventListener(
          "click",
          rejectCall
        );
      }

      /* ===================
         END CALL
      =================== */

      if (endCallBtn) {
        endCallBtn.addEventListener(
          "click",
          endCall
        );
      }

      /* ===================
         SAVED AUTH
      =================== */

      const savedAuth =
        loadAuth();

      if (
        savedAuth &&
        savedAuth.username
      ) {
        const usernameInput =
          el("username");

        if (usernameInput) {
          usernameInput.value =
            savedAuth.username;
        }

        const passwordInput =
          el("password");

        if (passwordInput) {
          passwordInput.focus();
        }
      }
    } catch (error) {
      console.error(
        "Application startup error:",
        error
      );

      showAuthError(
        "Could not start encryption system. Check that libsodium loaded correctly."
      );
    }
  }
);
