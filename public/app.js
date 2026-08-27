let sodium = null;
let myKeyPair = null;
let myUsername = null;
let authToken = null;
let ws = null;
let activeChat = null;

const roster = new Map();
const messageLog = new Map();

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

function saveIdentity() {
  if (!myKeyPair || !myUsername) return;

  localStorage.setItem(
    "sealed_identity",
    JSON.stringify({
      username: myUsername,
      publicKey: sodium.to_base64(myKeyPair.publicKey),
      privateKey: sodium.to_base64(myKeyPair.privateKey),
    })
  );
}

function loadIdentity() {
  try {
    const raw = localStorage.getItem("sealed_identity");

    if (!raw) return null;

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

function renderFingerprint(
  publicKeyBase64,
  container,
  blockCount = 6
) {
  if (!container || !publicKeyBase64) return;

  container.innerHTML = "";

  try {
    const hash = sodium.crypto_generichash(
      16,
      sodium.from_base64(publicKeyBase64)
    );

    for (let i = 0; i < blockCount; i++) {
      const hue =
        hash[i * 2] * (360 / 255);

      const light =
        45 + (hash[i * 2 + 1] % 20);

      const block = document.createElement("span");

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
  return new Promise((resolve, reject) => {
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

      setTimeout(check, 50);
    };

    check();
  });
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
    "Content-Type":
      "application/json",
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
          : undefined,
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

    saveIdentity();
  }
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
          publicKey,
        }
      );

    authToken = result.token;
    myUsername =
      result.user.username;

    saveAuth();
    saveIdentity();

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
          password,
        }
      );

    authToken = result.token;
    myUsername =
      result.user.username;

    const stored =
      loadIdentity();

    if (
      stored &&
      stored.username === myUsername
    ) {
      myKeyPair = stored;
    } else {
      ensureKeyPair();
    }

    saveAuth();
    saveIdentity();

    /*
     * Keep the server's current
     * public key synchronized with
     * the browser's key.
     */
    await apiRequest(
      "/api/me/public-key",
      "PUT",
      {
        publicKey:
          sodium.to_base64(
            myKeyPair.publicKey
          ),
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
      ws.readyState === WebSocket.OPEN ||
      ws.readyState === WebSocket.CONNECTING
    )
  ) {
    return;
  }

  const protocol =
    location.protocol === "https:"
      ? "wss:"
      : "ws:";

  ws = new WebSocket(
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
          token: authToken,
        })
      );
    }
  );

  ws.addEventListener(
    "message",
    (event) => {
      try {
        const msg =
          JSON.parse(event.data);

        handleServerMessage(msg);
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

      if (
        el("chat-screen").hidden ===
        false
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

function handleServerMessage(msg) {
  switch (msg.type) {
    case "authenticated":
      myUsername =
        msg.username;

      saveAuth();
      saveIdentity();

      setLoading(false);
      showChatScreen();

      break;

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

    case "error":
      setLoading(false);

      showAuthError(
        msg.message ||
          "An error occurred."
      );

      break;

    case "user_list":
      roster.clear();

      for (const user of msg.users || []) {
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

    case "message": {
      const plaintext =
        decryptFrom(
          msg.from,
          msg.nonce,
          msg.ciphertext
        );

      if (plaintext === null) {
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
            Date.now(),
        }
      );

      if (
        activeChat === msg.from
      ) {
        renderMessages(
          msg.from
        );
      }

      break;
    }

    default:
      console.log(
        "Unknown server message:",
        msg
      );

      break;
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

  count.textContent =
    roster.size;

  list.innerHTML = "";

  for (
    const [username] of roster
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

    name.className = "name";

    const dot =
      document.createElement(
        "span"
      );

    dot.className = "dot";

    name.appendChild(dot);

    const text =
      document.createTextNode(
        username
      );

    name.appendChild(text);

    li.appendChild(name);

    li.addEventListener(
      "click",
      () => {
        selectChat(username);
      }
    );

    list.appendChild(li);
  }
}

/* =========================
   CHAT
========================= */

function selectChat(username) {
  const publicKey =
    roster.get(username);

  if (!publicKey) return;

  activeChat = username;

  el("chat-with")
    .textContent =
    username;

  renderFingerprint(
    publicKey,
    el("chat-with-fp"),
    5
  );

  el("message-input")
    .disabled = false;

  el("send-btn")
    .disabled = false;

  renderRoster();

  renderMessages(username);

  el("message-input").focus();
}

function renderMessages(username) {
  const box =
    el("messages");

  box.innerHTML = "";

  const log =
    messageLog.get(username) ||
    [];

  for (const item of log) {
    if (item.system) {
      const div =
        document.createElement(
          "div"
        );

      div.className =
        "system-note";

      div.textContent =
        item.text;

      box.appendChild(div);

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

    div.appendChild(text);

    const meta =
      document.createElement(
        "span"
      );

    meta.className = "meta";

    meta.textContent =
      new Date(
        item.ts
      ).toLocaleTimeString();

    div.appendChild(meta);

    box.appendChild(div);
  }

  box.scrollTop =
    box.scrollHeight;
}

function appendMessage(
  username,
  item
) {
  if (
    !messageLog.has(username)
  ) {
    messageLog.set(
      username,
      []
    );
  }

  messageLog
    .get(username)
    .push(item);
}

function addSystemNote(
  username,
  text
) {
  if (!username) return;

  appendMessage(
    username,
    {
      system: true,
      text,
    }
  );

  if (
    activeChat === username
  ) {
    renderMessages(username);
  }
}

/* =========================
   SEND MESSAGE
========================= */

function sendMessage() {
  if (!activeChat) return;

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

  const text =
    input.value.trim();

  if (!text) return;

  const recipientPublicKey =
    roster.get(activeChat);

  if (!recipientPublicKey) {
    alert(
      "Recipient key is not available."
    );

    return;
  }

  try {
    const nonce =
      sodium.randombytes_buf(
        sodium.crypto_box_NONCEBYTES
      );

    const ciphertext =
      sodium.crypto_box_easy(
        text,
        nonce,
        sodium.from_base64(
          recipientPublicKey
        ),
        myKeyPair.privateKey
      );

    ws.send(
      JSON.stringify({
        type: "message",
        to: activeChat,
        nonce:
          sodium.to_base64(
            nonce
          ),
        ciphertext:
          sodium.to_base64(
            ciphertext
          ),
      })
    );

    appendMessage(
      activeChat,
      {
        mine: true,
        text,
        ts: Date.now(),
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
   DECRYPT
========================= */

function decryptFrom(
  fromUsername,
  nonceB64,
  ciphertextB64
) {
  const senderPublicKeyB64 =
    roster.get(fromUsername);

  if (!senderPublicKeyB64) {
    return null;
  }

  try {
    const opened =
      sodium.crypto_box_open_easy(
        sodium.from_base64(
          ciphertextB64
        ),
        sodium.from_base64(
          nonceB64
        ),
        sodium.from_base64(
          senderPublicKeyB64
        ),
        myKeyPair.privateKey
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

      if (loginForm) {
        loginForm.addEventListener(
          "submit",
          async (event) => {
            event.preventDefault();

            await login();
          }
        );
      }

      if (registerBtn) {
        registerBtn.addEventListener(
          "click",
          async () => {
            await register();
          }
        );
      }

      if (messageForm) {
        messageForm.addEventListener(
          "submit",
          (event) => {
            event.preventDefault();

            sendMessage();
          }
        );
      }

      /*
       * Restore previous session.
       */
      const savedAuth =
        loadAuth();

      const savedIdentity =
        loadIdentity();

      if (
        savedAuth &&
        savedAuth.token &&
        savedAuth.username
      ) {
        authToken =
          savedAuth.token;

        myUsername =
          savedAuth.username;

        if (
          savedIdentity &&
          savedIdentity.username ===
            myUsername
        ) {
          myKeyPair =
            savedIdentity;
        } else {
          ensureKeyPair();
        }

        connectWebSocket();
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

