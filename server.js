const express = require("express");
const http = require("http");
const path = require("path");
const crypto = require("crypto");
const argon2 = require("argon2");
const { Pool } = require("pg");
const { WebSocketServer } = require("ws");

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  console.error("ERROR: DATABASE_URL is not configured.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

app.use(express.json({ limit: "50kb" }));

app.use(express.static(path.join(__dirname, "public")));

/* =========================
   DATABASE
========================= */

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(32) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      public_key TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash CHAR(64) PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS sessions_user_id_idx
    ON sessions(user_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS sessions_expires_at_idx
    ON sessions(expires_at)
  `);

  /*
   * message_queue holds ONLY opaque ciphertext for
   * recipients who are offline. The server never
   * stores plaintext and never sees the private keys
   * needed to decrypt these rows.
   */
  await pool.query(`
    CREATE TABLE IF NOT EXISTS message_queue (
      id BIGSERIAL PRIMARY KEY,
      recipient_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      sender_username VARCHAR(32) NOT NULL,
      nonce TEXT NOT NULL,
      ciphertext TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS message_queue_recipient_idx
    ON message_queue(recipient_id, created_at)
  `);

  console.log("Database initialized.");
}

/* =========================
   HELPERS
========================= */

function normalizeUsername(username) {
  return String(username || "").trim().toLowerCase();
}

function validUsername(username) {
  return /^[a-zA-Z0-9_]{3,32}$/.test(username);
}

function validPassword(password) {
  return typeof password === "string" && password.length >= 8;
}

function createSessionToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function hashSessionToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function getBearerToken(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.slice(7).trim();
}

async function getUserFromToken(token) {
  if (!token) return null;

  const tokenHash = hashSessionToken(token);

  const result = await pool.query(
    `
      SELECT
        u.id,
        u.username,
        u.public_key
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = $1
      AND s.expires_at > NOW()
    `,
    [tokenHash]
  );

  return result.rows[0] || null;
}

/* =========================
   HEALTH
========================= */

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: true
    });
  } catch (error) {
    console.error("Health error:", error);

    res.status(500).json({
      ok: false,
      database: false
    });
  }
});

/* =========================
   REGISTER
========================= */

app.post("/api/register", async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username);
    const password = req.body.password;
    const publicKey = req.body.publicKey || null;

    if (!validUsername(username)) {
      return res.status(400).json({
        error:
          "Username must be 3-32 characters and contain only letters, numbers or underscore."
      });
    }

    if (!validPassword(password)) {
      return res.status(400).json({
        error: "Password must contain at least 8 characters."
      });
    }

    const passwordHash = await argon2.hash(password);

    const result = await pool.query(
      `
        INSERT INTO users
          (username, password_hash, public_key)
        VALUES
          ($1, $2, $3)
        RETURNING id, username, public_key
      `,
      [username, passwordHash, publicKey]
    );

    const user = result.rows[0];

    const token = createSessionToken();
    const tokenHash = hashSessionToken(token);

    await pool.query(
      `
        INSERT INTO sessions
          (token_hash, user_id, expires_at)
        VALUES
          ($1, $2, NOW() + INTERVAL '30 days')
      `,
      [tokenHash, user.id]
    );

    res.status(201).json({
      ok: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        publicKey: user.public_key
      }
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "Username already exists."
      });
    }

    console.error("Register error:", error);

    res.status(500).json({
      error: "Registration failed."
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username);
    const password = req.body.password;

    if (!username || !password) {
      return res.status(400).json({
        error: "Username and password are required."
      });
    }

    const result = await pool.query(
      `
        SELECT
          id,
          username,
          password_hash,
          public_key
        FROM users
        WHERE username = $1
      `,
      [username]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({
        error: "Invalid username or password."
      });
    }

    let valid = false;

    try {
      valid = await argon2.verify(
        user.password_hash,
        password
      );
    } catch (error) {
      console.error("Argon2 verification error:", error);
    }

    if (!valid) {
      return res.status(401).json({
        error: "Invalid username or password."
      });
    }

    const token = createSessionToken();
    const tokenHash = hashSessionToken(token);

    await pool.query(
      `
        INSERT INTO sessions
          (token_hash, user_id, expires_at)
        VALUES
          ($1, $2, NOW() + INTERVAL '30 days')
      `,
      [tokenHash, user.id]
    );

    res.json({
      ok: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        publicKey: user.public_key
      }
    });
  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      error: "Login failed."
    });
  }
});

/* =========================
   LOGOUT
========================= */

app.post("/api/logout", async (req, res) => {
  try {
    const token = getBearerToken(req);

    if (token) {
      await pool.query(
        `
          DELETE FROM sessions
          WHERE token_hash = $1
        `,
        [hashSessionToken(token)]
      );
    }

    res.json({ ok: true });
  } catch (error) {
    console.error("Logout error:", error);

    res.status(500).json({
      error: "Logout failed."
    });
  }
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/me", async (req, res) => {
  try {
    const token = getBearerToken(req);
    const user = await getUserFromToken(token);

    if (!user) {
      return res.status(401).json({
        error: "Not authenticated."
      });
    }

    res.json({
      ok: true,
      user: {
        id: user.id,
        username: user.username,
        publicKey: user.public_key
      }
    });
  } catch (error) {
    console.error("Me error:", error);

    res.status(500).json({
      error: "Could not get user."
    });
  }
});

/* =========================
   UPDATE PUBLIC KEY
========================= */

app.put("/api/me/public-key", async (req, res) => {
  try {
    const token = getBearerToken(req);
    const user = await getUserFromToken(token);

    if (!user) {
      return res.status(401).json({
        error: "Not authenticated."
      });
    }

    const publicKey = req.body.publicKey;

    if (
      typeof publicKey !== "string" ||
      publicKey.length < 20 ||
      publicKey.length > 500
    ) {
      return res.status(400).json({
        error: "Invalid public key."
      });
    }

    await pool.query(
      `
        UPDATE users
        SET public_key = $1
        WHERE id = $2
      `,
      [publicKey, user.id]
    );

    const client = clients.get(user.username);

    if (client) {
      client.publicKey = publicKey;
    }

    broadcastUserList();

    res.json({ ok: true });
  } catch (error) {
    console.error("Public key update error:", error);

    res.status(500).json({
      error: "Could not update public key."
    });
  }
});

/* =========================
   WEBSOCKET CLIENTS
========================= */

const clients = new Map();

function send(ws, message) {
  if (ws && ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify(message));
  }
}

function broadcastUserList() {
  const users = [...clients.entries()].map(
    ([username, client]) => ({
      username,
      publicKey: client.publicKey
    })
  );

  for (const client of clients.values()) {
    send(client.ws, {
      type: "user_list",
      users
    });
  }
}

/* =========================
   WEBSOCKET
========================= */

wss.on("connection", (ws) => {
  let currentUser = null;
  let currentUserId = null;

  ws.on("message", async (raw) => {
    let msg;

    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return;
    }

    /* ---------- AUTH ---------- */

    if (msg.type === "authenticate") {
      if (currentUser) {
        send(ws, {
          type: "error",
          message: "Already authenticated."
        });

        return;
      }

      try {
        const user = await getUserFromToken(msg.token);

        if (!user) {
          send(ws, {
            type: "auth_error",
            message: "Invalid or expired session."
          });

          ws.close();
          return;
        }

        currentUser = user.username;
        currentUserId = user.id;

        const existing = clients.get(currentUser);

        if (existing && existing.ws !== ws) {
          try {
            existing.ws.close();
          } catch {}
        }

        clients.set(currentUser, {
          ws,
          publicKey: user.public_key,
          userId: user.id
        });

        send(ws, {
          type: "authenticated",
          username: currentUser,
          publicKey: user.public_key
        });

        broadcastUserList();

        const queued = await pool.query(
          `
            SELECT id, sender_username, nonce, ciphertext, created_at
            FROM message_queue
            WHERE recipient_id = $1
            ORDER BY created_at ASC
          `,
          [currentUserId]
        );

        if (queued.rows.length) {
          for (const row of queued.rows) {
            send(ws, {
              type: "message",
              from: row.sender_username,
              nonce: row.nonce,
              ciphertext: row.ciphertext,
              timestamp: new Date(row.created_at).getTime()
            });
          }

          await pool.query(
            `
              DELETE FROM message_queue
              WHERE recipient_id = $1
            `,
            [currentUserId]
          );
        }
      } catch (error) {
        console.error("WebSocket auth error:", error);

        send(ws, {
          type: "auth_error",
          message: "Authentication failed."
        });

        ws.close();
      }

      return;
    }

    /* ---------- REQUIRE AUTH ---------- */

    if (!currentUser) {
      send(ws, {
        type: "auth_error",
        message: "Authenticate first."
      });

      return;
    }

    /* ---------- PUBLIC KEY ---------- */

    if (msg.type === "update_public_key") {
      if (!msg.publicKey) return;

      await pool.query(
        `
          UPDATE users
          SET public_key = $1
          WHERE id = $2
        `,
        [msg.publicKey, currentUserId]
      );

      const client = clients.get(currentUser);

      if (client) {
        client.publicKey = msg.publicKey;
      }

      broadcastUserList();

      return;
    }

    /* ---------- MESSAGE ---------- */

    if (msg.type === "message") {
      if (
        !msg.to ||
        !msg.nonce ||
        !msg.ciphertext
      ) {
        return;
      }

      /*
       * IMPORTANT:
       * "from" is never accepted from the browser.
       * It comes from the authenticated session.
       */

      const envelope = {
        type: "message",
        from: currentUser,
        nonce: msg.nonce,
        ciphertext: msg.ciphertext,
        timestamp: Date.now()
      };

      const recipient = clients.get(msg.to);

      if (recipient) {
        send(recipient.ws, envelope);
        return;
      }

      /*
       * Recipient is offline: persist the opaque
       * {nonce, ciphertext} pair so it survives a
       * server restart. We look up their id by
       * username since we only keep ids for
       * connected clients in memory.
       */
      try {
        const recipientRow = await pool.query(
          `SELECT id FROM users WHERE username = $1`,
          [msg.to]
        );

        const recipientId = recipientRow.rows[0]?.id;

        if (!recipientId) return;

        await pool.query(
          `
            INSERT INTO message_queue
              (recipient_id, sender_username, nonce, ciphertext)
            VALUES
              ($1, $2, $3, $4)
          `,
          [recipientId, currentUser, msg.nonce, msg.ciphertext]
        );
      } catch (error) {
        console.error("Queueing offline message failed:", error);
      }
    }
  });

  ws.on("close", () => {
    if (!currentUser) return;

    const client = clients.get(currentUser);

    if (client && client.ws === ws) {
      clients.delete(currentUser);
      broadcastUserList();
    }
  });

  ws.on("error", (error) => {
    console.error("WebSocket error:", error.message);
  });
});

/* =========================
   SESSION CLEANUP
========================= */

setInterval(async () => {
  try {
    await pool.query(`
      DELETE FROM sessions
      WHERE expires_at <= NOW()
    `);
  } catch (error) {
    console.error(
      "Session cleanup error:",
      error.message
    );
  }
}, 60 * 60 * 1000);

/*
 * Drop queued messages nobody has picked up after 30
 * days. This is a storage/hygiene bound, not a security
 * feature — it doesn't add forward secrecy on its own.
 */
setInterval(async () => {
  try {
    await pool.query(`
      DELETE FROM message_queue
      WHERE created_at <= NOW() - INTERVAL '30 days'
    `);
  } catch (error) {
    console.error(
      "Message queue cleanup error:",
      error.message
    );
  }
}, 60 * 60 * 1000);

/* =========================
   START SERVER
========================= */

async function start() {
  try {
    await initDatabase();

    server.listen(PORT, () => {
      console.log(
        `Encrypted chat relay listening on http://localhost:${PORT}`
      );
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

start();

/* =========================
   SHUTDOWN
========================= */

async function shutdown(signal) {
  console.log(`${signal} received. Shutting down...`);

  try {
    await pool.end();
  } catch (error) {
    console.error("Database shutdown error:", error);
  }

  server.close(() => {
    process.exit(0);
  });
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
