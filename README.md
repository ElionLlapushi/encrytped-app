# sealed — a minimal end-to-end encrypted chat app

A working demo of E2EE chat: the server relays messages it cannot read.

## How the encryption works

- Each browser generates an **X25519 keypair** locally on first use (via
  [libsodium](https://libsodium.gitbook.io/doc/)), using `crypto_box_keypair()`.
  The **private key never leaves the browser** — it's stored in
  `localStorage` and never sent over the network.
- Public keys are shared openly through the server (that's what makes them
  "public").
- To send a message, the client calls
  `crypto_box_easy(plaintext, nonce, recipientPublicKey, myPrivateKey)` —
  this is the NaCl "box" construction: X25519 key exchange + XSalsa20-Poly1305
  authenticated encryption. It gives you:
  - **Confidentiality** — only the recipient's private key can open it.
  - **Authenticity** — the recipient can be sure it was sent by the holder of
    the claimed sender's private key (forged senders fail decryption).
- The server (`server.js`) only ever touches usernames, public keys, and
  opaque `{nonce, ciphertext}` blobs. Grep the file — there's no decryption
  code there because it doesn't have the keys to do it.

## Fingerprints (verify before you trust)

Each user's sidebar shows a strip of colored blocks derived from a hash of
their public key. **This matters**: without verifying it, a malicious or
compromised server could hand you the wrong public key and quietly
man-in-the-middle your "encrypted" chat. Compare fingerprints with your
contact over a different channel (phone call, in person) the first time you
talk — same idea as Signal's "safety numbers."

## Running it

```bash
npm install
npm start
```

Then open `http://localhost:3000` in two different browser profiles (or one
normal + one incognito window) to chat with yourself under two handles.

## What this demo does *not* give you yet

Be upfront with your users about these gaps if you ship this:

1. **No forward secrecy.** Every message to a given contact is encrypted
   with the same long-term keypair. If a private key is ever stolen, an
   attacker who recorded past ciphertext can decrypt all of it. Signal's
   Double Ratchet fixes this by rotating keys per-message.
   → To upgrade: look at `libsignal-protocol-javascript` or the newer
   `@signalapp/libsignal-client` bindings, which implement X3DH + Double
   Ratchet.
2. **No real authentication.** Anyone can register any free username — there's
   no password, no account recovery, no protection against someone else
   registering your handle first. Add real auth (e.g. WebAuthn or a
   password + server-side session) in front of the WebSocket registration.
3. **No persistence.** Messages to offline users are queued in memory only
   and lost on server restart. For production, store the *ciphertext* queue
   in a real database (Postgres/Redis) — never store plaintext.
4. **No transport encryption in this demo config.** Run this behind TLS
   (`wss://`, e.g. via a reverse proxy like Caddy or nginx with Let's
   Encrypt) in any real deployment. E2EE protects message content even over
   plain WebSocket, but TLS still matters for metadata and to stop
   downgrade/injection attacks on the connection itself.
5. **No group chat.** This is 1:1 only. Group E2EE (encrypting once per
   recipient, or a shared group key with member management) is meaningfully
   more complex — ask if you want to go there next.
6. **Key backup/multi-device.** Right now a key lives in one browser's
   `localStorage`. Losing that browser's storage means losing the ability to
   read old messages and losing your identity. Real apps solve this with
   encrypted key backup or per-device keys + a linking flow.

## File layout

```
encrypted-chat/
├── server.js           # WebSocket relay — never decrypts anything
├── package.json
└── public/
    ├── index.html
    ├── style.css
    └── app.js           # all crypto happens here, client-side
```
