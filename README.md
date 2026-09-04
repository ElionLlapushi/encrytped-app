# 🔐 Sealed

### Private. Encrypted. Yours.

Sealed is a privacy-focused real-time communication platform designed to provide secure messaging and encrypted audio communication.

The project is built around a simple principle:

> Your private conversations should remain private.

Messages are encrypted on the user's device before transmission, while the server is designed to act primarily as a transport and synchronization layer rather than a place where plaintext conversations are stored.

---

## ✨ Features

### 💬 End-to-End Encrypted Messaging

Sealed is designed around client-side encryption.

Messages are encrypted before leaving the sender's device and decrypted only by the intended recipient.

The server should never need access to plaintext message contents.

### 🔐 Secure Identity

Each device is intended to have its own cryptographic identity.

The long-term architecture includes:

- Device identity keys
- Signed pre-keys
- One-time pre-keys
- Session establishment
- Forward secrecy
- Post-compromise recovery
- Message key rotation
- Replay protection
- Identity verification

### 📞 Encrypted Audio Calls

Sealed supports real-time audio communication using WebRTC.

The connection can use:

- STUN
- TURN
- UDP
- TCP
- TLS/TURN over port 443

TURN infrastructure is provided through Metered when a direct peer-to-peer connection is not possible.

### 🌐 Real-Time Communication

The application uses WebSockets for:

- Online presence
- Real-time messages
- Call signaling
- Connection events
- Delivery synchronization

### 📦 Offline Message Delivery

Messages can be queued when the recipient is temporarily offline.

The production architecture is designed to use acknowledgment-based delivery rather than deleting messages immediately after sending them.

### 🛡️ Account Protection

The backend includes:

- Password hashing with Argon2
- Authentication sessions
- Rate limiting
- Input validation
- PostgreSQL persistence
- Authentication middleware
- Session expiration
- Secure WebSocket authentication

---

# 🏗️ Architecture

Sealed is built using a client/server architecture.

```text
                   ┌─────────────────────┐
                   │       Sealed        │
                   │      Client A       │
                   └──────────┬──────────┘
                              │
                         Encrypt locally
                              │
                              ▼
                    ┌──────────────────┐
                    │      Server      │
                    │                  │
                    │ Authentication   │
                    │ WebSocket        │
                    │ Message routing  │
                    │ PostgreSQL       │
                    │ TURN credentials │
                    └────────┬─────────┘
                             │
                             │ Encrypted data
                             ▼
                   ┌─────────────────────┐
                   │       Sealed        │
                   │      Client B       │
                   └──────────┬──────────┘
                              │
                         Decrypt locally
The server should not be considered the trusted location for message plaintext.

⸻

🔒 Cryptographic Architecture

Security is one of the core design principles of Sealed.

The current development version contains a custom ratchet implementation. This implementation is considered transitional and is not intended to be treated as a production-grade Signal Protocol implementation.

The production architecture is intended to use an established and appropriately licensed secure messaging protocol implementation.

The target architecture includes:

Identity Keys

Every device has a long-term cryptographic identity.
Device
 ├── Identity Key Pair
 ├── Signed Pre-Key
 ├── One-Time Pre-Keys
 └── Session State
Identity keys are generated on the client.

Private keys should never be uploaded to the server.

⸻

🔑 Session Establishment

The intended architecture uses a pre-key based session establishment system.

A simplified flow:
Alice                         Server                         Bob
  │                             │                             │
  │──── Request Bob bundle ────►│                             │
  │                             │                             │
  │◄──── Identity + PreKeys ────│                             │
  │                             │                             │
  │──── Encrypted session msg ───────────────────────────────►│
  │                             │                             │
  │                             │                      Establish session
  │                             │                             │
  │◄════════ Encrypted messages ═════════════════════════════►│
The server distributes public cryptographic material but does not receive users’ private identity keys.

⸻

🔄 Forward Secrecy

Sealed is designed to provide forward secrecy through regularly changing session/message keys.

The goal is:

Compromise of a current key should not automatically expose previously encrypted conversations.

Session state must therefore be treated as cryptographic state rather than simple application data.

⸻

🧩 Message Security

A production message envelope should contain opaque encrypted data rather than plaintext.

Conceptually:
{
  "type": "message",
  "messageId": "...",
  "senderDevice": "...",
  "recipientDevice": "...",
  "envelope": "...",
  "createdAt": "..."
}
The server does not need to understand the contents of the encrypted envelope.
📁 Project Structure

The project is organized approximately as follows:
encrypted-app/
│
├── server.js
├── package.json
├── package-lock.json
├── .env
│
└── public/
    ├── index.html
    ├── app.js
    └── style.css
⚙️ Environment Variables

Create a .env file:
PORT=3000

DATABASE_URL=your_postgresql_connection_string

METERED_API_KEY=your_metered_api_key
METERED_DOMAIN=your_metered_domain
Never commit .env to Git.

Your .gitignore should contain:
node_modules/
.env
.env.*
!.env.example
⸻

🗃️ Database

PostgreSQL is used for persistent application state.

The production database architecture is intended to contain separate concepts for:
users
  │
  └── devices
        ├── identity key
        ├── signed pre-key
        └── one-time pre-keys

message_queue
        │
        └── encrypted envelopes
A user’s account and a cryptographic device identity should not be treated as the same object.

This allows Sealed to support:

* Multiple devices
* Device revocation
* Key rotation
* New device registration
* Identity verification
* Secure device management

⸻

📱 Multi-Device Security

A future production version will treat every device independently.

Example:
John
│
├── iPhone
│    └── Device Key A
│
├── MacBook
│    └── Device Key B
│
└── Windows PC
     └── Device Key C
A compromised device should therefore be revocable without necessarily destroying the entire account.

⸻

🛡️ Security Principles

Sealed follows these principles:

1. Encrypt on the client

Sensitive content should be encrypted before transmission.

2. Never trust the network

All communication must assume the network may be observed or manipulated.

3. Minimize server knowledge

The server should store the minimum information required to operate the service.

4. Do not store private keys on the server

Private cryptographic identity material belongs to the user’s device.

5. Verify identity keys

A malicious or compromised server must not be able to silently replace a user’s identity key.

6. Use established cryptography

Production cryptography should rely on established, reviewed protocol implementations rather than proprietary cryptographic designs.

7. Fail securely

Unexpected cryptographic states should result in failure rather than silently falling back to insecure behavior.

⸻

⚠️ Security Status

Sealed is currently under active security development.

The following areas are being hardened before production:

* Production Signal-compatible protocol implementation
* X3DH / modern session establishment
* Signed pre-keys
* One-time pre-keys
* Double Ratchet
* Skipped message keys
* Replay protection
* Message counters
* Authentication-bound associated data
* Identity verification
* Device management
* Device revocation
* Secure session persistence
* ACK-based message delivery
* Strong WebSocket validation
* WebSocket rate limiting
* CSP
* Security headers
* XSS hardening
* CSRF protection where applicable
* Authentication hardening
* Session/token redesign
* Database security review
* Dependency auditing
* Production logging review
* External security audit

⸻

🔐 Browser Security

Sealed runs cryptographic operations in the user’s browser.

This provides important privacy properties, but browsers also introduce limitations.

For example:

* JavaScript can potentially be modified if the deployment is compromised.
* IndexedDB is not equivalent to a hardware security module.
* XSS can potentially compromise application secrets.
* Browser extensions may have access to sensitive browser content.
* A compromised device can potentially expose decrypted messages.

For this reason, production deployment requires strong browser security controls.

These include:
HTTPS
    │
    ├── HSTS
    ├── CSP
    ├── Secure cookies where applicable
    ├── Trusted Types
    ├── Subresource integrity where appropriate
    ├── Dependency control
    └── Strict input validation
⸻

📞 WebRTC Security

Audio calls use WebRTC.

The architecture supports:
Client A
   │
   ├──── Direct connection ────► Client B
   │
   └──── TURN relay ───────────► Client B
TURN is used when direct peer-to-peer connectivity is unavailable.

TURN credentials should be temporary and should never be unnecessarily exposed through application logs.

⸻

🚦 Rate Limiting

Authentication endpoints are rate limited to reduce:

* Brute-force attacks
* Credential stuffing
* Automated account creation
* Resource abuse

Production deployment should additionally consider rate limiting for:

* WebSocket connections
* Message sending
* Pre-key uploads
* Device registration
* TURN credential requests
* Call signaling

⸻

📊 Privacy Model

Sealed aims to minimize server-side access to private communications.

Conceptually:
                   SERVER

        ┌─────────────────────────┐
        │ Authentication          │
        │ Public key material     │
        │ Encrypted envelopes     │
        │ Delivery metadata       │
        │ Temporary signaling     │
        └─────────────────────────┘

                  NO
        ┌─────────────────────────┐
        │ Plaintext messages      │
        │ Private identity keys   │
        │ Message encryption keys │
        └─────────────────────────┘
This does not mean that metadata disappears.

Depending on the final architecture, the service may still know information such as:

* Account identifiers
* Device identifiers
* Connection timestamps
* Delivery information
* IP/network information
* Call signaling metadata

Therefore, Sealed should not claim that it provides completely metadata-free communication unless the architecture actually provides that property.

⸻

💳 Commercial Product

Sealed is intended to evolve into a paid privacy-focused communication service.

The commercial architecture therefore prioritizes:

Security

Cryptographic correctness and secure defaults.

Reliability

Messages should not disappear because a connection failed.

Scalability

The infrastructure should support increasing numbers of users and devices.

Maintainability

Security-critical components should not depend on undocumented custom cryptography.

Licensing

Every cryptographic dependency must be reviewed for its license and compatibility with the commercial distribution model.

In particular, cryptographic protocol libraries may have licenses such as GPL or AGPL that can impose obligations on commercial products.

No dependency should be adopted solely because it is technically convenient.

⸻

🧪 Security Testing

Before production release, Sealed should undergo testing in several layers.

Application Security
Authentication
Authorization
Session management
Input validation
XSS
CSRF
CORS
Rate limiting
WebSocket abuse
Cryptographic Testing
Session establishment
Key rotation
Out-of-order messages
Duplicate messages
Replay attacks
Key changes
Device revocation
Concurrent sessions
Offline delivery
Infrastructure Testing
HTTPS
TLS configuration
PostgreSQL permissions
Environment secrets
Container/server security
Logging
Monitoring
Backups
Dependency vulnerabilities
External Audit

The final production release should ideally receive an independent security review/audit.

⸻

🏭 Production Deployment

A recommended production architecture:
                         Internet
                            │
                            ▼
                     ┌──────────────┐
                     │ HTTPS / WSS  │
                     └──────┬───────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │ Sealed API        │
                  │ Node.js           │
                  │ Express           │
                  │ WebSocket         │
                  └─────────┬─────────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
              ▼                           ▼
       ┌──────────────┐           ┌──────────────┐
       │ PostgreSQL   │           │ TURN         │
       │              │           │ Infrastructure│
       └──────────────┘           └──────────────┘
⸻

📈 Future Roadmap

Phase 1 — Cryptographic Foundation

* Secure identity architecture
* Signed pre-keys
* One-time pre-keys
* Session establishment
* Production-grade ratchet
* Replay protection
* Key verification

Phase 2 — Account Security

* Secure session architecture
* Device management
* Device revocation
* Key-change warnings
* Login security
* Account recovery strategy

Phase 3 — Messaging Infrastructure

* ACK-based delivery
* Reliable offline queue
* Message expiration
* Delivery states
* Multi-device synchronization

Phase 4 — Browser Hardening

* Strict CSP
* Trusted Types
* Secure headers
* XSS hardening
* Dependency integrity
* Secure storage improvements

Phase 5 — Calls

* WebRTC hardening
* TURN credential security
* Call authentication
* Call abuse protection
* Connection reliability

Phase 6 — Commercial Infrastructure

* Subscription system
* Plans
* Usage limits
* Billing
* Account management
* Admin dashboard
* Monitoring
* Abuse prevention

Phase 7 — Security Audit

* Threat modeling
* Penetration testing
* Cryptographic review
* Infrastructure audit
* Dependency audit
* Independent security assessment

⸻

🧠 Threat Model

Sealed is designed with the following threats in mind:

Network attacker

An attacker observing network traffic should not be able to read message plaintext.

Compromised server

A compromised server should have as little access as possible to message contents.

Malicious account

A malicious user should not be able to compromise other users simply by sending malformed protocol messages.

Stolen session

Authentication tokens must be treated as sensitive credentials.

Device compromise

If a user’s device is fully compromised, the application cannot guarantee secrecy from the attacker.

Malicious JavaScript

Browser application integrity is therefore a critical security boundary.

⸻

⚖️ Disclaimer

Sealed is a security-focused communication application, but no software can honestly guarantee perfect or absolute security.

Security depends on:

* Correct cryptographic implementation
* Secure infrastructure
* Secure deployment
* Updated dependencies
* Device security
* Browser security
* User behavior
* Continuous security testing

Claims such as “100% secure” should not be made.

The goal of Sealed is instead to provide strong, verifiable security properties based on established cryptographic principles and transparent engineering.

⸻

👨‍💻 Development

Sealed is actively being developed.

Security-related changes should be reviewed carefully before merging.

Avoid:
Custom cryptographic algorithms
Plaintext logging
Permanent credentials
Private keys on the server
Silent key replacement
Insecure protocol fallbacks
Unvalidated WebSocket messages
Prefer:
Established cryptographic protocols
Minimal server trust
Short-lived credentials
Strict validation
Explicit state transitions
Secure defaults
Independent security review
⸻

🔐 Sealed

Private communication, engineered with security in mind.

The long-term objective is simple:

Build a communication platform where privacy is not an optional feature — it is part of the architecture.
                              │
                              ▼
                         Plaintext
