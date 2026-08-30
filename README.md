# 🔐 Encrypted App

> A real-time end-to-end encrypted messaging application built with Node.js, WebSockets, PostgreSQL and modern cryptographic primitives.

## 🚀 What is Encrypted App?

Encrypted App is a secure real-time messaging platform built around one fundamental idea:

> **Your messages should belong to you — not the server.**

Messages are encrypted on the client side before being transmitted through the server.

The server is responsible for authentication, communication and data storage, but does not need access to the plaintext message content.

## ✨ Features

- 🔐 End-to-End Encryption
- 🔑 X25519 key exchange
- 🔄 Simplified Double Ratchet mechanism
- 🧂 Argon2 password hashing
- 🛡️ Secure session management
- 👤 Public key fingerprints
- ⚡ Real-time messaging with WebSockets
- 🗄️ PostgreSQL database
- 🚦 Rate limiting
- 🌐 Client-side encryption and decryption

## 🔒 How It Works

```text
        SENDER
          │
          │ Plaintext message
          ▼
   ┌─────────────────┐
   │ Client-side     │
   │ Encryption      │
   └────────┬────────┘
            │
            │ Ciphertext
            ▼
   ┌─────────────────┐
   │     SERVER      │
   │                 │
   │ Authentication  │
   │ WebSocket       │
   │ Routing         │
   │ PostgreSQL      │
   └────────┬────────┘
            │
            │ Ciphertext
            ▼
   ┌─────────────────┐
   │ Client-side     │
   │ Decryption      │
   └────────┬────────┘
            │
            ▼
        RECEIVER
🧠 Security Architecture

The application separates user authentication from message encryption.

The encryption process happens on the client side. The server primarily handles authentication, message routing and persistent application data.

This design minimizes the amount of sensitive information that the server needs to access.

🔐 Cryptography

X25519

X25519 is used for secure key agreement between clients.

SecretBox

Authenticated symmetric encryption is used to protect sensitive data and messages.

Argon2

Argon2 is used for secure password hashing.

Passwords are never stored as plaintext.

Key Ratcheting

The application includes a simplified Double Ratchet-inspired mechanism that allows encryption keys to evolve during a conversation.

⚠️ This is an educational implementation and should not be considered equivalent to Signal’s production-grade protocol.

⚡ Real-Time Communication

The application uses WebSockets to provide real-time communication between connected clients.

Instead of repeatedly polling the server, clients maintain a persistent WebSocket connection for fast message delivery.

🛡️ Authentication & Sessions

The backend includes:

* Password hashing with Argon2
* Session-based authentication
* Hashed session tokens
* Session expiration
* Server-side user identification
* Rate limiting

The server derives the authenticated user’s identity from the session rather than trusting a user-supplied from field.

🗄️ Database

PostgreSQL is used for persistent application data.

The database layer is responsible for application information such as:

* Users
* Authentication sessions
* Public keys
* Encrypted message data
📂 Project Structure
encrypted-app/
│
├── public/
│   ├── index.html
│   ├── app.js
│   └── style.css
│
├── server.js
├── package.json
├── package-lock.json
├── .env
├── .gitignore
└── README.md
⚙️ Installation
1. Clone the repository
git clone https://github.com/ElionLlapushi/encrytped-app.git
cd encrytped-app
2.Install dependencies
npm install
1. Configure environment variables
PORT=3000
DATABASE_URL=your_postgresql_connection_string
SESSION_SECRET=your_secure_secret
4. Start the application
npm start
Then open:
http://localhost:3000
🧪 Testing

Testing is an important area for further development.

Planned tests include:

* Authentication
* Encryption and decryption
* Key exchange
* Session handling
* WebSocket communication
* Database operations
* Rate limiting

🔮 Future Improvements

* Complete Double Ratchet implementation
* X3DH / pre-key system
* Offline message support
* Multi-device support
* Message expiration
* Encrypted file sharing
* Group conversations
* Better key management
* Automated security tests
* Docker deployment
* CI/CD pipeline
* Security audit

🎯 Why I Built This

This project was created to explore how modern web applications can combine:

Software Engineering + Networking + Databases + Applied Cryptography 
⚠️ Security Disclaimer

This project is primarily an educational and portfolio project exploring practical cryptography and secure application architecture.

It should not be considered production-ready cryptographic software.

The simplified ratchet implementation does not provide all the guarantees and protections of mature protocols such as Signal.

For production messaging systems, established and professionally audited cryptographic protocols and libraries should be preferred.

👨‍💻 Author

Elion Llapushi

Epoka Software Engineering Student interested in:

* Backend Development
* Cryptography
* Distributed Systems

Highlights

🔐 End-to-End Encryption
⚡ Real-Time WebSockets
🔑 X25519 Key Exchange
🔄 Key Ratcheting
🧂 Argon2 Password Hashing
🐘 PostgreSQL
🟢 Node.js

Security is not just about hiding data.
It’s about designing systems that don’t need to trust everyone in the first place. 🔐



