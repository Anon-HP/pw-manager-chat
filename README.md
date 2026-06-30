# Password Manager & Real-Time Chat Backend

This repository contains the backend infrastructure for a secure password manager and real-time chat application. Built with Go, it utilizes a thread-safe, in-memory data store to handle user authentication, encrypted vault storage, and high-concurrency WebSocket communication.

## Key Features

* **Secure Authentication:** Complete registration and login lifecycle using bcrypt for password hashing and short-lived JWTs paired with secure refresh tokens.
* **Encrypted Vault:** End-to-end architecture support utilizing Argon2 for key derivation and AES-GCM for payload encryption.
* **Enterprise Chat Engine:** Gorilla WebSocket integration with concurrent read and write pumps, strict deadman's switch timers, and an offline message queue.
* **WebSocket Ticket System:** A highly secure, one-time 10-second ticket architecture that completely hides JWTs from proxy logs and browser history during the WebSocket handshake.
* **Thread-Safe Singleton Database:** A unified in-memory data store utilizing Read/Write Mutex locks to manage concurrent access across the auth, vault, and chat modules.

---

## Prerequisites

* Go 1.22 or higher (required for standard library HTTP routing features)
* Git

---

## Installation & Setup

1. **Clone the repository**
```bash
git clone https://github.com/YOUR_USERNAME/pw-manager-chat-backend.git
cd pw-manager-chat-backend

```


2. **Configure Environment Variables**
Create a `.env` file in the root directory and define the following variables:
```env
JWT_SECRET_KEY=your_super_secret_key_here
FRONTEND_ORIGIN=http://localhost:3000

```


3. **Run the Server**
```bash
go run main.go

```


The server will initialize on port 5000.

---

## REST API Documentation

All protected routes require an `Authorization` header formatted as `Bearer <token>`.

### Authentication endpoints

| Method | Endpoint | Description | Auth Required |
| --- | --- | --- | --- |
| POST | `/api/register` | Registers a new user and generates vault keys | No |
| POST | `/api/login` | Authenticates user and returns JWT & Refresh Token | No |
| POST | `/api/refresh` | Issues a new JWT using a valid Refresh Token | No |
| POST | `/api/logout` | Revokes the current session | No |
| DELETE | `/api/delete-account` | Deletes user account and all associated data | Yes |

### Vault endpoints

| Method | Endpoint | Description | Auth Required |
| --- | --- | --- | --- |
| GET | `/api/vault` | Retrieves all encrypted entries for the user | Yes |
| POST | `/api/vault/create` | Saves a new encrypted entry | Yes |
| PATCH | `/api/vault/update` | Updates an existing entry | Yes |
| DELETE | `/api/vault/delete` | Deletes a single entry via `?id=` query | Yes |
| DELETE | `/api/vault/delete-bulk` | Deletes multiple entries via JSON body | Yes |

---

## WebSocket Architecture

To prevent token leakage in URL parameters and server logs, the WebSocket connection utilizes a two-step ticket authorization protocol.

1. **Request a Ticket (REST):** The client makes an authenticated `GET` request to `/api/ws/ticket` using their JWT.
2. **Establish Connection (WS):** The server returns a one-time cryptographic ticket. The client immediately connects to `/api/ws?ticket=<ticket_string>`.
3. **Validation & Burn:** The server validates the ticket, instantly deletes it from memory to prevent reuse, and upgrades the connection to a WebSocket protocol.

| Method | Endpoint | Description | Auth Required |
| --- | --- | --- | --- |
| GET | `/api/ws/ticket` | Generates a 10-second one-time connection ticket | Yes |
| GET | `/api/ws` | Upgrades the connection to a WebSocket protocol | Ticket |
