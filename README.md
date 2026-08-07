# WebAuthn Service

This is a fully-functional reference implementation of **@simplewebauthn/server** and **@simplewebauthn/browser**, using **Express** to handle the WebAuthn flows for registration and authentication (login).

## Features

- **User Registration** via WebAuthn
- **User Authentication** via WebAuthn
- HTTPS Support for secure origins
- CSRF protection via **lusca**
- Rate Limiting to prevent abuse
- Handles both **resident key** and **non-resident key** options
- Uses **CORS** for cross-origin requests

## Requirements

- Node.js (>=12.x)
- SSL certificates for HTTPS (if enabled)
- Environment configuration via `.env` file

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/your-repo/webauthn-service.git
    cd webauthn-service
    ```

2. Install dependencies:

    ```bash
    pnpm install
    ```

3. Create a `.env` file with the following environment variables:

    ```env
    RP_ID=["example.com"]    # Relying Party ID, can be an array
    EXPECTED_ORIGINS=["https://example.com"]  # Expected origins for authentication
    RP_NAME=My WebAuthn Service    # Name of your service
    TIMEOUT=60000    # Timeout for registration/authentication flows
    SESSION_SECRET=replace-with-a-long-random-secret
    ENABLE_CONFORMANCE=true    # Enable conformance routes for FIDO Metadata Service
    ENABLE_HTTPS=true    # Enable HTTPS mode for the service
    ```

## Usage

### Authentication and storage integration

The WebAuthn endpoints require an existing, server-authenticated Express session. Your login
middleware must set `req.session.authenticatedUserId` to the application's immutable internal user
ID before calling them. Do not populate it from a request header, query parameter, or request body.

The example keeps ceremony state and authenticators in memory so it can demonstrate the required
server-side trust boundary: challenges are one-time, expire after `TIMEOUT`, and credentials and
signature counters are selected only from the server's records. Replace both maps and the session
store with shared durable storage before deploying multiple processes or relying on passkeys in
production. The browser must submit `{ ceremonyId, response }` to each verification endpoint; it
must not submit a challenge or a device record.

### Start the Server

To run the server, use the following command:

```bash
pnpm start
```
