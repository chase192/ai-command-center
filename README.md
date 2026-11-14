# AI Command Center

Starter application for asking OpenAI, Anthropic Claude, and xAI Grok the same question and combining their responses. **This is a new starter, not a copy of any previously deployed application.**

## Start locally
1. Install Node.js 20 or newer.
2. Open a terminal in this folder and run `npm install`.
3. Copy `.env.example` to `.env`. Fill in `APP_PASSWORD`, a different random `SESSION_SECRET` (32+ characters), and your provider API keys.
4. Run `npm start` and visit `http://localhost:3000`.
5. Sign in using your `APP_PASSWORD`.

Provider model IDs in `.env.example` are examples. Update them to model IDs available on your accounts. Provider API usage may incur charges.

## GitHub Desktop
Clone your empty `chase192/ai-command-center` repository, copy these files **into the cloned folder** (not the outer ZIP folder), review Changes, commit, and push. Never upload `.env`, passwords, API keys, or secrets.

## Render
Create a Node Web Service connected to the GitHub repository. Build command: `npm install`; start command: `npm start`. Set the environment variables from `.env.example` in Render's environment settings (with actual secret values), **not** in GitHub. Render supplies `PORT`. Use HTTPS for production.

## Authentication and request flow
- The browser POSTs the shared `APP_PASSWORD` to `/api/login` over HTTPS in production.
- The server compares it using a timing-safe comparison and issues a signed, HttpOnly, SameSite=Strict session cookie, expiring in 12 hours. Session data contains only a timestamp and a random nonce; no API keys.
- Browser POSTs a prompt to `/api/ask` with its cookie. Server validates the cookie and same-origin request.
- Server sends requests in parallel to the three AI providers using environment-stored API keys. Keys are never sent to the browser.
- Server sends the three answers to OpenAI for synthesis and returns the combined response plus the individual responses.
- `/api/logout` clears the cookie. Sessions are stateless: server restart does not invalidate existing signed cookies; rotate `SESSION_SECRET` to revoke them all.

## Security and limitations
Single-user starter with a shared password, **not** a production-grade multi-user identity system. Use a unique strong password, HTTPS, secure secret management, and consider SSO, durable server-side sessions, audit logging, usage quotas, and stronger CSRF defenses before broader deployment. In-memory rate limiting is per server process and not a substitute for edge protection. Never paste provider keys into chat. Outputs from AI providers are untrusted and should not be treated as instructions to execute. Provider responses are returned as plain text.
