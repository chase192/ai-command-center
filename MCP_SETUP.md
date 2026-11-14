# ChatGPT MCP integration (testing branch only)

This branch adds a stateless JSON-RPC MCP endpoint at `/mcp`. It does not modify the production `main` branch.

## Environment variables (Render test service only)
- `AUTH0_DOMAIN`: your Auth0 tenant domain, without https://
- `AUTH0_AUDIENCE`: `https://chase-ai-command-center.onrender.com/mcp`
- Existing `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `XAI_API_KEY`, `SESSION_SECRET`, `APP_PASSWORD` remain required.

**Important:** This implementation currently hardcodes the production Render MCP resource URL. Before deploying to a separate preview hostname, update `MCP_URL` in `mcp.js` and set the Auth0 API audience to the same exact URL. Do not connect ChatGPT to the production URL until an MCP-enabled version has been deployed there.

## Auth0
Use the existing Regular Web Application as the OAuth client, and the existing Custom API with identifier equal to the MCP resource URL. Grant user-delegated scopes `mcp:read` and `mcp:execute` to the Regular Web Application. Add the exact callback URL provided by ChatGPT under Auth0 Allowed Callback URLs. Configure Auth0 to issue RS256 JWT access tokens with this API audience. The code validates RS256 signatures using the tenant JWKS, issuer, audience, expiration, and requested scopes.

## MCP
- `GET /.well-known/oauth-protected-resource` and `GET /.well-known/oauth-protected-resource/mcp`: protected resource metadata.
- `POST /mcp`: JSON-RPC initialize, ping, tools/list, tools/call. Requires a Bearer access token.
- Tool: `ask_ai_command_center` with `{ "prompt": "..." }`.
- `tools/list` requires `mcp:read`, and `tools/call` requires `mcp:execute`.
- Browser password/cookie authentication remains unchanged for `/api/ask`.

## Test plan
1. Create a separate Render web service from this branch with the correct environment variables; don't replace the existing live service.
2. Check OAuth metadata, and confirm `POST /mcp` without a token returns 401.
3. Test a real Auth0 user access token with both scopes. An Auth0 machine-to-machine test token does not prove interactive ChatGPT OAuth works.
4. Test MCP initialize, tools/list and tools/call with a short prompt.
5. Add the testing service URL to ChatGPT as a custom MCP server and complete OAuth.
6. Verify no API keys, access tokens or client secrets are logged. Only merge into main after successful testing.

## Limitations
This is a minimal stateless MCP implementation for initial integration. It has not been deployed or integration-tested. Some clients may require further MCP protocol features or authorization metadata adjustments.
