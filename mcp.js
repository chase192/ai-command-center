import crypto from 'node:crypto';

const MCP_URL = (process.env.MCP_RESOURCE_URL || 'https://chase-ai-command-center.onrender.com/mcp').replace(/\/$/, '');
const MCP_ORIGIN = new URL(MCP_URL).origin;
const DOMAIN = (process.env.AUTH0_DOMAIN || '').replace(/^https?:\/\//, '').replace(/\/$/, '');
const ISSUER = DOMAIN ? `https://${DOMAIN}/` : '';
const AUDIENCE = process.env.AUTH0_AUDIENCE || MCP_URL;
const JWKS_URL = ISSUER ? new URL('.well-known/jwks.json', ISSUER).toString() : '';
let keyCache = { expires: 0, keys: [] };

function unauthorized(res, message = 'Unauthorized') {
  res.set('WWW-Authenticate', `Bearer resource_metadata="${MCP_ORIGIN}/.well-known/oauth-protected-resource/mcp", error="invalid_token"`);
  return res.status(401).json({ error: message });
}
function decode(part) {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}
async function publicKey(kid) {
  if (Date.now() > keyCache.expires) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      const response = await fetch(JWKS_URL, { signal: controller.signal });
      if (!response.ok) throw new Error('Unable to retrieve signing keys');
      const data = await response.json();
      if (!Array.isArray(data.keys)) throw new Error('Invalid signing keys');
      keyCache = { keys: data.keys, expires: Date.now() + 5 * 60 * 1000 };
    } finally { clearTimeout(timer); }
  }
  let jwk = keyCache.keys.find(k => k.kid === kid && k.kty === 'RSA' && k.use === 'sig' && k.alg === 'RS256');
  if (!jwk) {
    keyCache.expires = 0;
    throw new Error('Signing key not found');
  }
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}
async function verifyToken(req, res, next) {
  if (!ISSUER) { console.warn('[MCP] Auth0 issuer not configured'); return res.status(503).json({ error: 'MCP authentication not configured' }); }
  const match = /^Bearer (\S+)$/i.exec(req.get('authorization') || '');
  if (!match) { console.warn('[MCP] Missing bearer token'); return unauthorized(res); }
  try {
    const parts = match[1].split('.');
    if (parts.length !== 3) throw new Error('Malformed token');
    const header = decode(parts[0]);
    const claims = decode(parts[1]);
    if (header.alg !== 'RS256' || typeof header.kid !== 'string') throw new Error('Invalid algorithm');
    const key = await publicKey(header.kid);
    const valid = crypto.verify('RSA-SHA256', Buffer.from(parts[0] + '.' + parts[1]), key, Buffer.from(parts[2], 'base64url'));
    const now = Math.floor(Date.now() / 1000);
    if (!valid) throw new Error('Invalid signature');
    if (claims.iss !== ISSUER) throw new Error('Issuer mismatch');
    if (!(typeof claims.aud === 'string' ? claims.aud === AUDIENCE : Array.isArray(claims.aud) && claims.aud.includes(AUDIENCE))) throw new Error('Audience mismatch');
    if (!Number.isInteger(claims.exp) || claims.exp <= now) throw new Error('Token expired or missing expiry');
    if (claims.nbf !== undefined && (!Number.isInteger(claims.nbf) || claims.nbf > now)) throw new Error('Token not yet valid');
    if (claims.iat !== undefined && (!Number.isInteger(claims.iat) || claims.iat > now + 60)) throw new Error('Invalid issue time');
    if (typeof claims.sub !== 'string') throw new Error('Missing subject');
    req.mcpScopes = new Set((claims.scope || '').split(/\s+/).filter(Boolean));
    console.info('[MCP] Token verified', { scopeRead: req.mcpScopes.has('mcp:read'), scopeExecute: req.mcpScopes.has('mcp:execute') });
    next();
  } catch (error) {
    console.warn('[MCP] Token rejected', { reason: error.message });
    return unauthorized(res);
  }
}
function rpc(id, result) { return { jsonrpc: '2.0', id, result }; }
function rpcError(id, code, message) { return { jsonrpc: '2.0', id, error: { code, message } }; }
const tool = {
  name: 'ask_ai_command_center',
  description: 'Ask OpenAI, Claude and Grok the same question and return a synthesized answer plus each model response. Uses paid API credits.',
  inputSchema: {
    type: 'object',
    properties: { prompt: { type: 'string', minLength: 1, maxLength: 5000 } },
    required: ['prompt'],
    additionalProperties: false
  }
};

export function registerMcp(app, askModels) {
  // OAuth protected-resource metadata: ChatGPT discovers the Auth0 authorization server here.
  const metadata = {
    resource: MCP_URL,
    authorization_servers: ISSUER ? [ISSUER] : [],
    scopes_supported: ['mcp:read', 'mcp:execute'],
    bearer_methods_supported: ['header']
  };
  app.use(['/mcp', '/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'], (req, _res, next) => {
    console.info('[MCP] Incoming request', { method: req.method, path: req.path, hasBearer: /^Bearer /i.test(req.get('authorization') || ''), contentType: req.get('content-type') || 'none' });
    next();
  });
  app.get('/.well-known/oauth-protected-resource', (_req, res) => res.json(metadata));
  app.get('/.well-known/oauth-protected-resource/mcp', (_req, res) => res.json(metadata));
  app.get('/mcp', verifyToken, (_req, res) => res.status(405).set('Allow', 'POST').end());
  app.delete('/mcp', verifyToken, (_req, res) => res.status(405).set('Allow', 'POST').end());
  app.post('/mcp', verifyToken, async (req, res) => {
    const request = req.body;
    console.info('[MCP] RPC request', { method: typeof request?.method === 'string' ? request.method : 'invalid', protocol: req.get('mcp-protocol-version') || 'unspecified' });
    if (!request || typeof request !== 'object' || Array.isArray(request) || request.jsonrpc !== '2.0' || typeof request.method !== 'string') {
      return res.status(400).json(rpcError(null, -32600, 'Invalid Request'));
    }
    // MCP notifications have no response body.
    if (request.id === undefined) return res.status(202).end();
    const id = request.id;
    res.set('Cache-Control', 'no-store');
    if (request.method === 'initialize') return res.json(rpc(id, {
      protocolVersion: '2025-03-26',
      capabilities: { tools: {} },
      serverInfo: { name: 'ai-command-center', version: '1.0.0' }
    }));
    if (request.method === 'ping') return res.json(rpc(id, {}));
    if (request.method === 'tools/list') {
      if (!req.mcpScopes.has('mcp:read')) { console.warn('[MCP] tools/list denied: missing mcp:read'); return res.status(403).json(rpcError(id, -32003, 'Missing mcp:read scope')); }
      console.info('[MCP] tools/list returned ask_ai_command_center');
      return res.json(rpc(id, { tools: [tool] }));
    }
    if (request.method === 'tools/call') {
      if (!req.mcpScopes.has('mcp:execute')) return res.status(403).json(rpcError(id, -32003, 'Missing mcp:execute scope'));
      const args = request.params?.arguments;
      if (request.params?.name !== tool.name || !args || typeof args.prompt !== 'string' || !args.prompt.trim() || args.prompt.length > 5000) {
        return res.json(rpcError(id, -32602, 'Invalid tool arguments'));
      }
      try {
        const result = await askModels(args.prompt);
        return res.json(rpc(id, {
          content: [{ type: 'text', text: JSON.stringify(result) }],
          isError: !!result.error
        }));
      } catch {
        return res.json(rpc(id, { content: [{ type: 'text', text: 'AI providers unavailable' }], isError: true }));
      }
    }
    return res.json(rpcError(id, -32601, 'Method not found'));
  });
}
