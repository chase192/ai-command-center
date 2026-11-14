import { createRemoteJWKSet, jwtVerify } from 'jose';
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

export function mountMcp(app, askModels) {
  const issuer = (process.env.MCP_OAUTH_ISSUER || '').replace(/\/$/, '');
  const audience = process.env.MCP_OAUTH_AUDIENCE || '';
  const publicUrl = (process.env.PUBLIC_BASE_URL || '').replace(/\/$/, '');
  if (!issuer || !audience || !publicUrl) {
    console.log('MCP disabled: configure MCP_OAUTH_ISSUER, MCP_OAUTH_AUDIENCE and PUBLIC_BASE_URL');
    return;
  }
  if (!issuer.startsWith('https://') || !publicUrl.startsWith('https://')) {
    throw new Error('MCP OAuth issuer and public URL must use HTTPS');
  }
  const resource = publicUrl + '/mcp';
  const jwks = createRemoteJWKSet(new URL(issuer + '/.well-known/jwks.json'));

  const metadata = {
    resource,
    authorization_servers: [issuer],
    bearer_methods_supported: ['header'],
    scopes_supported: ['ask:models']
  };
  app.get('/.well-known/oauth-protected-resource', (_req, res) => res.json(metadata));
  app.get('/.well-known/oauth-protected-resource/mcp', (_req, res) => res.json(metadata));

  function challenge(res, message = 'Authentication required') {
    res.set('WWW-Authenticate', 'Bearer resource_metadata="' +
      publicUrl + '/.well-known/oauth-protected-resource/mcp"');
    return res.status(401).json({ error: message });
  }

  app.post('/mcp', async (req, res) => {
    const authorization = req.get('authorization') || '';
    if (!authorization.startsWith('Bearer ')) return challenge(res);
    try {
      const { payload } = await jwtVerify(authorization.slice(7), jwks, {
        issuer,
        audience,
        algorithms: ['RS256']
      });
      const scopes = String(payload.scope || '').split(/\s+/);
      if (!scopes.includes('ask:models')) return challenge(res, 'Missing ask:models scope');
    } catch {
      return challenge(res, 'Invalid or expired token');
    }

    const server = new McpServer({ name: 'AI Command Center', version: '1.0.0' });
    server.registerTool('ask_all_models', {
      description: 'Ask OpenAI, Claude and Grok the same question, then synthesize their responses. Sends the question to all three external AI providers and incurs API usage charges.',
      securitySchemes: [{ type: 'oauth2', scopes: ['ask:models'] }],
      inputSchema: { question: z.string().min(1).max(5000) }
    }, async ({ question }) => {
      const result = await askModels(question);
      return {
        content: [{ type: 'text', text: JSON.stringify(result) }],
        isError: Boolean(result.error)
      };
    });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      console.error('MCP request failed:', error?.message || 'unknown error');
      if (!res.headersSent) res.status(500).json({ error: 'MCP request failed' });
    } finally {
      res.on('close', () => {
        transport.close().catch(() => {});
        server.close().catch(() => {});
      });
    }
  });
  app.get('/mcp', (_req, res) => res.status(405).set('Allow', 'POST').end());
  app.delete('/mcp', (_req, res) => res.status(405).set('Allow', 'POST').end());
  console.log('Secure MCP endpoint enabled');
}
