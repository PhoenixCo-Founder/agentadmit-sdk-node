# @agentadmit/sdk — Node.js

User-mediated AI agent authorization. Plug-and-play for Express and Next.js.

## Quick Start

```bash
npm install @agentadmit/sdk
npx agentadmit init
```

Edit `agentadmit.yaml` to define your scopes, then add to your Express app:

```javascript
const express = require('express');
const { loadConfig, createStorage, createAgentAdmitRouter, setStorage, requireScopeIfAgent } = require('@agentadmit/sdk');

const app = express();
app.use(express.json());

// Initialize AgentAdmit
const config = loadConfig('agentadmit.yaml');
const storage = createStorage(config);
setStorage(storage);

// Create and mount AgentAdmit routes
const { wellknownRouter, agentadmitRouter } = createAgentAdmitRouter({
  storage,
  getCurrentUser: async (req) => { /* your auth logic */ },
});
app.use(wellknownRouter);
app.use('/agentadmit', agentadmitRouter);

// Protect your routes with scope enforcement
app.get('/api/orders', requireScopeIfAgent('read:orders'), (req, res) => {
  const user = req.agentAdmit?.user;
  // Your existing logic — unchanged
  res.json({ orders: getOrdersForUser(user.user_id) });
});
```

## Next.js API Routes

```typescript
// pages/api/orders.ts (or app/api/orders/route.ts)
import { validateAgentToken, getConfig } from '@agentadmit/sdk';

export default async function handler(req, res) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const config = getConfig();

  if (token?.startsWith(config.token_prefix_access)) {
    const ctx = await validateAgentToken(token);
    if (!ctx.scopes.includes('read:orders')) {
      return res.status(403).json({ error: 'insufficient_scope' });
    }
    // Agent path
    return res.json({ orders: await getOrders(ctx.user.user_id) });
  }

  // Regular user path
  // ... your existing auth
}
```

## MCP Server Integration

Building an MCP server in TypeScript/Node? AgentAdmit is the auth layer. MCP servers are app owners. Same SDK, same pricing.

For **STDIO transport** (most MCP servers), the agent includes the token in tool arguments:

```javascript
const { validateAgentToken } = require('@agentadmit/node');

async function handleToolCall(name, args) {
  // 1. Extract token from tool arguments
  const token = args.agentadmit_token;
  delete args.agentadmit_token;
  if (!token) throw new Error('agentadmit_token required');
  
  // 2. Validate via AgentAdmit hosted service
  const ctx = await validateAgentToken(token);
  
  // 3. Check scope for this tool
  const required = SCOPE_MAP[name];
  if (required && !ctx.scopes.includes(required)) {
    throw new Error(`Missing scope '${required}'`);
  }
  
  // 4. Run the tool
  return TOOL_HANDLERS[name](args, ctx);
}
```

For **HTTP transport** (Express-based MCP servers), use the full SDK middleware. The agent sends the token via `Authorization: Bearer` header, same as any HTTP API.

Full MCP integration guide with complete before/after examples: `docs.agentadmit.com/mcp`

## How It Works

1. User clicks "AI Agent Access" in your app
2. Selects scopes and connection duration
3. Gets a token to give to their AI agent
4. Agent exchanges the token for scoped API access
5. User revokes anytime

The token goes to the human, not the agent. No automated delivery = no prompt injection surface.

## Important

**Mandatory introspection.** All token validation goes through api.agentadmit.com. There is no self-hosted mode. No local JWT validation. No bypass. This is required for security, audit logging, and scope enforcement.

**In-app AI scopes.** If your app has built-in AI features (analysis, plan generation, photo recognition), do not expose those as agent scopes. The user's AI agent can read the raw data and do the analysis itself. Exposing in-app AI endpoints to agents creates double cost.

## Documentation

Full integration guide: https://docs.agentadmit.com/getting-started

## License

All rights reserved. Patent pending.
