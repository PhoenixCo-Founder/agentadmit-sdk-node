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
const { validateAgentToken } = require('@agentadmit/sdk');

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

Full MCP integration guide with complete before/after examples: `agentadmit.com/docs/mcp-guide`

**MCP operators:** You also get the embeddable admin panel with revoke capability, admin scopes for your own AI agent to monitor your server, and full audit trail for billing. See the Admin Revocation and Embeddable Admin Panel sections below.

## How It Works

1. User clicks "AgentAdmit" in your app
2. Selects scopes and connection duration
3. Gets a token to give to their AI agent
4. Agent exchanges the token for scoped API access
5. User revokes anytime

The token goes to the human, not the agent. No automated delivery = no prompt injection surface.

## Important

**Mandatory introspection.** All token validation goes through api.agentadmit.com. There is no self-hosted mode. No local JWT validation. No bypass. This is required for security, audit logging, and scope enforcement.

**Admin revocation.** As the app operator, you can revoke any user's agent connection via `DELETE /agentadmit/admin/connections/{connection_id}` (requires admin role or `manage:connections` scope). Your own AI agent can also revoke connections if given this scope.

**Embeddable admin panel.** Drop the `<AgentAdmitAdminPanel>` React component into your admin section to view all agent connections, usage metrics, billing status, and revoke any connection without leaving your app. See the React SDK for details.

**In-app AI scopes.** If your app has built-in AI features (analysis, plan generation, photo recognition), do not expose those as agent scopes. The user's AI agent can read the raw data and do the analysis itself. Exposing in-app AI endpoints to agents creates double cost.

## Rate Limiting

The AgentAdmit introspection endpoint enforces rate limits. The Node.js SDK handles HTTP 429 responses **automatically** with exponential backoff and jitter — no changes needed in your middleware code.

### Retry behavior

| Parameter | Default | Description |
|-----------|---------|-------------|
| Initial delay | 1 second | First retry wait |
| Backoff multiplier | 2× | Doubles each retry |
| Cap | 30 seconds | Maximum wait per retry |
| Jitter | 0–500 ms | Random addition to each delay |
| Max retries | **3** | Configurable |

The SDK also respects the `Retry-After` response header — if present, it overrides the computed backoff delay.

### Configuring max retries

In `agentadmit.yaml`:

```yaml
max_retries: 5  # default: 3. Set to 0 to disable retries.
```

### Handling exhausted retries

When all retries are exhausted, `validateAgentToken` throws `RateLimitError`:

```typescript
import { requireScope, RateLimitError } from '@agentadmit/sdk';

app.use((err: any, req, res, next) => {
  if (err instanceof RateLimitError) {
    res.set('Retry-After', String(err.retryAfter ?? 60));
    return res.status(429).json({
      error: 'rate_limited',
      retry_after: err.retryAfter,
      limit: err.limit,
      remaining: err.remaining,
      reset: err.reset,
    });
  }
  next(err);
});
```

`RateLimitError` properties:
- `retryAfter` — seconds from `Retry-After` header (or `null`)
- `limit` — `X-RateLimit-Limit` header value (or `null`)
- `remaining` — `X-RateLimit-Remaining` header value (or `null`)
- `reset` — `X-RateLimit-Reset` Unix timestamp (or `null`)

## Documentation

Full integration guide: https://agentadmit.com/docs/app-owner-guide


## Data Collection & Privacy

The AgentAdmit Node.js SDK runs server-side and does not interact with app stores or end-user devices directly.

### What the SDK does
- Validates AgentAdmit tokens presented by AI agents
- Enforces scope-based access control on your API routes
- Manages connection lifecycle (create, revoke, audit)

### What the SDK does NOT do
- Does not collect end-user data
- Does not send telemetry or analytics
- Does not phone home to AgentAdmit servers (all operations use your configured keys and storage)
- Does not track users or devices

### Privacy impact
Since this SDK runs on your server, it has no direct App Store or Play Store compliance surface. Your client-side integration (e.g., the AgentAdmit React SDK) handles privacy manifest and data safety requirements.

For complete compliance guidance, see our [compliance guide](https://agentadmit.com/docs/compliance).

## License

All rights reserved. Patent pending.

## Security Alerts

Monitor suspicious agent activity. Six alert types:
- `volume_spike`, `failed_scope_attempts`, `burst_pattern`,
- `stale_reactivation`, `new_scope_usage`, `revoked_connection_attempt`

### Configure Alert Thresholds

```typescript
import { configureAlerts } from '@agentadmit/sdk';

await configureAlerts({
  app_id: 'app_abc123',
  alert_type: 'volume_spike',
  enabled: true,
  threshold_value: 100,
  threshold_window_minutes: 5,
  kill_switch_enabled: true,
});
```

### List Alert Events

```typescript
import { listAlerts } from '@agentadmit/sdk';
const { events, total } = await listAlerts({ app_id: 'app_abc123', alert_type: 'volume_spike' });
```

### Get Current Config

```typescript
import { getAlertConfig } from '@agentadmit/sdk';
const config = await getAlertConfig({ app_id: 'app_abc123' });
```
