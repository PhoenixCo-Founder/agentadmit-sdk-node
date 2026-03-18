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

## License

All rights reserved. Patent pending.
