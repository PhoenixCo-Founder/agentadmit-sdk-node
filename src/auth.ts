/**
 * agentadmit/auth.ts
 * Token validation, scope enforcement, and audit logging for Express.
 */

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { getConfig } from './config';
import { loadPublicKey } from './keys';
import { StorageBackend } from './storage';

let _storage: StorageBackend | null = null;
let _verifyUserToken: ((token: string) => string | Promise<string>) | null = null;

export function setStorage(storage: StorageBackend) {
  _storage = storage;
}

export function setUserVerifier(fn: (token: string) => string | Promise<string>) {
  _verifyUserToken = fn;
}

function getStorage(): StorageBackend {
  if (!_storage) throw new Error('AgentAdmit storage not initialized');
  return _storage;
}

function getBearerToken(req: Request): string | null {
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7);
  return null;
}

export interface AgentContext {
  auth_type: 'agent' | 'user';
  user: Record<string, any>;
  connection: Record<string, any> | null;
  scopes: string[];
}

/**
 * Validate an ag_at_ token and return the agent context.
 */
export async function validateAgentToken(token: string): Promise<Omit<AgentContext, 'auth_type'>> {
  const config = getConfig();
  const storage = getStorage();

  if (!token.startsWith(config.token_prefix_access)) {
    throw new Error('Not an AgentAdmit access token');
  }

  const raw = token.slice(config.token_prefix_access.length);
  const publicKey = loadPublicKey(config.public_key_path);

  let payload: any;
  try {
    payload = jwt.verify(raw, publicKey, {
      algorithms: [config.algorithm as jwt.Algorithm],
      audience: config.audience,
    });
  } catch (err: any) {
    if (err.name === 'TokenExpiredError') {
      // Try to mark connection as expired
      try {
        const decoded = jwt.decode(raw) as any;
        const connId = decoded?.agentadmit?.connection_id;
        if (connId) await storage.updateConnection(connId, { status: 'expired' });
      } catch {}
      throw new Error('Access token has expired');
    }
    throw new Error('Invalid access token');
  }

  const claims = payload.agentadmit || {};
  const connectionId = claims.connection_id;
  const scopes = claims.scopes || [];
  const userId = payload.sub;

  if (!connectionId || !userId) {
    throw new Error('Token missing required claims');
  }

  const connection = await storage.getActiveConnection(connectionId);
  if (!connection) {
    throw new Error('Connection revoked or not found');
  }

  const user = await storage.getUser(userId, config.user_lookup_field);
  if (!user) {
    throw new Error('User not found');
  }

  // Update last_used
  try {
    await storage.updateConnection(connectionId, { last_used: new Date() });
  } catch {}

  return { user, connection, scopes };
}

/**
 * Express middleware: require a specific scope (agent-only).
 */
export function requireScope(scope: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const token = getBearerToken(req);
    const config = getConfig();

    if (!token || !token.startsWith(config.token_prefix_access)) {
      return res.status(401).json({ error: 'invalid_token', error_description: 'AgentAdmit token required' });
    }

    try {
      const ctx = await validateAgentToken(token);
      if (!ctx.scopes.includes(scope)) {
        return res.status(403).json({
          error: 'insufficient_scope',
          required_scope: scope,
          granted_scopes: ctx.scopes,
        });
      }

      await logAccess(ctx, scope, req);
      (req as any).agentAdmit = { auth_type: 'agent', ...ctx };
      next();
    } catch (err: any) {
      return res.status(401).json({ error: 'invalid_token', error_description: err.message });
    }
  };
}

/**
 * Express middleware: enforce scope only if caller is an agent.
 */
export function requireScopeIfAgent(scope: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const token = getBearerToken(req);
    const config = getConfig();

    if (!token || !token.startsWith(config.token_prefix_access)) {
      return next(); // Not an agent — pass through
    }

    try {
      const ctx = await validateAgentToken(token);
      if (!ctx.scopes.includes(scope)) {
        return res.status(403).json({
          error: 'insufficient_scope',
          required_scope: scope,
          granted_scopes: ctx.scopes,
        });
      }

      await logAccess(ctx, scope, req);
      (req as any).agentAdmit = { auth_type: 'agent', ...ctx };
      next();
    } catch (err: any) {
      return res.status(401).json({ error: 'invalid_token', error_description: err.message });
    }
  };
}

/**
 * Express middleware: resolve user or agent from token.
 */
export function resolveAuth() {
  return async (req: Request, res: Response, next: NextFunction) => {
    const token = getBearerToken(req);
    const config = getConfig();

    if (!token) {
      return res.status(401).json({ error: 'not_authenticated' });
    }

    if (token.startsWith(config.token_prefix_access)) {
      try {
        const ctx = await validateAgentToken(token);
        (req as any).agentAdmit = { auth_type: 'agent', ...ctx };
        return next();
      } catch (err: any) {
        return res.status(401).json({ error: 'invalid_token', error_description: err.message });
      }
    }

    // Regular user token
    if (!_verifyUserToken) {
      return res.status(500).json({ error: 'server_error', error_description: 'User token verifier not configured' });
    }

    try {
      const userId = await _verifyUserToken(token);
      const storage = getStorage();
      const user = await storage.getUser(userId, config.user_lookup_field);
      if (!user) {
        return res.status(404).json({ error: 'user_not_found' });
      }
      (req as any).agentAdmit = { auth_type: 'user', user, scopes: ['*'], connection: null };
      next();
    } catch {
      return res.status(401).json({ error: 'invalid_token' });
    }
  };
}

/**
 * Write audit log entry.
 */
async function logAccess(
  ctx: { connection: Record<string, any> | null; user: Record<string, any> },
  scope: string,
  req: Request,
): Promise<void> {
  try {
    const config = getConfig();
    const storage = getStorage();
    await storage.logAccess({
      timestamp: new Date(),
      connection_id: ctx.connection?.connection_id || 'unknown',
      user_id: ctx.user?.[config.user_lookup_field] || 'unknown',
      scope_used: scope,
      resource: req.path,
      method: req.method,
      agent_label: ctx.connection?.agent_label || 'Unknown Agent',
    });
  } catch (err) {
    console.error('[AgentAdmit] Audit log failed:', err);
  }
}

/**
 * Check connection cap for tier enforcement.
 */
export async function checkConnectionCap(userId: string, tier: string): Promise<void> {
  const { getTierLimits } = require('./config');
  const limits = getTierLimits(tier);
  if (!limits?.hard_cap) return;

  const storage = getStorage();
  const count = await storage.countActiveConnections(userId);

  if (count >= limits.connections_limit) {
    const err: any = new Error(`Connection limit reached (${count}/${limits.connections_limit})`);
    err.statusCode = 429;
    err.detail = {
      error: 'connection_limit_reached',
      connections_used: count,
      connections_limit: limits.connections_limit,
      tier,
    };
    throw err;
  }
}
