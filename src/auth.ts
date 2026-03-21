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

  if (!token.startsWith(config.token_prefix_access)) {
    throw new Error('Not an AgentAdmit access token');
  }

  // MANDATORY INTROSPECTION — validate via AgentAdmit hosted service
  // No local JWT decode. Every verification call goes through AgentAdmit.
  const verifyUrl = (config as any).agentadmit_verify_url || 'https://api.agentadmit.com/v1/verify';
  const appId = config.app_id;
  const apiKey = (config as any).api_key || '';

  let response: globalThis.Response;
  try {
    response = await fetch(verifyUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-App-Id': appId,
        'X-Api-Key': apiKey,
        'Content-Type': 'application/json',
      },
    });
  } catch (err: any) {
    throw new Error(`AgentAdmit introspection failed (network): ${err.message}`);
  }

  if (response.status === 401) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.error_description || 'Token validation failed');
  }

  if (response.status !== 200) {
    throw new Error(`Verification service returned ${response.status}`);
  }

  const data = await response.json();

  const scopes = data.scopes || [];
  const userId = data.user_id;
  const connectionId = data.connection_id;

  if (!userId) {
    throw new Error('Introspection returned no user');
  }

  // User lookup from app's local database (if storage is configured)
  let user: Record<string, any> = { [config.user_lookup_field]: userId };
  try {
    const storage = getStorage();
    const localUser = await storage.getUser(userId, config.user_lookup_field);
    if (localUser) user = localUser;
  } catch {}

  const connection = {
    connection_id: connectionId,
    scopes,
    agent_label: data.agent_label || 'Unknown Agent',
  };

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
