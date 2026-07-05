/**
 * agentadmit/auth.ts
 * Token validation, scope enforcement, and audit logging for Express.
 */

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { getConfig } from './config';
import { loadPublicKey } from './keys';
import { StorageBackend } from './storage';
import { RateLimitError } from './errors';
import type { ConsentVerdict } from './consent';

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
  /** Consent Ledger verdict for the external-agent path, when present. */
  consent?: ConsentVerdict;
  /** Human-presence fact for the connection, when the platform returns it. */
  presence?: PresenceInfo;
}

/**
 * Human-presence fact from the WebAuthn step-up: whether the human who
 * authorized this connection completed a presence ceremony on the consent
 * page. Additive — absent on older servers, and `verified: false` for
 * connections minted without a ceremony (direct-API tokens, presence-off
 * sessions, pre-presence connections).
 */
export interface PresenceInfo {
  verified: boolean;
  /** Ceremony type, e.g. 'webauthn'. null when never verified. */
  method: string | null;
  /** Authenticator user-verification flag reported by the ceremony. */
  uv: boolean | null;
  /** ISO-8601 timestamp of the ceremony. null when never verified. */
  verified_at: string | null;
}

/**
 * Error codes the hosted /api/v1/verify endpoint returns with HTTP 200 and
 * `active: false`. Unknown codes pass through as plain strings.
 */
export const VERIFY_ERROR_CODES = [
  'invalid_token',
  'token_expired',
  'token_revoked',
  'connection_revoked',
  'connection_expired',
  'environment_mismatch',
  'insufficient_scope',
] as const;

export type VerifyErrorCode = (typeof VERIFY_ERROR_CODES)[number];

/** Successful introspection result from /api/v1/verify. */
export interface VerifyActive {
  active: true;
  sub?: string;
  user_id?: string;
  connection_id?: string;
  scopes?: string[];
  role?: string;
  app_id?: string;
  jti?: string;
  exp?: number;
  /** Consent Ledger verdict (external-agent path). Additive; may be absent. */
  consent?: ConsentVerdict;
  /** Human-presence fact for the connection. Additive; may be absent. */
  presence?: PresenceInfo;
}

/** Failed (but non-fatal) introspection result — HTTP 200, active: false. */
export interface VerifyInactive {
  active: false;
  error?: VerifyErrorCode | (string & {});
}

// ---------------------------------------------------------------------------
// Rate-limit retry helpers
// ---------------------------------------------------------------------------

/** Parse an integer from an HTTP response header. Returns null if missing or invalid. */
function parseIntHeader(headers: Headers, name: string): number | null {
  const val = headers.get(name);
  if (val === null) return null;
  const n = parseInt(val, 10);
  return Number.isFinite(n) ? n : null;
}

/** Parse a float from an HTTP response header. Returns null if missing or invalid. */
function parseFloatHeader(headers: Headers, name: string): number | null {
  const val = headers.get(name);
  if (val === null) return null;
  const n = parseFloat(val);
  return Number.isFinite(n) ? n : null;
}

/** sleep for `ms` milliseconds */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/** Hard cap on any single retry wait — including a server-supplied Retry-After. */
const MAX_RETRY_WAIT_MS = 30_000;
/** Hard cap on cumulative wait across all retries of a single verify call. */
const MAX_RETRY_BUDGET_MS = 120_000;

/**
 * POST to the AgentAdmit introspection endpoint with automatic 429 retry.
 *
 * Retry policy:
 *   - Initial delay: 1 second
 *   - Each retry doubles the delay, capped at 30 seconds
 *   - Each delay adds 0–500 ms of random jitter
 *   - Honors Retry-After header if present, capped at 30 seconds
 *     (Retry-After is untrusted server input and must not pin the caller)
 *   - Cumulative wait across retries is capped at 120 seconds
 *   - After maxRetries or the wait budget is exhausted, throws RateLimitError
 */
async function introspectWithRetry(
  verifyUrl: string,
  token: string,
  appId: string,
  apiKey: string,
  maxRetries: number,
): Promise<globalThis.Response> {
  let delay = 1000; // ms
  let waitedMs = 0; // cumulative wait across retries

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    let response: globalThis.Response;
    try {
      response = await fetch(verifyUrl, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ token }),
      });
    } catch (err: any) {
      throw new Error(`AgentAdmit introspection failed (network): ${err.message}`);
    }

    if (response.status !== 429) {
      return response;
    }

    // --- 429 handling ---
    const retryAfter = parseFloatHeader(response.headers, 'Retry-After');
    const limit = parseIntHeader(response.headers, 'X-RateLimit-Limit');
    const remaining = parseIntHeader(response.headers, 'X-RateLimit-Remaining');
    const reset = parseIntHeader(response.headers, 'X-RateLimit-Reset');

    if (attempt >= maxRetries) {
      throw new RateLimitError({
        message: `AgentAdmit rate limit exceeded. Max retries (${maxRetries}) exhausted.`,
        retryAfter,
        limit,
        remaining,
        reset,
      });
    }

    const requestedMs = retryAfter !== null ? retryAfter * 1000 : delay;
    const waitMs = Math.min(Math.max(0, requestedMs), MAX_RETRY_WAIT_MS);
    const jitterMs = Math.random() * 500; // 0–500 ms
    const totalWaitMs = waitMs + jitterMs;

    if (waitedMs + totalWaitMs > MAX_RETRY_BUDGET_MS) {
      throw new RateLimitError({
        message: `AgentAdmit rate limit retry budget (${MAX_RETRY_BUDGET_MS / 1000}s) exhausted.`,
        retryAfter,
        limit,
        remaining,
        reset,
      });
    }
    waitedMs += totalWaitMs;

    console.warn(
      `[AgentAdmit] Rate-limited (attempt ${attempt + 1}/${maxRetries}). ` +
      `Retrying in ${(totalWaitMs / 1000).toFixed(2)}s.`,
    );

    await sleep(totalWaitMs);
    delay = Math.min(delay * 2, 30_000);
  }

  // Should never be reached
  throw new Error('Unexpected exit from retry loop');
}

// ---------------------------------------------------------------------------

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
  const verifyUrl = (config as any).agentadmit_verify_url || 'https://api.agentadmit.com/api/v1/verify';
  const appId = config.app_id;
  const apiKey = (config as any).api_key || '';
  const maxRetries = (config as any).max_retries ?? 3;

  // introspectWithRetry handles 429 with exponential backoff + jitter.
  // RateLimitError propagates to the caller when retries are exhausted.
  const response = await introspectWithRetry(verifyUrl, token, appId, apiKey, maxRetries);

  // Non-2xx response: treat token as invalid regardless of body content.
  // 401 gets a more descriptive message if the body cooperates.
  if (!response.ok) {
    if (response.status === 401) {
      const errData = (await response.json().catch(() => ({}))) as Record<string, string>;
      throw new Error(errData.error_description || 'Token validation failed');
    }
    throw new Error(`Verification service returned ${response.status}`);
  }

  // Parse the response body; a parse failure is treated as invalid.
  let data: Record<string, any>;
  try {
    data = (await response.json()) as Record<string, any>;
  } catch {
    throw new Error('Token is not active: invalid_token');
  }

  // Check active flag (RFC 7662 introspection pattern).
  // `active` must be strictly boolean true — coercion (e.g. string "true",
  // truthy object) is rejected to prevent bypass via type confusion.
  if (data.active !== true) {
    const reason = (typeof data.error === 'string' ? data.error : null) || 'invalid_token';
    throw new Error(`Token is not active: ${reason}`);
  }

  // Validate identity fields — wrong types are treated as invalid rather than
  // thrown raw, to avoid leaking internal state through unhandled errors.
  const scopesRaw = data.scopes;
  if (
    scopesRaw !== undefined &&
    (
      !Array.isArray(scopesRaw) ||
      scopesRaw.some((s: unknown) => typeof s !== 'string')
    )
  ) {
    throw new Error('Token is not active: invalid_token');
  }

  const scopes: string[] = Array.isArray(scopesRaw) ? scopesRaw : [];

  // Optional string identity fields: if present they must be strings.
  const stringFields = ['user_id', 'agent_id', 'connection_id', 'sub', 'role', 'app_id', 'jti'] as const;
  for (const field of stringFields) {
    if (data[field] !== undefined && typeof data[field] !== 'string') {
      throw new Error('Token is not active: invalid_token');
    }
  }

  const userId: string = data.user_id;
  const connectionId: string = data.connection_id;

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

  // Consent Ledger verdict rides along when the platform returns it.
  const consent =
    data.consent && typeof data.consent === 'object' && typeof data.consent.granted === 'boolean'
      ? (data.consent as ConsentVerdict)
      : undefined;

  // Human-presence fact rides along when the platform returns it. Same
  // strictness as `active`: verified must be boolean true/false, never coerced.
  const presence =
    data.presence && typeof data.presence === 'object' && typeof data.presence.verified === 'boolean'
      ? (data.presence as PresenceInfo)
      : undefined;

  return {
    user,
    connection,
    scopes,
    ...(consent !== undefined ? { consent } : {}),
    ...(presence !== undefined ? { presence } : {}),
  };
}

/**
 * True when the connection behind this context was authorized by a human who
 * completed a presence ceremony (WebAuthn) on the consent page. Strict:
 * absent or malformed presence data is NOT verified.
 */
export function presenceVerified(ctx: { presence?: PresenceInfo }): boolean {
  return ctx.presence?.verified === true;
}

/**
 * Express middleware: require a presence-verified connection (agent-only).
 * 403 `presence_required` when the connection was minted without a completed
 * WebAuthn ceremony — including all connections from servers that predate
 * the presence feature (fail closed, mirroring requireScope's posture).
 */
export function requirePresence() {
  return async (req: Request, res: Response, next: NextFunction) => {
    const token = getBearerToken(req);
    const config = getConfig();

    if (!token || !token.startsWith(config.token_prefix_access)) {
      return res.status(401).json({ error: 'invalid_token', error_description: 'AgentAdmit token required' });
    }

    try {
      const ctx = await validateAgentToken(token);
      if (!presenceVerified(ctx)) {
        return res.status(403).json({
          error: 'presence_required',
          error_description: 'This action requires a connection authorized with human presence verification.',
        });
      }

      (req as any).agentAdmit = { auth_type: 'agent', ...ctx };
      next();
    } catch (err: any) {
      return res.status(401).json({ error: 'invalid_token', error_description: err.message });
    }
  };
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
