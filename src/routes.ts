/**
 * agentadmit/routes.ts
 * Express router with all AgentAdmit endpoints.
 *
 * ALL token operations go through the AgentAdmit hosted service. The SDK does
 * NOT sign JWTs, generate RSA keys, or serve JWKS endpoints. The hosted service
 * owns all cryptographic operations.
 */

import type { Router, Request, Response } from 'express';
import { randomBytes } from 'crypto';
import { getConfig, getScopeMetadata, getDurationOptions } from './config';
import { StorageBackend } from './storage';
import { checkConnectionCap } from './auth';

// express is an OPTIONAL peer dependency: only createAgentAdmitRouter needs
// it, and non-Express consumers (auth-only usage, Next.js API routes) must be
// able to require the SDK without it installed. Through 1.5.0 the top-level
// value import above made a bare `npm install @agentadmit/sdk` +
// `require('@agentadmit/sdk')` crash with MODULE_NOT_FOUND, because index.ts
// re-exports this module unconditionally — so the runtime require is deferred
// to the moment a router is actually created.
function requireExpressRouterFactory(): () => Router {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return require('express').Router;
  } catch {
    throw new Error(
      "createAgentAdmitRouter requires the optional peer dependency 'express'. Install it with: npm install express",
    );
  }
}

// Version from the package manifest — bumping package.json is the whole
// release step. Works from src/ (dev) and dist/ (published) alike.
let AGENTADMIT_VERSION = '0.0.0';
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  AGENTADMIT_VERSION = require('../package.json').version;
} catch {
  /* keep fallback */
}

export interface RouterOptions {
  storage: StorageBackend;
  getCurrentUser: (req: Request) => Promise<Record<string, any> | null>;
  determineRole?: (user: Record<string, any>) => string;
  getUserTier?: (user: Record<string, any>) => string;
  validateScopes?: (scopes: string[], user: Record<string, any>) => { valid: boolean; invalid: string[] };
  getEndpointsForScopes?: (scopes: string[]) => Record<string, any>[];
  requireTokenMintPresence?: (req: Request, currentUser: Record<string, any>) => Promise<void> | void;
}

/**
 * Make a request to the AgentAdmit hosted service. Authenticated with the
 * operator API key, except for /exchange (authenticated: false) where the
 * connection token itself is the credential.
 */
async function callHostedService(
  path: string,
  body: Record<string, any>,
  options: { authenticated?: boolean } = {},
): Promise<{ status: number; data: any }> {
  const config = getConfig();
  const url = `${config.agentadmit_api_url.replace(/\/$/, '')}${path}`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-App-Id': config.app_id,
  };
  if (options.authenticated !== false) {
    headers['Authorization'] = `Bearer ${config.api_key}`;
  }

  const resp = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });

  const data = await resp.json().catch(() => ({}));
  return { status: resp.status, data };
}

function tokenMintPresenceErrorResponse(err: any): { status: number; data: Record<string, any> } {
  const status = Number.isInteger(err?.statusCode)
    ? err.statusCode
    : Number.isInteger(err?.status)
      ? err.status
      : 403;

  const data = err?.detail && typeof err.detail === 'object'
    ? err.detail
    : err?.body && typeof err.body === 'object'
      ? err.body
      : {
          error: err?.code || 'presence_attestation_required',
          error_description: err?.message || 'Human presence verification is required before generating a connection token.',
        };

  return { status, data };
}

export function createAgentAdmitRouter(options: RouterOptions): { wellknownRouter: Router; agentadmitRouter: Router } {
  const config = getConfig();
  const { storage, getCurrentUser } = options;
  const determineRole = options.determineRole || (() => 'user');
  const getUserTier = options.getUserTier || (() => config.default_tier);
  const getEndpointsForScopes = options.getEndpointsForScopes || (() => []);

  const validateScopes = options.validateScopes || ((scopes: string[]) => {
    const validNames = new Set(config.scopes.map(s => s.name));
    const invalid = scopes.filter(s => !validNames.has(s));
    return { valid: invalid.length === 0, invalid };
  });

  const Router = requireExpressRouterFactory();
  const wellknownRouter = Router();
  const agentadmitRouter = Router();

  // Discovery
  wellknownRouter.get('/.well-known/agentadmit', (_req: Request, res: Response) => {
    const base = config.api_base_url.replace(/\/$/, '');
    res.json({
      agentadmit_version: AGENTADMIT_VERSION,
      issuer: base,
      app_name: config.app_name,
      app_id: config.app_id,
      api_base_url: base,
      agentadmit_service_url: config.agentadmit_api_url,
      scopes_endpoint: `${base}${config.route_prefix}/scopes`,
      discovery_endpoint: `${base}${config.route_prefix}/discovery`,
      connections_endpoint: `${base}${config.route_prefix}/connections`,
      scopes_supported: config.scopes.map(s => s.name),
      roles_supported: [...new Set(config.scopes.map(s => s.role || 'user'))],
      duration_options: getDurationOptions(),
    });
  });

  // Scopes
  agentadmitRouter.get('/scopes', (_req: Request, res: Response) => {
    res.json({
      scopes: getScopeMetadata(),
      roles: [...new Set(config.scopes.map(s => s.role || 'user'))],
    });
  });

  // Durations
  agentadmitRouter.get('/durations', (_req: Request, res: Response) => {
    res.json({ durations: getDurationOptions() });
  });

  // Generate connection token — calls hosted service
  agentadmitRouter.post('/connections/generate-token', async (req: Request, res: Response) => {
    try {
      const currentUser = await getCurrentUser(req);
      if (!currentUser) return res.status(401).json({ error: 'unauthorized' });

      const { scopes, duration_seconds, label, purpose } = req.body;
      if (!scopes || !Array.isArray(scopes)) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'scopes array required' });
      }

      // Declared purpose: the user-facing reason recorded on the grant at the
      // consent moment. Review-time record only, never an enforcement input;
      // authorization decisions ride scopes, connection status, and consent.
      // Optional (1..300 chars). Absent/null → the key is omitted downstream.
      if (purpose !== undefined && purpose !== null) {
        if (typeof purpose !== 'string' || purpose.length < 1 || purpose.length > 300) {
          return res.status(400).json({
            error: 'invalid_request',
            error_description: 'purpose must be a string of 1 to 300 characters',
          });
        }
      }

      const validation = validateScopes(scopes, currentUser);
      if (!validation.valid) {
        return res.status(400).json({ error: 'invalid_scope', invalid_scopes: validation.invalid });
      }

      const userId = currentUser[config.user_lookup_field];
      const role = determineRole(currentUser);
      const userTier = getUserTier(currentUser);

      await checkConnectionCap(userId, userTier);

      if (options.requireTokenMintPresence) {
        try {
          const result = await options.requireTokenMintPresence(req, currentUser);
          // Contract: the hook THROWS to deny; returning nothing allows the
          // mint. A returned value is a contract violation — fail CLOSED so a
          // misconfigured hook that returns a "denial" object instead of
          // throwing can never silently let the mint proceed (fail-open).
          if (result !== undefined && result !== null) {
            return res.status(500).json({
              error: 'presence_hook_misconfigured',
              error_description:
                'The token-mint presence hook must throw to deny; it must not return a value.',
            });
          }
        } catch (err: any) {
          const denial = tokenMintPresenceErrorResponse(err);
          return res.status(denial.status).json(denial.data);
        }
      }

      // Call AgentAdmit hosted service. duration_seconds is tri-state:
      // key absent → hosted default (30 days); explicit null → until
      // revoked; integer 60–31536000 → explicit duration.
      const issueBody: Record<string, any> = {
        user_id: String(userId),
        scopes,
        role,
      };
      if ('duration_seconds' in req.body) {
        issueBody.duration_seconds = duration_seconds ?? null;
      }
      // Declared purpose is forwarded verbatim when provided; the key is
      // OMITTED when absent (the hosted mint treats absence as "none declared").
      if (purpose !== undefined && purpose !== null) {
        issueBody.purpose = purpose;
      }
      const { status, data } = await callHostedService(`/api/v1/apps/${config.app_id}/token`, issueBody);

      if (status !== 200 && status !== 201) {
        console.error('[AgentAdmit] Hosted token generation failed:', status, data);
        return res.status(502).json({ error: 'token_generation_failed', error_description: 'Authorization service could not generate token' });
      }

      // Store local record
      // Use hosted service's connection_id if provided; generate a local fallback
      // to prevent duplicate-key errors when hosting service omits it.
      await storage.storeConnection({
        connection_id: data.connection_id || `conn_${randomBytes(16).toString('base64url')}`,
        user_id: String(userId),
        scopes,
        role,
        agent_label: label,
        // Declared purpose is persisted locally so GET /connections (served
        // from this store) can surface it. Explicit null is normalized to
        // undefined — same "none declared" treatment as the hosted mint body.
        purpose: purpose ?? undefined,
        duration_seconds: 'duration_seconds' in req.body ? duration_seconds ?? null : null,
        status: 'active',
      });

      res.json({
        connection_token: data.token,
        expires_in: data.expires_in ?? config.connection_token_ttl,
        scopes,
      });
    } catch (err: any) {
      console.error('[AgentAdmit] Generate token error:', err);
      res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  // Token exchange — forwards to hosted service
  agentadmitRouter.post('/token', async (req: Request, res: Response) => {
    try {
      const { grant_type, connection_token, agent_id, agent_label, agent_metadata } = req.body;

      if (grant_type !== 'connection_token') {
        return res.status(400).json({ error: 'unsupported_grant_type' });
      }
      if (!connection_token) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'connection_token required' });
      }

      // Forward to AgentAdmit hosted service. No API key on this call —
      // the connection token is the credential.
      // Optional fields must be OMITTED when absent: the hosted /api/v1/exchange
      // rejects explicit JSON nulls ("Expected string, received null").
      const exchangeBody: Record<string, any> = { token: connection_token };
      if (agent_label != null) exchangeBody.agent_label = agent_label;
      if (agent_id != null) exchangeBody.agent_id = agent_id;
      if (agent_metadata != null) exchangeBody.agent_metadata = agent_metadata;

      const { status, data } = await callHostedService('/api/v1/exchange', exchangeBody,
        { authenticated: false });

      if (status !== 200) {
        return res.status(status < 500 ? status : 502).json(data);
      }

      // Add endpoint map if available
      if (getEndpointsForScopes && data.scopes) {
        data.endpoints = getEndpointsForScopes(data.scopes);
      }

      res.json(data);
    } catch (err: any) {
      const status = err.statusCode || 500;
      res.status(status).json(err.detail || { error: 'server_error', error_description: err.message });
    }
  });

  // List connections
  agentadmitRouter.get('/connections', async (req: Request, res: Response) => {
    try {
      const currentUser = await getCurrentUser(req);
      if (!currentUser) return res.status(401).json({ error: 'unauthorized' });

      const userId = currentUser[config.user_lookup_field];
      const connections = await storage.listConnections(userId);
      res.json({ connections, total: connections.length });
    } catch {
      res.status(500).json({ error: 'server_error' });
    }
  });

  // Delete connection — also notifies hosted service
  agentadmitRouter.delete('/connections/:connectionId', async (req: Request, res: Response) => {
    try {
      const currentUser = await getCurrentUser(req);
      if (!currentUser) return res.status(401).json({ error: 'unauthorized' });

      const userId = currentUser[config.user_lookup_field];
      const conn = await storage.getConnection(req.params.connectionId);

      if (!conn || conn.user_id !== String(userId)) {
        return res.status(404).json({ error: 'not_found' });
      }
      if (conn.status !== 'active') {
        return res.status(400).json({ error: 'already_revoked' });
      }

      // Revoke at the hosted service FIRST — that's where enforcement
      // happens. If this fails, the agent's token still verifies, so
      // reporting revoked:true would be false comfort. 404 means the hosted
      // service has no such connection — nothing to revoke there, proceed.
      try {
        const { status, data } = await callHostedService('/api/v1/revoke', {
          connection_id: req.params.connectionId,
          reason: 'user_requested',
        });
        if (!(status >= 200 && status < 300) && status !== 404) {
          console.error('[AgentAdmit] Hosted revoke failed:', status, data);
          return res.status(502).json({
            revoked: false,
            error: 'revoke_failed',
            error_description: 'Authorization service could not revoke the connection. Try again.',
          });
        }
      } catch (e) {
        console.error('[AgentAdmit] Hosted revoke failed (network):', e);
        return res.status(502).json({
          revoked: false,
          error: 'revoke_failed',
          error_description: 'Authorization service could not be reached. Try again.',
        });
      }

      await storage.revokeConnection(req.params.connectionId);
      res.json({ revoked: true, connection_id: req.params.connectionId });
    } catch {
      res.status(500).json({ error: 'server_error' });
    }
  });

  return { wellknownRouter, agentadmitRouter };
}
