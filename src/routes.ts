/**
 * agentadmit/routes.ts
 * Express router with all AgentAdmit endpoints.
 *
 * ALL token operations go through the AgentAdmit hosted service. The SDK does
 * NOT sign JWTs, generate RSA keys, or serve JWKS endpoints. The hosted service
 * owns all cryptographic operations.
 */

import { Router, Request, Response } from 'express';
import { randomBytes } from 'crypto';
import { getConfig, getScopeMetadata, getDurationOptions } from './config';
import { StorageBackend } from './storage';
import { checkConnectionCap } from './auth';

const AGENTADMIT_VERSION = '0.1';

interface RouterOptions {
  storage: StorageBackend;
  getCurrentUser: (req: Request) => Promise<Record<string, any> | null>;
  determineRole?: (user: Record<string, any>) => string;
  getUserTier?: (user: Record<string, any>) => string;
  validateScopes?: (scopes: string[], user: Record<string, any>) => { valid: boolean; invalid: string[] };
  getEndpointsForScopes?: (scopes: string[]) => Record<string, any>[];
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

      const { scopes, duration_seconds, label } = req.body;
      if (!scopes || !Array.isArray(scopes)) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'scopes array required' });
      }

      const validation = validateScopes(scopes, currentUser);
      if (!validation.valid) {
        return res.status(400).json({ error: 'invalid_scope', invalid_scopes: validation.invalid });
      }

      const userId = currentUser[config.user_lookup_field];
      const role = determineRole(currentUser);
      const userTier = getUserTier(currentUser);

      await checkConnectionCap(userId, userTier);

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
      const { status, data } = await callHostedService('/api/v1/exchange', {
        token: connection_token,
        agent_label: agent_label ?? null,
        agent_id: agent_id ?? null,
        agent_metadata: agent_metadata ?? null,
      }, { authenticated: false });

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

      // Notify hosted service
      try {
        await callHostedService('/api/v1/revoke', {
          connection_id: req.params.connectionId,
          reason: 'user_requested',
        });
      } catch (e) {
        console.warn('[AgentAdmit] Hosted revoke failed, revoking locally:', e);
      }

      await storage.revokeConnection(req.params.connectionId);
      res.json({ revoked: true, connection_id: req.params.connectionId });
    } catch {
      res.status(500).json({ error: 'server_error' });
    }
  });

  return { wellknownRouter, agentadmitRouter };
}
