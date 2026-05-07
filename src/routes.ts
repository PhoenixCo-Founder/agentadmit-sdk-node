/**
 * agentadmit/routes.ts
 * Express router with all AgentAdmit endpoints.
 */

import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { getConfig, getScopeMetadata, getDurationOptions, getTierLimits } from './config';
import { loadPrivateKey, loadPublicKey } from './keys';
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

function buildJwksKey(publicKeyPem: string): Record<string, any> | null {
  try {
    const key = crypto.createPublicKey(publicKeyPem);
    const jwk = key.export({ format: 'jwk' });
    return { ...jwk, use: 'sig', alg: 'RS256', kid: 'agentadmit-1' };
  } catch {
    return null;
  }
}

function createJwt(
  userId: string,
  scopes: string[],
  connectionId: string,
  role: string,
  agentLabel: string,
  lifetimeSeconds: number,
): string {
  const config = getConfig();
  const privateKey = loadPrivateKey(config.private_key_path);

  const payload = {
    iss: config.api_base_url.replace(/\/$/, ''),
    sub: userId,
    aud: config.audience,
    jti: uuidv4(),
    agentadmit: {
      version: AGENTADMIT_VERSION,
      scopes,
      connection_id: connectionId,
      agent_label: agentLabel,
      role,
    },
  };

  return jwt.sign(payload, privateKey, {
    algorithm: config.algorithm as jwt.Algorithm,
    expiresIn: lifetimeSeconds,
    header: { kid: 'agentadmit-1', alg: config.algorithm },
  });
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

  let jwksKey: Record<string, any> | null = null;
  try {
    const pubPem = loadPublicKey(config.public_key_path);
    jwksKey = buildJwksKey(pubPem);
  } catch {}

  const wellknownRouter = Router();
  const agentadmitRouter = Router();

  // Discovery
  wellknownRouter.get('/.well-known/agentadmit', (_req: Request, res: Response) => {
    const base = config.api_base_url.replace(/\/$/, '');
    res.json({
      agentadmit_version: AGENTADMIT_VERSION,
      issuer: base,
      app_name: config.app_name,
      api_base_url: base,
      token_endpoint: `${base}${config.route_prefix}/token`,
      revocation_endpoint: `${base}${config.route_prefix}/revoke`,
      scopes_endpoint: `${base}${config.route_prefix}/scopes`,
      jwks_uri: `${base}${config.route_prefix}/.well-known/jwks.json`,
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

  // JWKS
  agentadmitRouter.get('/.well-known/jwks.json', (_req: Request, res: Response) => {
    res.set('Cache-Control', 'public, max-age=3600');
    res.json({ keys: jwksKey ? [jwksKey] : [] });
  });

  // Durations
  agentadmitRouter.get('/durations', (_req: Request, res: Response) => {
    res.json({ durations: getDurationOptions() });
  });

  // Generate connection token
  agentadmitRouter.post('/connections/generate-token', async (req: Request, res: Response) => {
    try {
      const currentUser = await getCurrentUser(req);
      if (!currentUser) return res.status(401).json({ error: 'unauthorized' });

      const { scopes, duration_seconds } = req.body;
      if (!scopes || !Array.isArray(scopes)) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'scopes array required' });
      }

      const validation = validateScopes(scopes, currentUser);
      if (!validation.valid) {
        return res.status(400).json({ error: 'invalid_scope', invalid_scopes: validation.invalid });
      }

      const duration = duration_seconds || config.connection_token_ttl;
      const exchangeUrl = `${config.api_base_url.replace(/\/$/, '')}${config.route_prefix}/token`;
      const urlPart = Buffer.from(exchangeUrl).toString('base64url');
      const secretPart = crypto.randomBytes(32).toString('base64url'); // 256 bits of cryptographic entropy (industry benchmark)
      const rawToken = `${config.token_prefix_connection}${urlPart}.${secretPart}`;

      const now = new Date();
      const userId = currentUser[config.user_lookup_field];
      const role = determineRole(currentUser);
      const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

      await storage.storeToken({
        token_hash: tokenHash,
        token: rawToken,
        user_id: userId,
        scopes,
        role,
        duration_seconds: duration,
        used: false,
        created_at: now,
        expires_at: new Date(now.getTime() + config.connection_token_ttl * 1000),
      });

      res.json({
        connection_token: rawToken,
        expires_in: config.connection_token_ttl,
        scopes,
      });
    } catch (err: any) {
      console.error('[AgentAdmit] Generate token error:', err);
      res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  // Token exchange
  agentadmitRouter.post('/token', async (req: Request, res: Response) => {
    try {
      const { grant_type, connection_token, agent_id, agent_label, agent_metadata } = req.body;

      if (grant_type !== 'connection_token') {
        return res.status(400).json({ error: 'unsupported_grant_type' });
      }
      if (!connection_token) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'connection_token required' });
      }

      const tokenHash = crypto.createHash('sha256').update(connection_token).digest('hex');
      const now = new Date();
      const tokenDoc = await storage.getToken(tokenHash);

      if (!tokenDoc || tokenDoc.used || (tokenDoc.expires_at && new Date(tokenDoc.expires_at) <= now)) {
        return res.status(400).json({ error: 'invalid_token', error_description: 'Token expired, used, or not found' });
      }

      // Tier enforcement
      const user = await storage.getUser(tokenDoc.user_id, config.user_lookup_field);
      const userTier = user ? getUserTier(user) : config.default_tier;
      await checkConnectionCap(tokenDoc.user_id, userTier);

      await storage.markTokenUsed(tokenHash);

      const connectionId = `conn_${crypto.randomBytes(16).toString('base64url')}`;
      const label = agent_label || 'Unknown Agent';
      const tokenDuration = tokenDoc.duration_seconds || 2592000;

      await storage.storeConnection({
        connection_id: connectionId,
        user_id: tokenDoc.user_id,
        scopes: tokenDoc.scopes,
        role: tokenDoc.role || 'user',
        agent_id: agent_id || null,
        agent_label: label,
        agent_metadata: agent_metadata || null,
        duration_seconds: tokenDuration,
        expires_at: new Date(now.getTime() + tokenDuration * 1000),
        status: 'active',
        created_at: now,
        last_used: null,
        revoked_at: null,
      });

      const rawJwt = createJwt(
        tokenDoc.user_id,
        tokenDoc.scopes,
        connectionId,
        tokenDoc.role || 'user',
        label,
        tokenDuration,
      );

      res.json({
        access_token: `${config.token_prefix_access}${rawJwt}`,
        token_type: 'bearer',
        expires_in: tokenDuration,
        scopes: tokenDoc.scopes,
        role: tokenDoc.role || 'user',
        connection_id: connectionId,
        app_name: config.app_name,
        api_base_url: config.api_base_url,
        endpoints: getEndpointsForScopes(tokenDoc.scopes),
      });
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
    } catch (err: any) {
      res.status(500).json({ error: 'server_error' });
    }
  });

  // Delete connection
  agentadmitRouter.delete('/connections/:connectionId', async (req: Request, res: Response) => {
    try {
      const currentUser = await getCurrentUser(req);
      if (!currentUser) return res.status(401).json({ error: 'unauthorized' });

      const userId = currentUser[config.user_lookup_field];
      const conn = await storage.getConnection(req.params.connectionId);

      if (!conn || conn.user_id !== userId) {
        return res.status(404).json({ error: 'not_found' });
      }
      if (conn.status !== 'active') {
        return res.status(400).json({ error: 'already_revoked' });
      }

      await storage.revokeConnection(req.params.connectionId);
      res.json({ revoked: true, connection_id: req.params.connectionId });
    } catch (err: any) {
      res.status(500).json({ error: 'server_error' });
    }
  });

  return { wellknownRouter, agentadmitRouter };
}
