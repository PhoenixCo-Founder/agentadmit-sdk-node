"use strict";
/**
 * agentadmit/routes.ts
 * Express router with all AgentAdmit endpoints.
 *
 * ALL token operations go through the AgentAdmit hosted service. The SDK does
 * NOT sign JWTs, generate RSA keys, or serve JWKS endpoints. The hosted service
 * owns all cryptographic operations.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.createAgentAdmitRouter = createAgentAdmitRouter;
const express_1 = require("express");
const crypto_1 = require("crypto");
const config_1 = require("./config");
const auth_1 = require("./auth");
// Version from the package manifest — bumping package.json is the whole
// release step. Works from src/ (dev) and dist/ (published) alike.
let AGENTADMIT_VERSION = '0.0.0';
try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    AGENTADMIT_VERSION = require('../package.json').version;
}
catch {
    /* keep fallback */
}
/**
 * Make a request to the AgentAdmit hosted service. Authenticated with the
 * operator API key, except for /exchange (authenticated: false) where the
 * connection token itself is the credential.
 */
async function callHostedService(path, body, options = {}) {
    const config = (0, config_1.getConfig)();
    const url = `${config.agentadmit_api_url.replace(/\/$/, '')}${path}`;
    const headers = {
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
function createAgentAdmitRouter(options) {
    const config = (0, config_1.getConfig)();
    const { storage, getCurrentUser } = options;
    const determineRole = options.determineRole || (() => 'user');
    const getUserTier = options.getUserTier || (() => config.default_tier);
    const getEndpointsForScopes = options.getEndpointsForScopes || (() => []);
    const validateScopes = options.validateScopes || ((scopes) => {
        const validNames = new Set(config.scopes.map(s => s.name));
        const invalid = scopes.filter(s => !validNames.has(s));
        return { valid: invalid.length === 0, invalid };
    });
    const wellknownRouter = (0, express_1.Router)();
    const agentadmitRouter = (0, express_1.Router)();
    // Discovery
    wellknownRouter.get('/.well-known/agentadmit', (_req, res) => {
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
            duration_options: (0, config_1.getDurationOptions)(),
        });
    });
    // Scopes
    agentadmitRouter.get('/scopes', (_req, res) => {
        res.json({
            scopes: (0, config_1.getScopeMetadata)(),
            roles: [...new Set(config.scopes.map(s => s.role || 'user'))],
        });
    });
    // Durations
    agentadmitRouter.get('/durations', (_req, res) => {
        res.json({ durations: (0, config_1.getDurationOptions)() });
    });
    // Generate connection token — calls hosted service
    agentadmitRouter.post('/connections/generate-token', async (req, res) => {
        try {
            const currentUser = await getCurrentUser(req);
            if (!currentUser)
                return res.status(401).json({ error: 'unauthorized' });
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
            await (0, auth_1.checkConnectionCap)(userId, userTier);
            // Call AgentAdmit hosted service. duration_seconds is tri-state:
            // key absent → hosted default (30 days); explicit null → until
            // revoked; integer 60–31536000 → explicit duration.
            const issueBody = {
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
                connection_id: data.connection_id || `conn_${(0, crypto_1.randomBytes)(16).toString('base64url')}`,
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
        }
        catch (err) {
            console.error('[AgentAdmit] Generate token error:', err);
            res.status(500).json({ error: 'server_error', error_description: err.message });
        }
    });
    // Token exchange — forwards to hosted service
    agentadmitRouter.post('/token', async (req, res) => {
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
            const exchangeBody = { token: connection_token };
            if (agent_label != null)
                exchangeBody.agent_label = agent_label;
            if (agent_id != null)
                exchangeBody.agent_id = agent_id;
            if (agent_metadata != null)
                exchangeBody.agent_metadata = agent_metadata;
            const { status, data } = await callHostedService('/api/v1/exchange', exchangeBody, { authenticated: false });
            if (status !== 200) {
                return res.status(status < 500 ? status : 502).json(data);
            }
            // Add endpoint map if available
            if (getEndpointsForScopes && data.scopes) {
                data.endpoints = getEndpointsForScopes(data.scopes);
            }
            res.json(data);
        }
        catch (err) {
            const status = err.statusCode || 500;
            res.status(status).json(err.detail || { error: 'server_error', error_description: err.message });
        }
    });
    // List connections
    agentadmitRouter.get('/connections', async (req, res) => {
        try {
            const currentUser = await getCurrentUser(req);
            if (!currentUser)
                return res.status(401).json({ error: 'unauthorized' });
            const userId = currentUser[config.user_lookup_field];
            const connections = await storage.listConnections(userId);
            res.json({ connections, total: connections.length });
        }
        catch {
            res.status(500).json({ error: 'server_error' });
        }
    });
    // Delete connection — also notifies hosted service
    agentadmitRouter.delete('/connections/:connectionId', async (req, res) => {
        try {
            const currentUser = await getCurrentUser(req);
            if (!currentUser)
                return res.status(401).json({ error: 'unauthorized' });
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
            }
            catch (e) {
                console.warn('[AgentAdmit] Hosted revoke failed, revoking locally:', e);
            }
            await storage.revokeConnection(req.params.connectionId);
            res.json({ revoked: true, connection_id: req.params.connectionId });
        }
        catch {
            res.status(500).json({ error: 'server_error' });
        }
    });
    return { wellknownRouter, agentadmitRouter };
}
