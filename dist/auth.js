"use strict";
/**
 * agentadmit/auth.ts
 * Token validation, scope enforcement, and audit logging for Express.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.setStorage = setStorage;
exports.setUserVerifier = setUserVerifier;
exports.validateAgentToken = validateAgentToken;
exports.requireScope = requireScope;
exports.requireScopeIfAgent = requireScopeIfAgent;
exports.resolveAuth = resolveAuth;
exports.checkConnectionCap = checkConnectionCap;
const config_1 = require("./config");
const errors_1 = require("./errors");
let _storage = null;
let _verifyUserToken = null;
function setStorage(storage) {
    _storage = storage;
}
function setUserVerifier(fn) {
    _verifyUserToken = fn;
}
function getStorage() {
    if (!_storage)
        throw new Error('AgentAdmit storage not initialized');
    return _storage;
}
function getBearerToken(req) {
    const auth = req.headers.authorization || '';
    if (auth.startsWith('Bearer '))
        return auth.slice(7);
    return null;
}
// ---------------------------------------------------------------------------
// Rate-limit retry helpers
// ---------------------------------------------------------------------------
/** Parse an integer from an HTTP response header. Returns null if missing or invalid. */
function parseIntHeader(headers, name) {
    const val = headers.get(name);
    if (val === null)
        return null;
    const n = parseInt(val, 10);
    return Number.isFinite(n) ? n : null;
}
/** Parse a float from an HTTP response header. Returns null if missing or invalid. */
function parseFloatHeader(headers, name) {
    const val = headers.get(name);
    if (val === null)
        return null;
    const n = parseFloat(val);
    return Number.isFinite(n) ? n : null;
}
/** sleep for `ms` milliseconds */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
/**
 * POST to the AgentAdmit introspection endpoint with automatic 429 retry.
 *
 * Retry policy:
 *   - Initial delay: 1 second
 *   - Each retry doubles the delay, capped at 30 seconds
 *   - Each delay adds 0–500 ms of random jitter
 *   - Honors Retry-After header if present
 *   - After maxRetries exhausted, throws RateLimitError
 */
async function introspectWithRetry(verifyUrl, token, appId, apiKey, maxRetries) {
    let delay = 1000; // ms
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        let response;
        try {
            response = await fetch(verifyUrl, {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${apiKey}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ token }),
            });
        }
        catch (err) {
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
            throw new errors_1.RateLimitError({
                message: `AgentAdmit rate limit exceeded. Max retries (${maxRetries}) exhausted.`,
                retryAfter,
                limit,
                remaining,
                reset,
            });
        }
        const waitMs = retryAfter !== null ? retryAfter * 1000 : Math.min(delay, 30000);
        const jitterMs = Math.random() * 500; // 0–500 ms
        const totalWaitMs = waitMs + jitterMs;
        console.warn(`[AgentAdmit] Rate-limited (attempt ${attempt + 1}/${maxRetries}). ` +
            `Retrying in ${(totalWaitMs / 1000).toFixed(2)}s.`);
        await sleep(totalWaitMs);
        delay = Math.min(delay * 2, 30000);
    }
    // Should never be reached
    throw new Error('Unexpected exit from retry loop');
}
// ---------------------------------------------------------------------------
/**
 * Validate an ag_at_ token and return the agent context.
 */
async function validateAgentToken(token) {
    const config = (0, config_1.getConfig)();
    if (!token.startsWith(config.token_prefix_access)) {
        throw new Error('Not an AgentAdmit access token');
    }
    // MANDATORY INTROSPECTION — validate via AgentAdmit hosted service
    // No local JWT decode. Every verification call goes through AgentAdmit.
    const verifyUrl = config.agentadmit_verify_url || 'https://api.agentadmit.com/v1/verify';
    const appId = config.app_id;
    const apiKey = config.api_key || '';
    const maxRetries = config.max_retries ?? 3;
    // introspectWithRetry handles 429 with exponential backoff + jitter.
    // RateLimitError propagates to the caller when retries are exhausted.
    const response = await introspectWithRetry(verifyUrl, token, appId, apiKey, maxRetries);
    if (response.status === 401) {
        const errData = (await response.json().catch(() => ({})));
        throw new Error(errData.error_description || 'Token validation failed');
    }
    if (response.status !== 200) {
        throw new Error(`Verification service returned ${response.status}`);
    }
    const data = (await response.json());
    // Check active flag (RFC 7662 introspection pattern).
    // The verify endpoint returns {active: false} with HTTP 200 for invalid/
    // expired/revoked tokens. Without this check, we'd read empty scopes.
    if (!data.active) {
        const reason = data.error || 'invalid_token';
        throw new Error(`Token is not active: ${reason}`);
    }
    const scopes = data.scopes || [];
    const userId = data.user_id;
    const connectionId = data.connection_id;
    if (!userId) {
        throw new Error('Introspection returned no user');
    }
    // User lookup from app's local database (if storage is configured)
    let user = { [config.user_lookup_field]: userId };
    try {
        const storage = getStorage();
        const localUser = await storage.getUser(userId, config.user_lookup_field);
        if (localUser)
            user = localUser;
    }
    catch { }
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
function requireScope(scope) {
    return async (req, res, next) => {
        const token = getBearerToken(req);
        const config = (0, config_1.getConfig)();
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
            req.agentAdmit = { auth_type: 'agent', ...ctx };
            next();
        }
        catch (err) {
            return res.status(401).json({ error: 'invalid_token', error_description: err.message });
        }
    };
}
/**
 * Express middleware: enforce scope only if caller is an agent.
 */
function requireScopeIfAgent(scope) {
    return async (req, res, next) => {
        const token = getBearerToken(req);
        const config = (0, config_1.getConfig)();
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
            req.agentAdmit = { auth_type: 'agent', ...ctx };
            next();
        }
        catch (err) {
            return res.status(401).json({ error: 'invalid_token', error_description: err.message });
        }
    };
}
/**
 * Express middleware: resolve user or agent from token.
 */
function resolveAuth() {
    return async (req, res, next) => {
        const token = getBearerToken(req);
        const config = (0, config_1.getConfig)();
        if (!token) {
            return res.status(401).json({ error: 'not_authenticated' });
        }
        if (token.startsWith(config.token_prefix_access)) {
            try {
                const ctx = await validateAgentToken(token);
                req.agentAdmit = { auth_type: 'agent', ...ctx };
                return next();
            }
            catch (err) {
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
            req.agentAdmit = { auth_type: 'user', user, scopes: ['*'], connection: null };
            next();
        }
        catch {
            return res.status(401).json({ error: 'invalid_token' });
        }
    };
}
/**
 * Write audit log entry.
 */
async function logAccess(ctx, scope, req) {
    try {
        const config = (0, config_1.getConfig)();
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
    }
    catch (err) {
        console.error('[AgentAdmit] Audit log failed:', err);
    }
}
/**
 * Check connection cap for tier enforcement.
 */
async function checkConnectionCap(userId, tier) {
    const { getTierLimits } = require('./config');
    const limits = getTierLimits(tier);
    if (!limits?.hard_cap)
        return;
    const storage = getStorage();
    const count = await storage.countActiveConnections(userId);
    if (count >= limits.connections_limit) {
        const err = new Error(`Connection limit reached (${count}/${limits.connections_limit})`);
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
