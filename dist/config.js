"use strict";
/**
 * agentadmit/config.ts
 * Configuration loader for AgentAdmit Node.js SDK.
 *
 * IMPORTANT: AgentAdmit uses MANDATORY hosted introspection.
 * All token validation goes through api.agentadmit.com.
 * There is no self-hosted mode. No local JWT validation. No bypass.
 * This is required for security, audit logging, and scope enforcement.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadConfig = loadConfig;
exports.getConfig = getConfig;
exports.getScopeMetadata = getScopeMetadata;
exports.getDurationOptions = getDurationOptions;
exports.getTierLimits = getTierLimits;
const fs_1 = __importDefault(require("fs"));
const js_yaml_1 = __importDefault(require("js-yaml"));
const DEFAULT_CONFIG = {
    app_name: 'My App',
    app_id: '',
    api_key: '',
    api_base_url: 'http://localhost:3000',
    agentadmit_api_url: 'https://api.agentadmit.com',
    agentadmit_verify_url: 'https://api.agentadmit.com/api/v1/verify',
    token_prefix_connection: 'ag_ct_',
    token_prefix_access: 'ag_at_',
    algorithm: 'RS256',
    audience: 'agentadmit',
    connection_token_ttl: 900,
    scopes: [],
    durations: [
        { label: '1 Hour', seconds: 3600 },
        { label: '24 Hours', seconds: 86400 },
        { label: '7 Days', seconds: 604800 },
        { label: '30 Days', seconds: 2592000 },
        { label: 'Until I Revoke', seconds: null },
    ],
    tiers: [
        { name: 'trial', connections_limit: 3, hard_cap: true },
        { name: 'standard', connections_limit: 100, api_calls_monthly: 2000000, hard_cap: false },
    ],
    default_tier: 'standard',
    storage: {
        backend: 'mongodb',
        uri: 'mongodb://localhost:27017',
        database: 'agentadmit',
        connections_collection: 'agentadmit_connections',
        audit_log_collection: 'agentadmit_audit_log',
        tokens_collection: 'agentadmit_tokens',
    },
    route_prefix: '/agentadmit',
    discovery_path: '/.well-known/agentadmit',
    user_lookup_field: 'user_id',
    max_retries: 3,
};
let _config = null;
function loadConfig(configPath = 'agentadmit.yaml') {
    let resolvedPath = configPath;
    if (!fs_1.default.existsSync(resolvedPath)) {
        const envPath = process.env.AGENTADMIT_CONFIG;
        if (envPath && fs_1.default.existsSync(envPath)) {
            resolvedPath = envPath;
        }
        else {
            throw new Error(`Config file not found: ${configPath}. Run 'agentadmit init' to generate one.`);
        }
    }
    const raw = js_yaml_1.default.load(fs_1.default.readFileSync(resolvedPath, 'utf-8')) || {};
    _config = { ...DEFAULT_CONFIG, ...raw };
    // Validate the key prefix without ever echoing the key itself.
    if (_config.api_key && !/^aa_(test|live)_/.test(_config.api_key)) {
        throw new Error("Invalid api_key: must start with 'aa_test_' or 'aa_live_'");
    }
    console.log(`[AgentAdmit] Config loaded: ${resolvedPath} (${_config.scopes.length} scopes)`);
    return _config;
}
function getConfig() {
    if (!_config) {
        throw new Error('AgentAdmit config not loaded. Call loadConfig() first.');
    }
    return _config;
}
function getScopeMetadata() {
    return getConfig().scopes;
}
function getDurationOptions() {
    return getConfig().durations;
}
function getTierLimits(tierName) {
    const config = getConfig();
    return config.tiers.find(t => t.name === tierName) || config.tiers.find(t => t.name === config.default_tier);
}
